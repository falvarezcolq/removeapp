from pathlib import Path
import plistlib
import re
import subprocess
from typing import Dict, List, Optional, Tuple

from .models import CandidatePath, DeepScanItem, DeepScanResult, OrphanPath, RiskLevel, ScanResult


# Common locations where macOS apps leave support files.
BASE_PATTERNS: List[Tuple[str, str]] = [
    ("Applications", "/Applications/{app}.app"),
    ("User Application Support", "~/Library/Application Support/{app}"),
    ("User Caches", "~/Library/Caches/*{app}*"),
    ("User Preferences", "~/Library/Preferences/*{app}*"),
    ("User Logs", "~/Library/Logs/*{app}*"),
    ("System Application Support", "/Library/Application Support/{app}"),
    ("System Caches", "/Library/Caches/*{app}*"),
    ("System Preferences", "/Library/Preferences/*{app}*"),
    ("Launch Agents", "~/Library/LaunchAgents/*{app}*"),
    ("Launch Daemons", "/Library/LaunchDaemons/*{app}*"),
]

APP_SEARCH_DIRS: List[str] = [
    "/Applications",
    "/System/Applications",
    "~/Applications",
]

# System apps that are protected by SIP (System Integrity Protection) and cannot be removed
SYSTEM_PROTECTED_APPS: Tuple[str, ...] = (
    "chess",
    "mail",
    "messages",
    "reminders",
    "notes",
    "calendar",
    "contacts",
    "finder",
    "ftp account browser",
    "dictionary",
    "stocks",
    "weatherwidgetservice",
    "tv",
)

ORPHAN_PATTERNS: List[Tuple[str, str]] = [
    ("User Application Support", "~/Library/Application Support/*"),
    ("User Caches", "~/Library/Caches/*"),
    ("User Preferences", "~/Library/Preferences/*.plist"),
    ("User Logs", "~/Library/Logs/*"),
    ("User Launch Agents", "~/Library/LaunchAgents/*.plist"),
    ("User Containers", "~/Library/Containers/*"),
    ("User Saved State", "~/Library/Saved Application State/*"),
    ("User WebKit", "~/Library/WebKit/*"),
    ("User HTTP Storages", "~/Library/HTTPStorages/*"),
    ("System Application Support", "/Library/Application Support/*"),
    ("System Caches", "/Library/Caches/*"),
    ("System Preferences", "/Library/Preferences/*.plist"),
    ("System Launch Daemons", "/Library/LaunchDaemons/*.plist"),
]


def _darwin_user_cache_dir() -> Optional[Path]:
    """Return the macOS per-boot user cache dir (DARWIN_USER_CACHE_DIR).

    This is the ``/private/var/folders/.../C`` path where sandboxed apps
    (and many Cocoa frameworks) write their caches — different from
    ``~/Library/Caches``.
    """
    try:
        result = subprocess.run(
            ["getconf", "DARWIN_USER_CACHE_DIR"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            p = Path(result.stdout.strip())
            if p.exists():
                return p
    except Exception:  # noqa: BLE001
        pass
    return None

DOMAIN_PREFIXES: Tuple[str, ...] = ("com", "org", "net", "io", "dev", "app")
IGNORED_APP_NAMES: Tuple[str, ...] = (
    "apple",
    "icloud",
    "mdmclient",
    "xpc",
    "trustd",
    "wirelessdiagnostics",
)


def is_system_protected_app(app_name: str) -> bool:
    """Check if an app is a system app protected by SIP and cannot be removed."""
    normalized = _normalize_name(app_name)
    for protected in SYSTEM_PROTECTED_APPS:
        if _normalize_name(protected) == normalized:
            return True
    return False


def list_installed_apps() -> List[str]:
    names: Dict[str, str] = {}

    for folder in APP_SEARCH_DIRS:
        base = Path(folder).expanduser()
        if not base.exists():
            continue

        for entry in base.glob("*.app"):
            if not entry.is_dir():
                continue

            app_name = entry.stem.strip()
            if not app_name:
                continue

            names.setdefault(app_name.lower(), app_name)

    return sorted(names.values(), key=lambda name: name.lower())


def _normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _extract_name_from_stem(stem: str) -> str:
    cleaned = stem.strip().replace("_", " ").replace("-", " ")
    if not cleaned:
        return ""

    tokens = [part for part in cleaned.split(".") if part]
    if len(tokens) >= 3 and tokens[0].lower() in DOMAIN_PREFIXES:
        return tokens[-1]

    return cleaned


def _infer_app_name(path: Path) -> str:
    try:
        is_dir = path.is_dir()
    except OSError:
        is_dir = False

    if is_dir:
        return path.name.strip()

    if path.suffix.lower() == ".plist":
        return _extract_name_from_stem(path.stem)

    return _extract_name_from_stem(path.name)


def _list_dir(parent: Path) -> List[Path]:
    """List direct children of *parent*.

    Falls back to a ``ls -1A`` subprocess when Python's own directory read
    returns nothing due to macOS TCC restrictions (e.g. ~/Library/Application
    Support requires Full Disk Access for the Python framework binary).
    """
    try:
        entries = list(parent.iterdir())
        if entries:
            return entries
    except OSError:
        return []

    # Python got an empty listing — try via the shell which inherits the
    # Terminal's Full Disk Access grant.
    try:
        result = subprocess.run(
            ["ls", "-1A", str(parent)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []
        return [parent / name for name in result.stdout.splitlines() if name]
    except Exception:  # noqa: BLE001
        return []


# Max entries collected per scan category so that noisy categories (Logs,
# Containers) do not crowd out results from other locations.
_MAX_PER_CATEGORY = 200


def list_orphan_leftovers(max_results: int = 2000) -> List[OrphanPath]:
    installed_norm = {_normalize_name(name) for name in list_installed_apps()}
    found: Dict[str, OrphanPath] = {}
    category_counts: Dict[str, int] = {}

    # Build the list of (category, parent_dir, glob_pattern) to scan.
    scan_targets: List[Tuple[str, Path, str]] = []

    # Scan DARWIN_USER_CACHE_DIR first — it's per-boot and would otherwise be
    # pushed out by the max_results cap when Application Support is large.
    darwin_cache = _darwin_user_cache_dir()
    if darwin_cache:
        scan_targets.append(("Darwin User Caches", darwin_cache, "*"))

    for category, pattern in ORPHAN_PATTERNS:
        expanded = Path(pattern).expanduser()
        scan_targets.append((category, expanded.parent, expanded.name))

    for category, parent, glob_pattern in scan_targets:
        if not parent.exists():
            continue

        # Use _list_dir so that paths blocked by TCC (e.g. ~/Library/Application
        # Support) are still enumerated via the shell fallback.
        if glob_pattern == "*":
            candidates = _list_dir(parent)
        else:
            # For patterns like "*.plist" first try Python glob, then shell fallback.
            candidates = list(parent.glob(glob_pattern))
            if not candidates:
                import fnmatch
                candidates = [p for p in _list_dir(parent) if fnmatch.fnmatch(p.name, glob_pattern)]

        for match in candidates:
            # Skip hidden files/dirs — they are system internals, not app leftovers.
            if match.name.startswith("."):
                continue

            try:
                app_name = _infer_app_name(match)
            except OSError:
                continue
            app_name_norm = _normalize_name(app_name)

            if not app_name_norm:
                continue
            if app_name_norm in installed_norm:
                continue
            if app_name_norm in IGNORED_APP_NAMES:
                continue

            key = str(match)
            found[key] = OrphanPath(
                path=match,
                category=category,
                app_name=app_name,
                size_bytes=_compute_size(match),
            )
            category_counts[category] = category_counts.get(category, 0) + 1
            if category_counts[category] >= _MAX_PER_CATEGORY:
                break


    return sorted(found.values(), key=lambda item: (item.app_name.lower(), str(item.path)))[:max_results]


def scan_app(app_name: str) -> ScanResult:
    cleaned = app_name.strip()
    if not cleaned:
        return ScanResult(app_name=app_name, found_paths=[])

    found: List[CandidatePath] = []
    for category, pattern in BASE_PATTERNS:
        expanded = Path(pattern.format(app=cleaned)).expanduser()

        # Use parent + glob to support wildcard patterns.
        if "*" in str(expanded):
            parent = expanded.parent
            glob_pattern = expanded.name
            if parent.exists():
                for match in parent.glob(glob_pattern):
                    if match.exists():
                        found.append(CandidatePath(path=match, category=category))
        else:
            if expanded.exists():
                found.append(CandidatePath(path=expanded, category=category))

    unique: Dict[str, CandidatePath] = {}
    for item in found:
        unique[str(item.path)] = item

    return ScanResult(app_name=cleaned, found_paths=sorted(unique.values(), key=lambda c: str(c.path)))


# ---------------------------------------------------------------------------
# Deep scan — extended patterns with risk classification
# ---------------------------------------------------------------------------

_RISK_ORDER: Dict[RiskLevel, int] = {
    RiskLevel.CRITICAL: 0,
    RiskLevel.HIGH: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.LOW: 3,
}

# (category, pattern_{app}, risk_level, risk_reason)
_DEEP_APP_PATTERNS: List[Tuple[str, str, RiskLevel, str]] = [
    (
        "Bundle principal",
        "/Applications/{app}.app",
        RiskLevel.HIGH,
        "Ejecutable y recursos de la app. Eliminarlo desinstala completamente la aplicacion.",
    ),
    (
        "Bundle (carpeta usuario)",
        "~/Applications/{app}.app",
        RiskLevel.HIGH,
        "Copia del bundle instalada en la carpeta personal del usuario.",
    ),
    (
        "Application Support (usuario)",
        "~/Library/Application Support/{app}",
        RiskLevel.MEDIUM,
        "Datos del usuario: bases de datos, documentos y configuracion local. Eliminar puede causar perdida de datos.",
    ),
    (
        "Application Support (sistema)",
        "/Library/Application Support/{app}",
        RiskLevel.MEDIUM,
        "Datos compartidos del sistema para esta app. Eliminar puede afectar a todos los usuarios del equipo.",
    ),
    (
        "Caches (usuario)",
        "~/Library/Caches/*{app}*",
        RiskLevel.LOW,
        "Archivos temporales regenerables automaticamente. Seguro eliminar, liberan espacio en disco.",
    ),
    (
        "Caches (sistema)",
        "/Library/Caches/*{app}*",
        RiskLevel.LOW,
        "Caches del sistema para esta app. Seguro eliminar.",
    ),
    (
        "Preferencias (usuario)",
        "~/Library/Preferences/*{app}*",
        RiskLevel.HIGH,
        "Archivo de configuracion y preferencias del usuario. Eliminarlo restablece todos los ajustes al estado inicial.",
    ),
    (
        "Preferencias (sistema)",
        "/Library/Preferences/*{app}*",
        RiskLevel.HIGH,
        "Preferencias a nivel de sistema. Eliminar restablece la configuracion para todos los usuarios.",
    ),
    (
        "Logs (usuario)",
        "~/Library/Logs/*{app}*",
        RiskLevel.LOW,
        "Registros de actividad de la app. Seguro eliminar; no afectan el funcionamiento.",
    ),
    (
        "Logs (sistema)",
        "/Library/Logs/*{app}*",
        RiskLevel.LOW,
        "Registros del sistema. Seguro eliminar.",
    ),
    (
        "LaunchAgent (usuario)",
        "~/Library/LaunchAgents/*{app}*",
        RiskLevel.CRITICAL,
        "Servicio en segundo plano que se ejecuta al iniciar sesion. Eliminar puede interrumpir sincronizacion o notificaciones.",
    ),
    (
        "LaunchAgent (sistema)",
        "/Library/LaunchAgents/*{app}*",
        RiskLevel.CRITICAL,
        "Servicio del sistema para todos los usuarios. Eliminar puede afectar servicios compartidos.",
    ),
    (
        "LaunchDaemon",
        "/Library/LaunchDaemons/*{app}*",
        RiskLevel.CRITICAL,
        "Demonio del sistema con privilegios elevados. Eliminar puede interrumpir servicios criticos.",
    ),
    (
        "Helper con privilegios",
        "/Library/PrivilegedHelperTools/*{app}*",
        RiskLevel.CRITICAL,
        "Herramienta con permisos de administrador. Eliminar puede romper funciones que requieren privilegios.",
    ),
    (
        "Extension del kernel",
        "/Library/Extensions/*{app}*",
        RiskLevel.CRITICAL,
        "Driver de bajo nivel del sistema. Eliminar sin precaucion puede causar inestabilidad.",
    ),
    (
        "Reportes de fallos",
        "~/Library/Application Support/CrashReporter/*{app}*",
        RiskLevel.LOW,
        "Registros de fallos anteriores de la app. Seguro eliminar.",
    ),
]

# (category, pattern_{bundle_id}, risk_level, risk_reason)
_DEEP_BUNDLE_PATTERNS: List[Tuple[str, str, RiskLevel, str]] = [
    (
        "Contenedor sandbox",
        "~/Library/Containers/{bundle_id}",
        RiskLevel.MEDIUM,
        "Datos aislados de la app (modelo sandbox). Puede contener documentos y datos del usuario.",
    ),
    (
        "Application Support (bundle ID)",
        "~/Library/Application Support/{bundle_id}",
        RiskLevel.MEDIUM,
        "Datos de soporte identificados por bundle ID. Misma naturaleza que Application Support por nombre.",
    ),
    (
        "Caches (bundle ID)",
        "~/Library/Caches/{bundle_id}",
        RiskLevel.LOW,
        "Caches identificados por bundle ID. Seguro eliminar.",
    ),
    (
        "Preferencias (bundle ID)",
        "~/Library/Preferences/{bundle_id}.plist",
        RiskLevel.HIGH,
        "Archivo de preferencias vinculado al bundle ID. Eliminarlo borra toda la configuracion de la app.",
    ),
    (
        "Estado guardado",
        "~/Library/Saved Application State/{bundle_id}.savedState",
        RiskLevel.LOW,
        "Estado de ventanas y sesion al cerrar la app. Seguro eliminar.",
    ),
    (
        "Scripts de automatizacion",
        "~/Library/Application Scripts/{bundle_id}",
        RiskLevel.LOW,
        "Scripts de automatizacion (AppleScript/Shortcuts) asociados a la app.",
    ),
    (
        "Datos WebKit",
        "~/Library/WebKit/{bundle_id}",
        RiskLevel.LOW,
        "Datos de vistas web dentro de la app (cookies, localStorage). Seguro eliminar.",
    ),
    (
        "Almacen HTTP",
        "~/Library/HTTPStorages/{bundle_id}",
        RiskLevel.LOW,
        "Almacen de datos HTTP local. Seguro eliminar.",
    ),
    (
        "Contenedores de grupo",
        "~/Library/Group Containers/*{bundle_id}*",
        RiskLevel.MEDIUM,
        "Datos compartidos entre la app y sus extensiones (widget, share extension, etc.).",
    ),
    (
        "LaunchAgent (bundle ID)",
        "~/Library/LaunchAgents/*{bundle_id}*",
        RiskLevel.CRITICAL,
        "Servicio en segundo plano identificado por bundle ID. Eliminar puede interrumpir la sincronizacion.",
    ),
]


def get_bundle_id(app_name: str) -> str:
    for folder in APP_SEARCH_DIRS:
        candidate = Path(folder).expanduser() / "{}.app".format(app_name)
        if not candidate.is_dir():
            continue
        info_plist = candidate / "Contents" / "Info.plist"
        if not info_plist.exists():
            continue
        try:
            with open(str(info_plist), "rb") as fh:
                data = plistlib.load(fh)
            bundle_id = data.get("CFBundleIdentifier", "")
            if bundle_id:
                return str(bundle_id)
        except Exception:  # noqa: BLE001
            pass
    return ""


def _compute_size(path: Path) -> int:
    try:
        if path.is_symlink() or path.is_file():
            return path.stat().st_size
        total = 0
        for entry in path.rglob("*"):
            try:
                if not entry.is_symlink() and entry.is_file():
                    total += entry.stat().st_size
            except OSError:
                pass
        return total
    except OSError:
        return 0


def _expand_and_glob(pattern: str, app: str, bundle_id: str) -> List[Path]:
    rendered = pattern.replace("{app}", app).replace("{bundle_id}", bundle_id)
    expanded = Path(rendered).expanduser()
    if "*" in str(expanded):
        parent = expanded.parent
        glob_pat = expanded.name
        if parent.exists():
            return [m for m in parent.glob(glob_pat) if m.exists()]
        return []
    return [expanded] if expanded.exists() else []


def deep_scan_app(app_name: str) -> DeepScanResult:
    cleaned = app_name.strip()
    if not cleaned:
        return DeepScanResult(app_name=app_name, bundle_id="", items=[])

    bundle_id = get_bundle_id(cleaned)
    found: Dict[str, DeepScanItem] = {}

    for category, pattern, risk, reason in _DEEP_APP_PATTERNS:
        for match in _expand_and_glob(pattern, cleaned, bundle_id):
            key = str(match)
            if key not in found:
                found[key] = DeepScanItem(
                    path=match,
                    category=category,
                    risk_level=risk,
                    risk_reason=reason,
                    size_bytes=_compute_size(match),
                )

    if bundle_id:
        for category, pattern, risk, reason in _DEEP_BUNDLE_PATTERNS:
            for match in _expand_and_glob(pattern, cleaned, bundle_id):
                key = str(match)
                if key not in found:
                    found[key] = DeepScanItem(
                        path=match,
                        category=category,
                        risk_level=risk,
                        risk_reason=reason,
                        size_bytes=_compute_size(match),
                    )

    items = sorted(found.values(), key=lambda x: (_RISK_ORDER.get(x.risk_level, 99), str(x.path)))
    return DeepScanResult(app_name=cleaned, bundle_id=bundle_id, items=items)
