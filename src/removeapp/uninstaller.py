from pathlib import Path
import json
import shlex
import shutil
import subprocess
from datetime import datetime
from typing import List, Optional, Tuple

from send2trash import send2trash

from .models import CandidatePath

_LSREGISTER = (
    "/System/Library/Frameworks/CoreServices.framework"
    "/Frameworks/LaunchServices.framework/Support/lsregister"
)


def refresh_launch_services(app_paths: Optional[List[Path]] = None) -> str:
    """Unregister specific .app bundles (or do a full domain rescan) from LaunchServices.
    Returns a short status string."""
    try:
        if app_paths:
            for p in app_paths:
                subprocess.run(
                    [_LSREGISTER, "-u", str(p)],
                    timeout=10,
                    capture_output=True,
                )
            # Also trigger a lightweight rescan so the index is consistent.
            subprocess.run(
                [_LSREGISTER, "-kill", "-r", "-domain", "local", "-domain", "user"],
                timeout=30,
                capture_output=True,
            )
            return "LaunchServices actualizado para {} bundle(s).".format(len(app_paths))
        else:
            subprocess.run(
                [_LSREGISTER, "-kill", "-r", "-domain", "local", "-domain", "system", "-domain", "user"],
                timeout=60,
                capture_output=True,
            )
            return "Base de datos LaunchServices reconstruida completamente."
    except Exception as exc:  # noqa: BLE001
        return "Error al actualizar LaunchServices: {}".format(exc)


def ensure_backup_dir(base: Optional[Path] = None) -> Path:
    root = base or Path.home() / ".removeapp"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _delete_permanently(target: Path) -> None:
    """Delete a path permanently, with elevated fallback on macOS.

    Some app bundles and system support files are owned by root and can raise
    permission errors when removed from a regular Python process.
    """
    try:
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        else:
            target.unlink()
        return
    except PermissionError:
        pass

    # Fallback: ask macOS for admin privileges to remove protected paths.
    quoted = shlex.quote(str(target))
    cmd = "rm -rf {}".format(quoted)
    result = subprocess.run(
        ["osascript", "-e", 'do shell script "{}" with administrator privileges'.format(cmd)],
        capture_output=True,
        timeout=30,
        text=True,
    )
    if result.returncode != 0:
        raise PermissionError(
            "Acceso denegado al eliminar {}. Ejecuta RemoveApp con permisos de admin "
            "o concede Acceso Total al Disco en Ajustes del Sistema > Privacidad y Seguridad.".format(target)
        )


def uninstall_paths(paths: List[CandidatePath], permanent: bool = False) -> Tuple[int, List[str], Path]:
    backup_dir = ensure_backup_dir()
    manifest_path = backup_dir / f"run-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"

    removed = 0
    errors: List[str] = []
    removed_paths: List[str] = []

    for item in paths:
        target = item.path
        try:
            if not target.exists() and not target.is_symlink():
                continue

            if permanent:
                _delete_permanently(target)
            else:
                try:
                    send2trash(str(target))
                except Exception as trash_exc:  # noqa: BLE001
                    # Fallback: use Finder via osascript for TCC-protected paths.
                    posix_path = str(target).replace('"', '\\"')
                    result = subprocess.run(
                        [
                            "osascript",
                            "-e",
                            'tell application "Finder" to delete POSIX file "{}"'.format(posix_path),
                        ],
                        capture_output=True,
                        timeout=15,
                    )
                    if result.returncode != 0:
                        raise PermissionError(
                            "{} (Acceso denegado — concede Acceso Total al Disco en "
                            "Ajustes del Sistema > Privacidad y Seguridad)".format(trash_exc)
                        ) from trash_exc

            removed += 1
            removed_paths.append(str(target))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{target}: {exc}")

    manifest_path.write_text(
        json.dumps(
            {
                "timestamp": datetime.now().isoformat(),
                "permanent": permanent,
                "removed_paths": removed_paths,
                "errors": errors,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    # Unregister any .app bundles that were removed so they disappear from
    # Spotlight, Command+Tab and the App Switcher immediately.
    app_bundles = [
        Path(p) for p in removed_paths if p.endswith(".app")
    ]
    if app_bundles:
        refresh_launch_services(app_bundles)
    elif removed_paths:
        # Even if the .app itself wasn't in this batch, rebuild the index so
        # stale entries (preferences, containers, etc.) are purged.
        refresh_launch_services()

    return removed, errors, manifest_path
