from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List


class RiskLevel(str, Enum):
    LOW = "Bajo"
    MEDIUM = "Medio"
    HIGH = "Alto"
    CRITICAL = "Crítico"


@dataclass
class CandidatePath:
    path: Path
    category: str


@dataclass
class OrphanPath:
    path: Path
    category: str
    app_name: str
    size_bytes: int = 0


@dataclass
class ScanResult:
    app_name: str
    found_paths: List[CandidatePath]


@dataclass
class DeepScanItem:
    path: Path
    category: str
    risk_level: RiskLevel
    risk_reason: str
    size_bytes: int = 0


@dataclass
class DeepScanResult:
    app_name: str
    bundle_id: str
    items: List[DeepScanItem]
