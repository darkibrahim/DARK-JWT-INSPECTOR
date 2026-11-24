"""OS / architecture / Python / environment detection (Termux, NetHunter, Kali, Arch)."""
from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional

from config import MIN_PYTHON


@dataclass
class PlatformInfo:
    os_name: str
    os_release: str
    distro_id: str
    distro_name: str
    architecture: str
    arch_family: str
    python_version: str
    python_ok: bool
    is_termux: bool
    is_nethunter: bool
    is_kali: bool
    is_arch: bool
    is_android: bool
    package_manager: str
    environment: str
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def parse_os_release(text: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        data[key.strip()] = value.strip().strip('"').strip("'")
    return data


def _read_os_release() -> str:
    for candidate in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            return Path(candidate).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return ""


def detect_termux(env: Mapping[str, str], path_exists: Callable[[str], bool]) -> bool:
    return bool(
        env.get("TERMUX_VERSION")
        or "com.termux" in env.get("PREFIX", "")
        or path_exists("/data/data/com.termux/files/usr")
    )


def detect_nethunter(env: Mapping[str, str], path_exists: Callable[[str], bool],
                     is_kali: bool, is_android: bool) -> bool:
    """Heuristic: Kali userland running on an Android kernel, or NetHunter marker files."""
    if env.get("NETHUNTER") or path_exists("/data/local/nhsystem") or path_exists("/etc/nethunter"):
        return True
    return is_kali and is_android


def detect_platform(
    env: Optional[Mapping[str, str]] = None,
    os_release_text: Optional[str] = None,
    path_exists: Optional[Callable[[str], bool]] = None,
    which: Optional[Callable[[str], Optional[str]]] = None,
    system: Optional[str] = None,
    machine: Optional[str] = None,
    release: Optional[str] = None,
    py_version: Optional[tuple] = None,
) -> PlatformInfo:
    """All inputs can be injected so detection is unit-testable on any machine."""
    env = os.environ if env is None else env
    path_exists = path_exists or (lambda p: Path(p).exists())
    which = which or shutil.which
    system = system or platform.system()
    machine = machine or platform.machine()
    release = release or platform.release()
    py_version = py_version or sys.version_info[:3]
    text = _read_os_release() if os_release_text is None else os_release_text

    osr = parse_os_release(text)
    distro_id = osr.get("ID", "").lower()
    id_like = osr.get("ID_LIKE", "").lower().split()
    distro_name = osr.get("PRETTY_NAME") or osr.get("NAME") or ""

    is_kali = distro_id == "kali"
    is_arch = distro_id in ("arch", "archarm", "manjaro", "endeavouros") or "arch" in id_like
    is_android = (
        "android" in release.lower()
        or bool(env.get("ANDROID_ROOT") or env.get("ANDROID_DATA"))
        or path_exists("/system/build.prop")
    )
    is_termux = detect_termux(env, path_exists)
    is_nethunter = detect_nethunter(env, path_exists, is_kali, is_android) and not is_termux

    m = machine.lower()
    if m in ("aarch64", "arm64"):
        arch_family = "ARM64 (aarch64)"
    elif m in ("x86_64", "amd64"):
        arch_family = "x86_64"
    else:
        arch_family = machine or "unknown"

    if is_termux:
        pm = "pkg" if which("pkg") else ("apt" if which("apt") else "unknown")
    else:
        pm = next((c for c in ("apt", "pacman", "dnf", "apk") if which(c)), "unknown")

    if is_termux:
        environment = "Termux"
    elif is_nethunter:
        environment = "Kali NetHunter (rootless)"
    elif is_kali:
        environment = "Kali Linux"
    elif is_arch:
        environment = "Arch Linux"
    else:
        environment = "%s (generic)" % (system or "Unknown OS")

    python_ok = tuple(py_version[:2]) >= MIN_PYTHON
    notes: List[str] = []
    if not python_ok:
        notes.append("Python %d.%d+ is required." % MIN_PYTHON)
    if arch_family not in ("ARM64 (aarch64)", "x86_64"):
        notes.append("Architecture '%s' is outside the targeted set (ARM64, x86_64)." % machine)
    if is_nethunter:
        notes.append("NetHunter detected by heuristics; detection is best-effort.")

    return PlatformInfo(
        os_name=system, os_release=release, distro_id=distro_id, distro_name=distro_name,
        architecture=machine, arch_family=arch_family,
        python_version=".".join(str(x) for x in py_version[:3]), python_ok=python_ok,
        is_termux=is_termux, is_nethunter=is_nethunter, is_kali=is_kali, is_arch=is_arch,
        is_android=is_android, package_manager=pm, environment=environment, notes=notes,
    )


def install_hints(info: PlatformInfo) -> List[str]:
    """Environment-specific installation commands (printed, never auto-run)."""
    if info.is_termux:
        return [
            "Termux (no sudo needed):",
            "  pkg update && pkg install python git",
            "  pkg install python-cryptography     # optional: enables RSA/ECDSA verification",
            "  sh install.sh",
        ]
    if info.is_nethunter:
        return [
            "Kali NetHunter Rootless (run inside the NetHunter terminal):",
            "  apt update && apt install -y python3 python3-venv python3-pip git",
            "  apt install -y python3-cryptography   # optional: RSA/ECDSA verification",
            "  sh install.sh",
            "  (If apt says 'permission denied', Python 3 is usually preinstalled: just run sh install.sh)",
        ]
    if info.is_kali:
        return [
            "Kali Linux:",
            "  sudo apt update && sudo apt install -y python3 python3-venv python3-pip git",
            "  sudo apt install -y python3-cryptography   # optional: RSA/ECDSA verification",
            "  sh install.sh",
        ]
    if info.is_arch:
        return [
            "Arch Linux:",
            "  sudo pacman -S --needed python python-pip git",
            "  sudo pacman -S --needed python-cryptography   # optional: RSA/ECDSA verification",
            "  sh install.sh",
        ]
    return [
        "Generic Linux/Unix:",
        "  Install Python %d.%d+ and git with your package manager." % MIN_PYTHON,
        "  sh install.sh",
    ]
