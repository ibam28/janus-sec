"""User configuration: config.toml, ignore list, and user-added allowlist entries.

Lives at ~/.config/janus-sec/config.toml (XDG_CONFIG_HOME), separate from
the audit log's state directory - config is what the user set up, state is
a record of what happened.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from janus_sec.checks.group_ownership import AllowlistPattern

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # Python 3.10 fallback


class ConfigError(ValueError):
    """Raised when the user config file cannot be parsed or an entry is
    missing a required key. Subclasses ValueError because tomllib parse
    errors already surface as ValueError subclasses.
    """


@dataclass(frozen=True, slots=True)
class IgnoreEntry:
    path: str
    check_type: str
    note: str = ""


@dataclass(frozen=True, slots=True)
class Config:
    ignore: list[IgnoreEntry]
    allowlist: list[AllowlistPattern]


def default_config_path() -> Path:
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg_config) if xdg_config else Path.home() / ".config"
    return base / "janus-sec" / "config.toml"


def _section_entries(
    data: dict,
    section: str,
    config_path: Path,
    required_keys: tuple[str, ...],
) -> list[dict]:
    """Return the entries of one array-of-tables section, verifying that
    the section is a list, each entry is a table, and every required key
    is present, so a malformed config produces an error naming the file,
    the entry, and the missing key(s) instead of a raw traceback.
    """
    entries = data.get(section, [])
    if not isinstance(entries, list):
        raise ConfigError(
            f"{config_path}: '{section}' must be an array of tables, written [[{section}]]"
        )

    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise ConfigError(
                f"{config_path}: [[{section}]] entry {index} must be a table"
            )
        missing = [key for key in required_keys if key not in entry]
        if missing:
            keys = ", ".join(f"'{key}'" for key in missing)
            raise ConfigError(
                f"{config_path}: [[{section}]] entry {index} is missing required key(s) {keys}"
            )

    return entries


def load_config(config_path: Path | None = None) -> Config:
    """Load user config. A missing file is not an error - it just means
    no ignore rules and no extra allowlist entries, same as a fresh
    install with nothing customized yet.

    Raises ConfigError when the file exists but is not valid TOML, or when
    an entry is missing a required key.
    """
    if config_path is None:
        config_path = default_config_path()

    if not config_path.exists():
        return Config(ignore=[], allowlist=[])

    try:
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {config_path}: {exc}") from exc

    ignore = [
        IgnoreEntry(
            path=entry["path"],
            check_type=entry["check_type"],
            note=entry.get("note", ""),
        )
        for entry in _section_entries(data, "ignore", config_path, ("path", "check_type"))
    ]

    allowlist = [
        AllowlistPattern(
            group=entry["group"],
            action=entry.get("action", "suppress"),
            os_name=entry.get("os"),
        )
        for entry in _section_entries(data, "allowlist", config_path, ("group",))
    ]

    return Config(ignore=ignore, allowlist=allowlist)


def is_ignored(path: str, check_type: str, config: Config) -> bool:
    return any(
        entry.path == path and entry.check_type == check_type
        for entry in config.ignore
    )


def filter_ignored(findings: list, config: Config) -> list:
    """Remove any finding that matches an ignore-list entry."""
    return [
        f for f in findings
        if not is_ignored(f.path, f.check_type.value, config)
    ]