"""Small pure parsers for stabilityd configuration compatibility."""

from __future__ import annotations

from collections.abc import Mapping


RUNTIME_INTEGER_DEFAULTS = {
    "OPENCLAW_GATEWAY_PORT": 23466,
    "OPENCLAW_STABILITY_INTERVAL_SECONDS": 30,
    "OPENCLAW_STABILITY_POLICY_TTL_SECONDS": 180,
}


ACTUATOR_ENVIRONMENT_SETTING_NAMES = (
    "HERMERS_ACP_ORPHAN_REAP_ENABLED",
    "HERMERS_GATEWAY_RESTART_ENABLED",
    "HERMERS_LSP_IDLE_REAP_ENABLED",
    "LEASE_REAP_ENABLED",
    "SESSION_RESET_ENABLED",
    "CRON_MUTATION_ENABLED",
    "GATEWAY_RESTART_ENABLED",
    "SOFT_GATEWAY_RESTART_ENABLED",
    "SOFT_RESCUE_RESTART_ENABLED",
)


HERMERS_PROFILE_LIFECYCLE_SETTING_NAMES = {
    "modeEnabled": "CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_ENABLED",
    "actuateEnabled": "CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_ACTUATE",
    "startEnabled": "CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_START",
    "lifecycleAllowlist": "CAT_AGENTS_STABILITY_HERMERS_PROFILE_LIFECYCLE_ALLOWLIST",
    "coldIdleSeconds": "CAT_AGENTS_STABILITY_HERMERS_PROFILE_COLD_IDLE_SECONDS",
    "hibernateIdleSeconds": "CAT_AGENTS_STABILITY_HERMERS_PROFILE_HIBERNATE_IDLE_SECONDS",
    "lifecycleCooldownSeconds": "CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_ACTION_COOLDOWN_SECONDS",
    "protectedIds": "CAT_AGENTS_STABILITY_HERMERS_PROFILE_PROTECTED_IDS",
}


RESTART_ACTUATOR_SETTING_NAMES = {
    "RESTART_COOLDOWN_SECONDS": "OPENCLAW_STABILITY_RESTART_COOLDOWN_SECONDS",
    "RESTART_WINDOW_SECONDS": "OPENCLAW_STABILITY_RESTART_WINDOW_SECONDS",
    "MAX_RESTARTS_PER_WINDOW": "OPENCLAW_STABILITY_MAX_RESTARTS",
    "ACTION_STREAK_THRESHOLD": "OPENCLAW_STABILITY_ACTION_STREAK",
    "STARTUP_GRACE_SECONDS": "OPENCLAW_STABILITY_STARTUP_GRACE_SECONDS",
}
HERMERS_GATEWAY_RESTART_LIMIT_ENV = "CAT_AGENTS_STABILITY_HERMERS_GATEWAY_RESTART_LIMIT"


def parse_restart_actuator_settings(environ: Mapping[str, object]) -> dict[str, int]:
    """Parse the legacy restart thresholds without touching runtime state.

    Defaults intentionally retain the source expressions' string conversion.
    Invalid values are reported with a setting name only, avoiding raw-value
    disclosure while preserving Python's strict ``int`` conversion behavior.
    """
    def parse(name: str, default: object) -> int:
        try:
            return int(environ.get(name, default))
        except (TypeError, ValueError, OverflowError):
            raise ValueError("invalid integer setting: " + name) from None

    restart_cooldown = parse("OPENCLAW_STABILITY_RESTART_COOLDOWN_SECONDS", "1800")
    restart_window = parse("OPENCLAW_STABILITY_RESTART_WINDOW_SECONDS", str(6 * 3600))
    max_restarts = parse("OPENCLAW_STABILITY_MAX_RESTARTS", "2")
    action_streak = parse("OPENCLAW_STABILITY_ACTION_STREAK", "2")
    startup_grace = parse("OPENCLAW_STABILITY_STARTUP_GRACE_SECONDS", "240")
    return {
        "RESTART_COOLDOWN_SECONDS": restart_cooldown,
        "RESTART_WINDOW_SECONDS": restart_window,
        "MAX_RESTARTS_PER_WINDOW": max_restarts,
        "ACTION_STREAK_THRESHOLD": action_streak,
        "STARTUP_GRACE_SECONDS": startup_grace,
    }


def parse_hermers_gateway_restart_limit(environ: Mapping[str, object], max_restarts: int) -> int:
    """Preserve the later Hermes limit assignment and its resolved-max fallback."""
    try:
        return int(environ.get(HERMERS_GATEWAY_RESTART_LIMIT_ENV, str(max_restarts)))
    except (TypeError, ValueError, OverflowError):
        raise ValueError("invalid integer setting: " + HERMERS_GATEWAY_RESTART_LIMIT_ENV) from None


def startup_grace_active(service_age: int | None, grace_seconds: int) -> bool:
    """Return whether a known service age is strictly inside startup grace."""
    return service_age is not None and service_age < grace_seconds


def parse_hermers_profile_lifecycle_settings(environ: Mapping[str, object]) -> dict[str, object]:
    """Preserve the existing environment and alias semantics for profile lifecycle settings.

    This is a pure parser so migration can be checked against a pinned source
    without importing the daemon or exercising any profile/runtime behavior.
    A present primary key wins even when its value is empty.
    """
    allowlist = environ.get(
        "CAT_AGENTS_STABILITY_HERMERS_PROFILE_LIFECYCLE_ALLOWLIST",
        environ.get("CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_MANAGED", ""),
    )
    cooldown = environ.get(
        "CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_ACTION_COOLDOWN_SECONDS",
        environ.get("CAT_AGENTS_STABILITY_HERMERS_PROFILE_LIFECYCLE_COOLDOWN_SECONDS", "600"),
    )
    protected = environ.get(
        "CAT_AGENTS_STABILITY_HERMERS_PROFILE_PROTECTED_IDS",
        environ.get("CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_PROTECTED", "main,cat_heart,catheart,cat_claw"),
    )
    return {
        "modeEnabled": environ.get("CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_ENABLED", "1") != "0",
        "actuateEnabled": environ.get(
            "CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_ACTUATE",
            environ.get("CAT_AGENTS_STABILITY_HERMERS_PROFILE_ACTUATE", "0"),
        ) != "0",
        "startEnabled": environ.get("CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_START", "1") != "0",
        "lifecycleAllowlist": {item.strip() for item in allowlist.split(",") if item.strip()},
        "coldIdleSeconds": int(environ.get("CAT_AGENTS_STABILITY_HERMERS_PROFILE_COLD_IDLE_SECONDS", str(30 * 60))),
        "hibernateIdleSeconds": int(environ.get("CAT_AGENTS_STABILITY_HERMERS_PROFILE_HIBERNATE_IDLE_SECONDS", str(8 * 3600))),
        "lifecycleCooldownSeconds": int(cooldown),
        "protectedIds": {item.strip() for item in protected.split(",") if item.strip()},
    }


def parse_integer_settings(environ: Mapping[str, object], defaults: Mapping[str, int]) -> dict[str, int]:
    """Parse exact legacy integer env semantics from an explicit mapping.

    Missing values use the supplied defaults. Invalid present values raise a
    stable ValueError without echoing potentially sensitive configuration.
    """
    parsed = {}
    for name, default in defaults.items():
        raw = environ.get(name)
        if raw is None:
            parsed[name] = int(default)
            continue
        try:
            parsed[name] = int(raw)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"invalid integer setting: {name}") from exc
    return parsed


def parse_actuator_environment_settings(environ: Mapping[str, object]) -> dict[str, bool]:
    """Preserve exact legacy opt-in/out strings and alias precedence for actuators.

    These settings intentionally do not normalize case or whitespace. A
    primary Hermes variable wins even when empty; the remaining flags keep
    their original exact ``!= '0'`` or ``== '1'`` semantics.
    """
    return {
        "HERMERS_ACP_ORPHAN_REAP_ENABLED": environ.get(
            "CAT_AGENTS_STABILITY_REAP_HERMERS_ACP_ORPHANS",
            environ.get("OPENCLAW_STABILITY_REAP_HERMERS_ACP_ORPHANS", "1"),
        ) != "0",
        "HERMERS_GATEWAY_RESTART_ENABLED": environ.get(
            "CAT_AGENTS_STABILITY_RESTART_HERMERS_GATEWAY",
            environ.get("OPENCLAW_STABILITY_RESTART_HERMERS_GATEWAY", "0"),
        ) == "1",
        "HERMERS_LSP_IDLE_REAP_ENABLED": environ.get(
            "CAT_AGENTS_STABILITY_REAP_HERMERS_IDLE_LSP", "1"
        ) != "0",
        "LEASE_REAP_ENABLED": environ.get("OPENCLAW_STABILITY_REAP_LEASES", "1") != "0",
        "SESSION_RESET_ENABLED": environ.get("OPENCLAW_STABILITY_RESET_SESSIONS", "1") != "0",
        "CRON_MUTATION_ENABLED": environ.get("OPENCLAW_STABILITY_MUTATE_CRON", "1") != "0",
        "GATEWAY_RESTART_ENABLED": environ.get("OPENCLAW_STABILITY_RESTART_GATEWAY", "1") != "0",
        "SOFT_GATEWAY_RESTART_ENABLED": environ.get("OPENCLAW_STABILITY_SOFT_RESTART_GATEWAY", "0") == "1",
        "SOFT_RESCUE_RESTART_ENABLED": environ.get("OPENCLAW_STABILITY_SOFT_RESCUE_RESTART", "1") != "0",
    }
