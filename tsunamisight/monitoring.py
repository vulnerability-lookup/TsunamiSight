"""Optional Valkey heartbeat and log forwarding. Silent fallback if Valkey unreachable."""

import time

from tsunamisight import config

_client = None
if config.heartbeat_enabled:
    try:
        import valkey  # type: ignore

        _client = valkey.Valkey(config.valkey_host, config.valkey_port)
    except Exception as exc:
        print(f"Valkey init failed, heartbeat disabled: {exc}")
        _client = None


def heartbeat(key: str = "process_heartbeat_TsunamiSight") -> None:
    if _client is None:
        return
    try:
        _client.set(key, time.time(), ex=config.expiration_period)
    except Exception as exc:
        print(f"Heartbeat error: {exc}")


def log(level: str = "warning", message: str = "", key: str = "process_logs_TsunamiSight") -> None:
    if _client is None:
        return
    entry = {"timestamp": time.time(), "level": level, "message": message}
    try:
        _client.rpush(key, str(entry))
        _client.expire(key, 86400)
    except Exception as exc:
        print(f"Log push error: {exc}")
