"""Load user configuration from the path in TSUNAMISIGHT_CONFIG env var."""

import importlib.util
import os


def _load(path: str):
    spec = importlib.util.spec_from_file_location("tsunamisight_userconf", path)
    if not spec or not spec.loader:
        raise RuntimeError(f"Cannot load config from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_conf_path = os.environ.get("TSUNAMISIGHT_CONFIG", "tsunamisight/conf_sample.py")
try:
    _conf = _load(_conf_path)
except Exception as exc:
    raise RuntimeError(
        f"No configuration file provided (path={_conf_path!r})."
    ) from exc


vulnerability_lookup_base_url = _conf.vulnerability_lookup_base_url
vulnerability_auth_token = _conf.vulnerability_auth_token
tsunami_plugins_git_repository = _conf.tsunami_plugins_git_repository
sighting_type = _conf.sighting_type
incremental_window = getattr(_conf, "incremental_window", "7 days ago")

try:
    heartbeat_enabled = bool(_conf.heartbeat_enabled)
    valkey_host = _conf.valkey_host
    valkey_port = _conf.valkey_port
    expiration_period = _conf.expiration_period
except AttributeError:
    heartbeat_enabled = False
    valkey_host = "127.0.0.1"
    valkey_port = 0
    expiration_period = 0
