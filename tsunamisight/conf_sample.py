vulnerability_lookup_base_url = "https://vulnerability.circl.lu/"
vulnerability_auth_token = ""

tsunami_plugins_git_repository = "tsunami-security-scanner-plugins"

sighting_type = "published-proof-of-concept"
incremental_window = "7 days ago"

# Optional Valkey heartbeat (graceful fallback if unreachable)
heartbeat_enabled = True
valkey_host = "127.0.0.1"
valkey_port = 10002
expiration_period = 18000
