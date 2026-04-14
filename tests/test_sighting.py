from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from tsunamisight.sighting import push_sighting


@pytest.fixture
def fake_client():
    return MagicMock()


def _payload(client):
    return client.create_sighting.call_args.kwargs["sighting"]


def test_push_sighting_builds_correct_payload(fake_client):
    fake_client.create_sighting.return_value = {"message": "created"}
    when = datetime(2024, 5, 1, 12, 0, tzinfo=timezone.utc)
    push_sighting(
        fake_client,
        plugin_relpath="google/detectors/rce/cve202342793",
        cve="CVE-2023-42793",
        when=when,
        sighting_type="published-proof-of-concept",
    )
    payload = _payload(fake_client)
    assert payload["vulnerability"] == "CVE-2023-42793"
    assert payload["type"] == "published-proof-of-concept"
    assert payload["source"] == (
        "https://github.com/google/tsunami-security-scanner-plugins/tree/master/"
        "google/detectors/rce/cve202342793"
    )
    assert payload["creation_timestamp"] == when


def test_duplicate_response_is_info_level(fake_client, caplog):
    fake_client.create_sighting.return_value = {"message": "duplicate sighting"}
    with caplog.at_level("INFO"):
        push_sighting(
            fake_client,
            plugin_relpath="x/y/z",
            cve="CVE-2020-1111",
            when=datetime(2024, 1, 1, tzinfo=timezone.utc),
            sighting_type="confirmed",
        )
    assert any("duplicate" in r.message.lower() for r in caplog.records)
    assert all(r.levelname != "WARNING" for r in caplog.records)


def test_non_duplicate_message_is_warning(fake_client, caplog):
    fake_client.create_sighting.return_value = {"message": "invalid type"}
    with caplog.at_level("WARNING"):
        push_sighting(
            fake_client,
            plugin_relpath="x/y/z",
            cve="CVE-2020-1111",
            when=datetime(2024, 1, 1, tzinfo=timezone.utc),
            sighting_type="confirmed",
        )
    assert any(r.levelname == "WARNING" for r in caplog.records)


def test_client_exception_is_swallowed(fake_client, caplog):
    fake_client.create_sighting.side_effect = RuntimeError("boom")
    with caplog.at_level("WARNING"):
        push_sighting(
            fake_client,
            plugin_relpath="x/y/z",
            cve="CVE-2020-1111",
            when=datetime(2024, 1, 1, tzinfo=timezone.utc),
            sighting_type="confirmed",
        )
    assert any("boom" in r.message for r in caplog.records)
