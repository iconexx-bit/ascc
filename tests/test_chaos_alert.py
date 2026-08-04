def test_chaos_alert_pipeline() -> None:
    """Temporary chaos test: intentionally fails to verify the
    Discord/Telegram failure-notification steps in ci.yml actually fire.
    Delete this file once the alert has been confirmed received."""
    assert False, "Chaos Trigger (Test Alert) — expected failure"
