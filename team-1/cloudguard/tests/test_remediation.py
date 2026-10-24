from unittest.mock import MagicMock
from cloudguard.remediation.actions import AddMissingTagsAction, CloseOpenNSGRuleAction


def test_add_missing_tags_is_idempotent():
    client = MagicMock()
    client.tag_resource.return_value = {"applied": True}
    action = AddMissingTagsAction(client)

    details = {"resource": {"id": "r1", "tags": {}}, "missing_tags": ["owner"]}
    assert action.is_compliant(details) is False
    action.apply(details)
    client.tag_resource.assert_called_once()

    # Simulate resource now compliant -> re-run should be a no-op
    details["resource"]["tags"] = {"owner": "team-a"}
    result = action.apply(details)
    assert result["no_op"] is True
    assert client.tag_resource.call_count == 1  # not called again


def test_nsg_action_is_high_risk():
    client = MagicMock()
    action = CloseOpenNSGRuleAction(client)
    assert action.is_high_risk is True