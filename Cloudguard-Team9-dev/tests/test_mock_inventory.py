from cloudguard.azure.mock_inventory import load_mock_resources


def test_load_mock_resources() -> None:
    resources = load_mock_resources()

    assert len(resources) == 4
    assert resources[0].name == "web-server-01"
    assert resources[0].tags["Environment"] == "dev"
    assert resources[1].name == "api-server-01"
    assert "Environment" not in resources[1].tags