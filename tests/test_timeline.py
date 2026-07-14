from evm_sentry.timeline import decode_log, topic_address


def test_topic_address_decodes_indexed_address() -> None:
    topic = "0x" + "0" * 24 + "1234567890abcdef1234567890abcdef12345678"
    assert topic_address(topic) == "0x1234567890abcdef1234567890abcdef12345678"


def test_decode_upgraded_event() -> None:
    log = {
        "topics": [
            "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b",
            "0x" + "0" * 24 + "1234567890abcdef1234567890abcdef12345678",
        ],
        "blockNumber": "0x10",
        "transactionHash": "0xabc",
        "logIndex": "0x2",
        "data": "0x",
    }
    event = decode_log(log)
    assert event is not None
    assert event.event == "Upgraded(address)"
    assert event.block_number == 16
    assert event.values["implementation"] == "0x1234567890abcdef1234567890abcdef12345678"


def test_decode_admin_changed_event_data_addresses() -> None:
    previous_admin = "1" * 40
    new_admin = "2" * 40
    log = {
        "topics": [
            "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f",
        ],
        "blockNumber": "0x20",
        "transactionHash": "0xdef",
        "logIndex": "0x0",
        "data": "0x" + "0" * 24 + previous_admin + "0" * 24 + new_admin,
    }
    event = decode_log(log)
    assert event is not None
    assert event.event == "AdminChanged(address,address)"
    assert event.values["previous_admin"] == "0x" + previous_admin
    assert event.values["new_admin"] == "0x" + new_admin
