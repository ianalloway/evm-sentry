#!/usr/bin/env python3
"""Exercise the installed CLI against a deterministic local JSON-RPC server."""

from __future__ import annotations

import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ADDRESS = "0x" + "a" * 40
IMPLEMENTATION = "0x" + "1" * 40
UPGRADED_TOPIC = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        request = json.loads(self.rfile.read(length))
        method = request["method"]

        if method == "eth_getCode":
            result = "0x6000ff"
        elif method == "eth_getBalance":
            result = "0x0"
        elif method == "eth_getStorageAt":
            result = "0x" + "0" * 64
        elif method == "eth_blockNumber":
            result = "0x2710"
        elif method == "eth_getLogs":
            result = [
                {
                    "address": ADDRESS,
                    "topics": [
                        UPGRADED_TOPIC,
                        "0x" + "0" * 24 + IMPLEMENTATION.removeprefix("0x"),
                    ],
                    "data": "0x",
                    "blockNumber": "0x270f",
                    "transactionHash": "0xabc",
                    "logIndex": "0x0",
                }
            ]
        else:
            result = None

        body = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        return


def run(*args: str, env: dict[str, str]) -> dict:
    completed = subprocess.run(
        ["evm-sentry", *args],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    return json.loads(completed.stdout)


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        env = os.environ.copy()
        env.pop("ETHERSCAN_API_KEY", None)
        env["EVM_SENTRY_RPC_BASE"] = f"http://127.0.0.1:{server.server_port}"

        scan = run(ADDRESS, "--chain", "base", "--format", "json", env=env)
        assert scan["chain"] == "base"
        assert scan["is_contract"] is True
        assert any(item["id"] == "OPCODE_SELFDESTRUCT" for item in scan["findings"])

        timeline = run(
            "timeline",
            ADDRESS,
            "--chain",
            "base",
            "--format",
            "json",
            env=env,
        )
        assert timeline["from_block"] == 9_000
        assert timeline["to_block"] == 10_000
        assert timeline["events"][0]["values"]["implementation"] == IMPLEMENTATION
    finally:
        server.shutdown()
        server.server_close()

    print("EVM Sentry installed-CLI smoke test passed")


if __name__ == "__main__":
    main()
