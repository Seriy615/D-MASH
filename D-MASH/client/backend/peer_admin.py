#!/usr/bin/env python3
"""Local administrator utility for verified D-MASH Node mesh peers.

This tool is intentionally not an HTTP endpoint. Run it locally on the Node
host as the service user. ``add`` verifies the remote Node's PoW identity and
challenge signature before storing its dialable address in the encrypted local
peer directory. The daemon reconnect loop then maintains the link.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from crypto import NodeCryptoManager
from database import DatabaseManager
from network import P2PNode


def parse_address(value: str) -> str:
    """Accept only a dialable host:port understood by P2PNode.connect_to."""
    value = value.strip()
    if not value or ":" not in value or value.startswith(("ws://", "wss://", "http://", "https://")):
        raise argparse.ArgumentTypeError("peer address must be host:port (without a URL scheme)")
    host, port = value.rsplit(":", 1)
    if not host or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise argparse.ArgumentTypeError("peer address must contain a valid TCP port")
    return value


async def open_admin_runtime(args):
    key_path = Path(args.identity)
    try:
        signing_key = key_path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise RuntimeError(f"cannot read Node identity: {error}") from error
    if not signing_key:
        raise RuntimeError("Node identity file is empty")
    crypto = NodeCryptoManager(signing_key)
    database = DatabaseManager(args.database)
    database.set_node_crypto(crypto)
    await database.connect()
    return crypto, database


async def command_add(args) -> int:
    crypto, database = await open_admin_runtime(args)
    node = P2PNode(database, can_route=True, can_accept_devices=False)
    try:
        # connect_to performs the PoW and signature checks before add_neighbor.
        verified = await node.connect_to(args.address)
        if not verified:
            print("PEER_ADD_FAILED: remote Node did not complete a verified handshake", file=sys.stderr)
            return 2
        peers = await database.get_all_neighbors()
        added = next((peer for peer in peers if peer.get("address") == args.address), None)
        if not added:
            print("PEER_ADD_FAILED: verified connection was not persisted", file=sys.stderr)
            return 2
        print(json.dumps({
            "status": "VERIFIED_AND_SAVED",
            "peer_id": added["real_node_id"],
            "address": added["address"],
            "note": "The running Node reconnects this peer within 10 seconds; restart is not required.",
        }))
        return 0
    finally:
        # The live daemon owns the durable link. This short verification client
        # must not retain a duplicate socket after the command returns.
        for connection in list(node.active_connections.values()):
            await connection.close()
        await database.close()


async def command_list(args) -> int:
    _, database = await open_admin_runtime(args)
    try:
        peers = await database.get_all_neighbors()
        print(json.dumps({"known_peers": peers, "count": len(peers)}, indent=2))
        return 0
    finally:
        await database.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="D-MASH local mesh-peer administration")
    parser.add_argument("--database", default="system.db", help="path to the local Node system DB")
    parser.add_argument("--identity", default="node_identity.key", help="path to the local Node identity key")
    commands = parser.add_subparsers(dest="command", required=True)
    add = commands.add_parser("add", help="verify and persist a dialable Node peer")
    add.add_argument("address", type=parse_address, help="host:port of the peer P2P listener")
    commands.add_parser("list", help="show encrypted-directory peers known to this Node")
    args = parser.parse_args()
    return asyncio.run(command_add(args) if args.command == "add" else command_list(args))


if __name__ == "__main__":
    raise SystemExit(main())
