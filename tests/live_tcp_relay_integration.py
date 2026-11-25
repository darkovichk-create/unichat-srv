#!/usr/bin/env python3
"""End-to-end TCP relay test against a disposable UniChatServerd process.

Run after building the server:
  python3 tests/live_tcp_relay_integration.py --server-command dotnet bin/Release/net10.0/UniChatServerd.dll

The test binds only to 127.0.0.1 on an ephemeral port and uses a temporary
SQLite database. It never connects to or changes the production listener.
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def reserve_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise AssertionError(f"connection closed after {len(chunks)}/{size} bytes")
        chunks.extend(part)
    return bytes(chunks)


def recv_frame(sock: socket.socket) -> bytes:
    digits = bytearray()
    while True:
        char = recv_exact(sock, 1)
        if char == b"\x00":
            break
        if not char.isdigit() or len(digits) >= 10:
            raise AssertionError(f"invalid frame length header: {bytes(digits + char)!r}")
        digits.extend(char)
    if not digits:
        raise AssertionError("empty frame length")
    size = int(digits.decode("ascii"))
    if size <= 0 or size > 128 * 1024:
        raise AssertionError(f"invalid advertised payload size: {size}")
    return bytes(digits) + b"\x00" + recv_exact(sock, size)


def build_frame(sender: bytes, target: bytes, payload: bytes, seed: int) -> bytes:
    header5 = seed.to_bytes(4, "little") + b"0"
    prefix = (
        b"\x00" + sender + b"\x00FORWARD\x00" + target
        + b"\x00UniChat\x00" + header5
    )
    advertised = len(prefix) + len(payload)
    return str(advertised).encode("ascii") + prefix + b"\x00" + payload


def connect(port: int) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.settimeout(5)
    return sock


def wait_closed(sock: socket.socket) -> None:
    sock.settimeout(5)
    data = sock.recv(1)
    if data != b"":
        raise AssertionError(f"expected closed socket, received {data!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--server-command",
        nargs=argparse.REMAINDER,
        required=True,
        help="server command, e.g. dotnet bin/Release/net10.0/UniChatServerd.dll",
    )
    args = parser.parse_args()
    if not args.server_command:
        parser.error("--server-command must include an executable")
    if shutil.which(args.server_command[0]) is None and not Path(args.server_command[0]).exists():
        parser.error(f"server executable not found: {args.server_command[0]}")

    port = reserve_port()
    with tempfile.TemporaryDirectory(prefix="unichat-live-test-") as temp:
        root = Path(temp)
        db_path = root / "audit.db"
        log_path = root / "server.log"
        log_file = log_path.open("wb")
        command = args.server_command + [
            "--ip", "127.0.0.1",
            "--port", str(port),
            "--audit-db", str(db_path),
            "--log-level", "Information",
        ]
        server = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        clients: list[socket.socket] = []
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if server.poll() is not None:
                    raise AssertionError(
                        "server exited during startup:\n"
                        + log_path.read_text(errors="replace")
                    )
                try:
                    with connect(port):
                        pass
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise AssertionError(
                    "server did not listen within 15 seconds:\n"
                    + log_path.read_text(errors="replace")
                )

            alice = connect(port)
            bob = connect(port)
            clients.extend([alice, bob])

            # Register Alice and Bob with valid first frames; first route is offline.
            first_alice = build_frame(b"alice", b"bob", b"register-alice", 1)
            alice.sendall(first_alice)
            first_bob = build_frame(b"bob", b"alice", b"register-bob", 2)
            bob.sendall(first_bob)
            assert recv_frame(alice) == first_bob, "initial private route was not byte-exact"

            # A fragmented header/body must be reassembled and forwarded unchanged.
            fragmented = build_frame(
                b"alice", b"bob", b"fragmented-payload:" + bytes(range(64)), 3
            )
            for start, end in ((0, 1), (1, 3), (3, 8), (8, 17), (17, 29), (29, len(fragmented))):
                alice.sendall(fragmented[start:end])
                time.sleep(0.005)
            assert recv_frame(bob) == fragmented, "fragmented frame changed in relay"

            # Two coalesced frames must remain two intact frames at the receiver.
            coalesced_a = build_frame(b"alice", b"bob", b"coalesced-A", 4)
            coalesced_b = build_frame(b"alice", b"bob", b"coalesced-B", 5)
            alice.sendall(coalesced_a + coalesced_b)
            assert recv_frame(bob) == coalesced_a, "first coalesced frame mismatch"
            assert recv_frame(bob) == coalesced_b, "second coalesced frame mismatch"

            # A larger opaque body is relayed without transformation.
            large_payload = bytes(range(256)) * 256
            large = build_frame(b"alice", b"bob", large_payload, 6)
            alice.sendall(large)
            assert recv_frame(bob) == large, "large opaque payload changed"

            # Broadcast reaches the other connected client.
            broadcast = build_frame(b"alice", b"*", b"broadcast-check", 7)
            alice.sendall(broadcast)
            assert recv_frame(bob) == broadcast, "broadcast was not byte-exact"
            assert recv_frame(alice) == broadcast, "broadcast sender did not receive its own copy"

            # Disconnect/reconnect the same ID and verify it can receive again.
            bob.close()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if db_path.exists():
                    with sqlite3.connect(db_path) as audit:
                        closed = audit.execute(
                            "SELECT COUNT(*) FROM audit_events "
                            "WHERE event_type='session_closed' AND client_id='bob'"
                        ).fetchone()[0]
                    if closed:
                        break
                time.sleep(0.05)
            else:
                raise AssertionError(
                    "server did not record closure of the old Bob session:\\n"
                    + log_path.read_text(errors="replace")
                )
            bob = connect(port)
            clients.append(bob)
            reconnect = build_frame(b"bob", b"alice", b"reconnected", 8)
            bob.sendall(reconnect)
            try:
                routed_reconnect = recv_frame(alice)
            except Exception:
                raise AssertionError(
                    "reconnected client did not register:\\n"
                    + log_path.read_text(errors="replace")
                )
            assert routed_reconnect == reconnect, "reconnected route changed bytes"
            after_reconnect = build_frame(b"alice", b"bob", b"after-reconnect", 9)
            alice.sendall(after_reconnect)
            assert recv_frame(bob) == after_reconnect, "reconnected client did not receive"

            # A second connection cannot claim an ID already owned by Alice.
            duplicate = connect(port)
            clients.append(duplicate)
            duplicate.sendall(build_frame(b"alice", b"bob", b"duplicate", 10))
            wait_closed(duplicate)

            # A registered connection cannot change its sender ID mid-session.
            alice.sendall(build_frame(b"mallory", b"bob", b"spoof-attempt", 11))
            wait_closed(alice)

            for client in clients:
                try:
                    client.close()
                except OSError:
                    pass
            clients.clear()

            server.terminate()
            server.wait(timeout=15)
            log_file.flush()
            log_file.close()

            with sqlite3.connect(db_path) as db:
                assert db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
                rows = db.execute(
                    "SELECT event_type, result, target_id, details FROM audit_events"
                ).fetchall()
            events = {(event, result) for event, result, _, _ in rows}
            assert ("server_started", "listening") in events
            assert ("client_connected", "registered") in events
            assert ("message_routed", "queued_to_socket_queue") in events
            assert ("message_routed", "queued_to_socket_queues") in events
            assert ("protocol_error", "duplicate_client_id") in events
            assert ("protocol_error", "client_id_mismatch") in events
            assert any(
                event == "message_routed" and result == "recipient_offline"
                for event, result, _, _ in rows
            )
            assert not any(
                b"fragmented-payload" in str(row).encode()
                or b"coalesced-A" in str(row).encode()
                or b"broadcast-check" in str(row).encode()
                for row in rows
            ), "audit DB unexpectedly contains message payload text"

            print("PASS: isolated TCP relay end-to-end test")
            print("  fragmented header/body: exact")
            print("  coalesced frames: exact and correctly split")
            print("  large opaque payload: exact (64 KiB)")
            print("  private route and broadcast: queued")
            print("  reconnect with same ClientId: passed")
            print("  duplicate ClientId and sender-ID spoof: rejected")
            print("  SQLite quick_check and payload privacy: passed")
            print(f"  audit events verified: {len(rows)}")
            return 0
        finally:
            for client in clients:
                try:
                    client.close()
                except OSError:
                    pass
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
            if not log_file.closed:
                log_file.close()


if __name__ == "__main__":
    raise SystemExit(main())
