"""Static wire-format model of the current GitHub unichat.exe dedicated TCP sender.

Reconstructed from PE32 build SHA-256
ca7dfa6520e67e6c5a77287f8160d02b4117b0e69c2a6702dfcbe2986f70766d,
sender routine at VA 0x5A3390 (IsServer=true branch).

The first NUL in prefix terminates the decimal outer length; it is not part
of the payload consumed by the server. The additional NUL between prefix and
primary data is part of the advertised payload length.
"""
from __future__ import annotations

import unittest

FORWARD = b"\x00FORWARD\x00"
UNCHAT = b"\x00UniChat\x00"


def build_current_dedicated_frame(
    client_id: bytes, target: bytes, header5: bytes, primary_data: bytes
) -> bytes:
    if len(header5) != 5:
        raise ValueError("inner header must be exactly five bytes")
    # The Delphi sender assembles:
    # NUL + ClientId + NUL-FORWARD-NUL + target + NUL-UniChat-NUL + header5
    # followed by one NUL separator and the opaque primary data.
    prefix = b"\x00" + client_id + FORWARD + target + UNCHAT + header5
    advertised = len(prefix) + len(primary_data)
    return str(advertised).encode("ascii") + prefix + b"\x00" + primary_data


def read_current_server_frame(frame: bytes) -> tuple[int, bytes]:
    header_end = frame.find(b"\x00")
    if header_end <= 0:
        raise ValueError("missing decimal header")
    advertised = int(frame[:header_end].decode("ascii"))
    start = header_end + 1
    end = start + advertised
    if end > len(frame):
        raise ValueError("truncated frame")
    return end, frame[start:end]


def client_receiver_frame_end(frame: bytes) -> int:
    """Model current client callback: decimal digit count + NUL + advertised bytes."""
    header_end = frame.find(b"\x00")
    if header_end <= 0:
        raise ValueError("missing decimal header")
    advertised = int(frame[:header_end].decode("ascii"))
    return header_end + 1 + advertised


def parse_server_prefix(payload: bytes) -> tuple[bytes, bytes, bytes] | None:
    fields = payload.split(b"\x00", 3)
    if len(fields) < 3 or not fields[0]:
        return None
    return fields[0], fields[1], fields[2]


class CurrentDelphiDedicatedTcpSpecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.header5 = bytes.fromhex("7856341230")
        self.primary = b"opaque-encrypted-data"

    def test_direct_message_prefix_matches_current_csharp_parser(self) -> None:
        frame = build_current_dedicated_frame(
            b"alice", b"bob", self.header5, self.primary
        )
        end, payload = read_current_server_frame(frame)
        self.assertEqual(end, len(frame))
        self.assertEqual(parse_server_prefix(payload), (b"alice", b"FORWARD", b"bob"))

    def test_broadcast_target_matches_current_csharp_parser(self) -> None:
        frame = build_current_dedicated_frame(
            b"alice", b"*", self.header5, self.primary
        )
        end, payload = read_current_server_frame(frame)
        self.assertEqual(end, len(frame))
        self.assertEqual(parse_server_prefix(payload), (b"alice", b"FORWARD", b"*"))

    def test_advertised_length_includes_internal_separator_exactly(self) -> None:
        frame = build_current_dedicated_frame(
            b"alice", b"bob", self.header5, self.primary
        )
        end, payload = read_current_server_frame(frame)
        self.assertEqual(len(payload), len(frame) - frame.index(b"\x00") - 1)
        self.assertEqual(end, len(frame))

    def test_client_receiver_boundary_matches_sender_and_server_reader(self) -> None:
        frame = build_current_dedicated_frame(
            b"alice", b"bob", self.header5, self.primary
        )
        receiver_end = client_receiver_frame_end(frame)
        server_end, _ = read_current_server_frame(frame)
        self.assertEqual(receiver_end, server_end)
        self.assertEqual(receiver_end, len(frame))

    def test_client_receiver_preserves_next_frame_after_coalesced_reads(self) -> None:
        first = build_current_dedicated_frame(
            b"alice", b"bob", self.header5, b"first-payload"
        )
        second = build_current_dedicated_frame(
            b"bob", b"alice", self.header5, b"second-payload"
        )
        end = client_receiver_frame_end(first + second)
        self.assertEqual((first + second)[end:], second)

    def test_inner_unichat_marker_and_five_byte_header_are_in_frame(self) -> None:
        frame = build_current_dedicated_frame(
            b"alice", b"bob", self.header5, self.primary
        )
        _, payload = read_current_server_frame(frame)
        marker = b"\x00UniChat\x00"
        marker_offset = payload.index(marker)
        self.assertEqual(payload[marker_offset + len(marker):][:5], self.header5)

    def test_two_coalesced_frames_leave_next_decimal_header_intact(self) -> None:
        first = build_current_dedicated_frame(
            b"alice", b"bob", self.header5, b"first-payload"
        )
        second = build_current_dedicated_frame(
            b"bob", b"alice", self.header5, b"second-payload"
        )
        first_end, _ = read_current_server_frame(first + second)
        self.assertEqual((first + second)[first_end:], second)


if __name__ == "__main__":
    unittest.main(verbosity=2)
