"""Compatibility boundary tests for the reconstructed legacy sender and server parser.

These tests deliberately do not implement a production parser. They encode the
observed Delphi TCP metadata layout and the current C# TryParsePrefix contract
so a future compatibility change cannot silently conflate the two formats.
"""
from __future__ import annotations

import unittest

FORWARD = b"\x00FORWARD\x00"
UNCHAT = b"\x00UniChat\x00"


def legacy_metadata(local_identity: bytes, target: bytes, header5: bytes) -> bytes:
    if len(header5) != 5:
        raise ValueError("legacy inner header must be five bytes")
    # Reconstructed Delphi concat: NUL-FORWARD-NUL + identity + empty +
    # second sender argument + NUL-UniChat-NUL + five-byte header.
    return FORWARD + local_identity + b"" + target + UNCHAT + header5


def build_legacy_frame(metadata: bytes, encrypted: bytes, *, include_separator_in_length: bool) -> bytes:
    separator = FORWARD
    advertised = len(metadata) + len(encrypted)
    if include_separator_in_length:
        advertised += len(separator)
    return str(advertised).encode("ascii") + b"\x00" + metadata + separator + encrypted


def parse_current_server_prefix(payload: bytes) -> tuple[str, bytes, str] | None:
    """Model current ClientConnection.TryParsePrefix's first three NUL fields."""
    fields = payload.split(b"\x00", 3)
    if len(fields) < 3:
        return None
    cur_id, marker, target = fields[:3]
    if not cur_id:
        return None
    return cur_id.decode("cp1251"), marker, target.decode("cp1251")


def callback_frame_end(frame: bytes) -> int:
    nul = frame.index(b"\x00")
    return nul + 1 + int(frame[:nul].decode("ascii"))



def build_documented_sender_frame(prefix: bytes, data: bytes) -> bytes:
    """Model the C# comment: decimal(len(data)+len(prefix)) NUL prefix NUL data."""
    advertised = len(prefix) + len(data)
    return str(advertised).encode("ascii") + b"\x00" + prefix + b"\x00" + data


def current_reader_frame_end(frame: bytes) -> int:
    """Model ClientConnection.ReadHeaderAsync + wirePayloadLength=advertised."""
    nul = frame.index(b"\x00")
    return nul + 1 + int(frame[:nul].decode("ascii"))

class LegacyTcpCompatibilitySpecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.metadata = legacy_metadata(
            local_identity=b"alice",
            target=b"bob",
            header5=bytes.fromhex("7856341230"),
        )
        self.ciphertext = bytes(range(64))

    def test_documented_sender_length_leaves_last_data_byte_in_current_reader(self) -> None:
        prefix = b"\\x00alice\\x00FORWARD\\x00bob\\x00UniChat\\x00"
        frame = build_documented_sender_frame(prefix, b"payload")
        end = current_reader_frame_end(frame)
        self.assertEqual(frame[end:], b"d")

    def test_documented_sender_length_plus_separator_consumes_complete_frame(self) -> None:
        prefix = b"\\x00alice\\x00FORWARD\\x00bob\\x00UniChat\\x00"
        frame = build_documented_sender_frame(prefix, b"payload")
        nul = frame.index(b"\x00")
        corrected_end = nul + 1 + int(frame[:nul].decode("ascii")) + 1
        self.assertEqual(corrected_end, len(frame))

    def test_current_server_layout_is_parseable_by_current_prefix_contract(self) -> None:
        current_payload = b"alice\x00FORWARD\x00bob\x00UniChat\x00payload"
        parsed = parse_current_server_prefix(current_payload)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed, ("alice", b"FORWARD", "bob"))

    def test_reconstructed_legacy_layout_is_not_current_server_prefix_layout(self) -> None:
        parsed = parse_current_server_prefix(self.metadata + FORWARD + self.ciphertext)
        self.assertIsNone(parsed)  # leading NUL yields empty ClientId in current C# parser

    def test_corrected_length_formula_consumes_complete_legacy_frame(self) -> None:
        frame = build_legacy_frame(
            self.metadata, self.ciphertext, include_separator_in_length=True
        )
        end = callback_frame_end(frame)
        self.assertEqual(end, len(frame))
        self.assertEqual(frame[end:], b"")

    def test_legacy_length_formula_leaves_nine_byte_ciphertext_tail(self) -> None:
        frame = build_legacy_frame(
            self.metadata, self.ciphertext, include_separator_in_length=False
        )
        end = callback_frame_end(frame)
        self.assertEqual(len(frame) - end, len(FORWARD))
        self.assertEqual(frame[end:], self.ciphertext[-len(FORWARD):])


if __name__ == "__main__":
    unittest.main(verbosity=2)
