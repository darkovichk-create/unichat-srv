"""Historical compatibility models plus checks for the documented C# length formula.

The nine-byte legacy reconstruction below belongs to the older uploaded EXE
(SHA-256 bc22efd0c092c85f3e086a768f23ad62fe0dc085e5a62ab2227618ac94243d5f).
It is NOT the current GitHub EXE. The current GitHub build is modeled separately
in current_delphi_dedicated_tcp_spec.py.

These tests are offline models, not a production parser or packet capture.
"""
from __future__ import annotations

import unittest

FORWARD = b"\x00FORWARD\x00"
UNCHAT = b"\x00UniChat\x00"


def legacy_metadata(local_identity: bytes, target: bytes, header5: bytes) -> bytes:
    """Historical older-build metadata reconstruction; not the current sender."""
    if len(header5) != 5:
        raise ValueError("legacy inner header must be five bytes")
    return FORWARD + local_identity + b"" + target + UNCHAT + header5


def build_legacy_frame(metadata: bytes, encrypted: bytes, *, include_separator_in_length: bool) -> bytes:
    """Historical older-build model with a separate nine-byte FORWARD separator."""
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
    """Model decimal(len(prefix)+len(data)) + prefix + NUL + data.

    For the current Delphi dedicated-TCP sender, prefix starts with NUL; that
    first NUL terminates the decimal header. The following separator is counted
    inside the advertised payload because the leading NUL is not payload.
    """
    advertised = len(prefix) + len(data)
    return str(advertised).encode("ascii") + prefix + b"\x00" + data


def current_reader_frame_end(frame: bytes) -> int:
    """Model ClientConnection.ReadHeaderAsync + read exactly advertised bytes."""
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

    def test_sender_length_with_initial_nul_prefix_consumes_complete_frame(self) -> None:
        prefix = b"\x00alice\x00FORWARD\x00bob\x00UniChat\x00"
        frame = build_documented_sender_frame(prefix, b"payload")
        end = current_reader_frame_end(frame)
        self.assertEqual(end, len(frame))
        self.assertEqual(frame[end:], b"")

    def test_adding_one_to_advertised_length_overreads_initial_nul_prefix_frame(self) -> None:
        prefix = b"\x00alice\x00FORWARD\x00bob\x00UniChat\x00"
        frame = build_documented_sender_frame(prefix, b"payload")
        end = current_reader_frame_end(frame)
        self.assertEqual(end + 1, len(frame) + 1)

    def test_current_server_layout_is_parseable_by_current_prefix_contract(self) -> None:
        current_payload = b"alice\x00FORWARD\x00bob\x00UniChat\x00payload"
        parsed = parse_current_server_prefix(current_payload)
        self.assertEqual(parsed, ("alice", b"FORWARD", "bob"))

    def test_historical_reconstructed_layout_is_not_current_server_prefix_layout(self) -> None:
        parsed = parse_current_server_prefix(self.metadata + FORWARD + self.ciphertext)
        self.assertIsNone(parsed)  # Historical model starts with an empty ClientId field.

    def test_corrected_length_formula_consumes_complete_historical_frame(self) -> None:
        frame = build_legacy_frame(
            self.metadata, self.ciphertext, include_separator_in_length=True
        )
        end = callback_frame_end(frame)
        self.assertEqual(end, len(frame))
        self.assertEqual(frame[end:], b"")

    def test_historical_length_formula_leaves_nine_byte_ciphertext_tail(self) -> None:
        frame = build_legacy_frame(
            self.metadata, self.ciphertext, include_separator_in_length=False
        )
        end = callback_frame_end(frame)
        self.assertEqual(len(frame) - end, len(FORWARD))
        self.assertEqual(frame[end:], self.ciphertext[-len(FORWARD):])


if __name__ == "__main__":
    unittest.main(verbosity=2)
