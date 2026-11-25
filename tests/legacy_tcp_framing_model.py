"""Historical offline model for the older uploaded UniChat EXE only.

Binary: older uploaded unichat(1).exe, SHA-256
bc22efd0c092c85f3e086a768f23ad62fe0dc085e5a62ab2227618ac94243d5f.

The sender/callback addresses and nine-byte-tail model below do NOT describe
the current GitHub EXE (SHA-256 ca7dfa6520e67e6c5a77287f8160d02b4117b0e69c2a6702dfcbe2986f70766d).
See current_delphi_dedicated_tcp_spec.py for the current dedicated-TCP format.
This is a forensic model, not a production parser or packet capture.
"""
from __future__ import annotations

import unittest

FORWARD = b"\x00FORWARD\x00"


def build_legacy_sender_frame(metadata: bytes, encrypted: bytes) -> bytes:
    """Historical older-build model of sender VA 0x579724."""
    advertised = len(metadata) + len(encrypted)
    return str(advertised).encode("ascii") + b"\x00" + metadata + FORWARD + encrypted


def callback_declared_frame_size(frame: bytes) -> int:
    """Historical older-build model of callback VA 0x58CF3C."""
    nul = frame.find(b"\x00")
    if nul <= 0:
        raise ValueError("missing decimal header terminator")
    advertised = int(frame[:nul].decode("ascii"))
    return nul + 1 + advertised


class LegacyTcpFramingModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.metadata = (
            FORWARD + b"alice" + b"*" + b"\x00UniChat\x00" + bytes.fromhex("7856341230")
        )

    def test_historical_sender_model_under_advertises_by_nine_bytes(self) -> None:
        for cipher_size in (0, 1, 8, 9, 32, 4096):
            with self.subTest(cipher_size=cipher_size):
                frame = build_legacy_sender_frame(self.metadata, b"\xA5" * cipher_size)
                declared = callback_declared_frame_size(frame)
                self.assertEqual(len(frame) - declared, len(FORWARD))

    def test_historical_remainder_composition_for_cipher_at_least_nine_bytes(self) -> None:
        cipher = bytes(range(32))
        frame = build_legacy_sender_frame(self.metadata, cipher)
        declared = callback_declared_frame_size(frame)
        self.assertEqual(frame[declared:], cipher[-len(FORWARD):])

    def test_historical_remainder_contains_separator_tail_for_short_cipher(self) -> None:
        cipher = b"\xA5" * 4
        frame = build_legacy_sender_frame(self.metadata, cipher)
        declared = callback_declared_frame_size(frame)
        expected = FORWARD[4:] + cipher
        self.assertEqual(frame[declared:], expected)

    def test_historical_coalesced_frames_leave_cipher_tail_before_next_prefix(self) -> None:
        first_cipher = b"\xA1" * 32
        second = build_legacy_sender_frame(self.metadata, b"\xB2" * 24)
        first = build_legacy_sender_frame(self.metadata, first_cipher)
        stream = first + second
        declared = callback_declared_frame_size(stream)
        self.assertEqual(stream[declared:declared + 9], first_cipher[-9:])
        self.assertTrue(stream[declared + 9:].startswith(second[:8]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
