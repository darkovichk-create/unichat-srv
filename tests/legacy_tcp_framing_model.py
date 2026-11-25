"""Offline model of the statically reconstructed legacy UniChat TCP framing.

This is a forensic specification test, not a production protocol parser and not
proof of a captured wire frame. It models the sender's observed length formula
and the receive callback's observed decimal-prefix frame-size calculation.
"""
from __future__ import annotations

import unittest

FORWARD = b"\x00FORWARD\x00"


def build_legacy_sender_frame(metadata: bytes, encrypted: bytes) -> bytes:
    """Model sender 0x579724: decimal(len(metadata)+len(cipher)) NUL metadata FORWARD cipher."""
    advertised = len(metadata) + len(encrypted)
    return str(advertised).encode("ascii") + b"\x00" + metadata + FORWARD + encrypted


def callback_declared_frame_size(frame: bytes) -> int:
    """Model callback 0x58CF3C: decimal digits + NUL + advertised payload bytes."""
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

    def test_sender_under_advertises_by_exactly_nine_bytes(self) -> None:
        for cipher_size in (0, 1, 8, 9, 32, 4096):
            with self.subTest(cipher_size=cipher_size):
                frame = build_legacy_sender_frame(self.metadata, b"\xA5" * cipher_size)
                declared = callback_declared_frame_size(frame)
                self.assertEqual(len(frame) - declared, len(FORWARD))

    def test_remainder_composition_for_cipher_at_least_nine_bytes(self) -> None:
        cipher = bytes(range(32))
        frame = build_legacy_sender_frame(self.metadata, cipher)
        declared = callback_declared_frame_size(frame)
        self.assertEqual(frame[declared:], cipher[-len(FORWARD):])

    def test_remainder_contains_separator_tail_when_cipher_shorter_than_nine(self) -> None:
        cipher = b"\xA5" * 4
        frame = build_legacy_sender_frame(self.metadata, cipher)
        declared = callback_declared_frame_size(frame)
        expected = FORWARD[4:] + cipher
        self.assertEqual(frame[declared:], expected)

    def test_coalesced_frames_leave_first_cipher_tail_before_second_prefix(self) -> None:
        first_cipher = b"\xA1" * 32
        second = build_legacy_sender_frame(self.metadata, b"\xB2" * 24)
        first = build_legacy_sender_frame(self.metadata, first_cipher)
        stream = first + second
        declared = callback_declared_frame_size(stream)
        self.assertEqual(stream[declared:declared + 9], first_cipher[-9:])
        self.assertTrue(stream[declared + 9:].startswith(second[:8]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
