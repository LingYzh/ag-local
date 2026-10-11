import struct
import unittest

from v5_server.network.framing import (
    MAX_CLIENT_FRAME_BYTES,
    MAX_FEED_BYTES,
    MAX_FRAMES_PER_FEED,
    MAX_SERVER_FRAME_BYTES,
    ClientFrame,
    FrameDirection,
    FramingError,
    IncrementalFrameDecoder,
    ServerFrame,
    decode_client_frame,
    decode_server_frame,
    encode_client_frame,
    encode_server_frame,
)


def client_fixture(command, index, server_index, body, marker=7):
    return (
        struct.pack("<IBIHH", 9 + len(body), marker, command, index, server_index)
        + body
    )


def server_fixture(command, index, server_index, body, compress=0):
    return (
        struct.pack(
            ">HBBBHHH",
            9 + len(body),
            compress,
            0,
            command >> 16,
            command & 0xFFFF,
            index,
            server_index,
        )
        + body
    )


class FramingTests(unittest.TestCase):
    def test_client_layout_fixture_and_roundtrip(self):
        body = b"\x00body\xff"
        expected = client_fixture(0x89ABCDEF, 0x1234, 0xFEDC, body, marker=8)
        frame = ClientFrame(0x89ABCDEF, 0x1234, 0xFEDC, body, marker=8)
        self.assertEqual(encode_client_frame(frame), expected)
        self.assertEqual(
            decode_client_frame(expected),
            ClientFrame(0x89ABCDEF, 0x1234, 0xFEDC, body, marker=8),
        )

    def test_server_layout_fixture_and_roundtrip(self):
        body = b"\x78\x9copaque\x00"
        expected = server_fixture(0x12345, 0x2345, 0xABCD, body, compress=1)
        frame = ServerFrame(0x12345, 0x2345, 0xABCD, body, compress=1)
        self.assertEqual(encode_server_frame(frame), expected)
        self.assertEqual(
            decode_server_frame(expected),
            ServerFrame(0x12345, 0x2345, 0xABCD, body, compress=1),
        )

    def test_empty_bodies_and_wire_compression_bytes_are_preserved(self):
        client = ClientFrame(10042, 0, 65535, b"", marker=7)
        server = ServerFrame(65536, 65535, 0, b"", compress=0)
        self.assertEqual(decode_client_frame(encode_client_frame(client)), client)
        self.assertEqual(decode_server_frame(encode_server_frame(server)), server)
        payload = b"\x78\x9cnot-decoded"
        wire_frame = server_fixture(68151, 1, 2, payload, compress=0)
        self.assertEqual(decode_server_frame(wire_frame).body, payload)

    def test_incremental_client_fragmentation_and_coalescing(self):
        packets = [
            client_fixture(10042, 1, 2, b"first", 7),
            client_fixture(10200, 3, 4, b"second", 8),
        ]
        decoder = IncrementalFrameDecoder(FrameDirection.CLIENT)
        got = []
        for byte in packets[0]:
            got.extend(decoder.feed(bytes((byte,))))
        got.extend(decoder.feed(packets[1] + packets[0]))
        self.assertEqual(
            got,
            [
                decode_client_frame(packets[0]),
                decode_client_frame(packets[1]),
                decode_client_frame(packets[0]),
            ],
        )
        self.assertEqual(decoder.buffered_bytes, 0)
        decoder.finish()

    def test_incremental_server_fragmentation_and_coalescing(self):
        packets = [
            server_fixture(10039, 1, 2, b"one", 0),
            server_fixture(83016, 3, 4, b"two", 1),
        ]
        decoder = IncrementalFrameDecoder(FrameDirection.SERVER)
        got = []
        split = 5
        got.extend(decoder.feed(packets[0][:split]))
        got.extend(decoder.feed(packets[0][split:] + packets[1]))
        self.assertEqual(got, [decode_server_frame(packet) for packet in packets])
        self.assertEqual(decoder.buffered_bytes, 0)

    def test_whole_frame_size_boundaries_are_inclusive(self):
        client_body = b"x" * (MAX_CLIENT_FRAME_BYTES - 13)
        client = ClientFrame(1, 0, 0, client_body, marker=7)
        client_packet = encode_client_frame(client)
        self.assertEqual(len(client_packet), MAX_CLIENT_FRAME_BYTES)
        self.assertEqual(len(decode_client_frame(client_packet).body), len(client_body))
        with self.assertRaises(FramingError):
            encode_client_frame(ClientFrame(1, 0, 0, client_body + b"x", marker=7))

        server_body = b"y" * (MAX_SERVER_FRAME_BYTES - 11)
        server = ServerFrame(131071, 0xFFFF, 0, server_body, compress=1)
        server_packet = encode_server_frame(server)
        self.assertEqual(len(server_packet), MAX_SERVER_FRAME_BYTES)
        self.assertEqual(len(decode_server_frame(server_packet).body), len(server_body))
        with self.assertRaises(FramingError):
            encode_server_frame(ServerFrame(1, 0, 0, server_body + b"y", compress=0))

    def test_incremental_limit_can_only_be_reduced(self):
        with self.assertRaises(FramingError):
            IncrementalFrameDecoder(FrameDirection.CLIENT, MAX_CLIENT_FRAME_BYTES + 1)
        with self.assertRaises(FramingError):
            IncrementalFrameDecoder(FrameDirection.SERVER, True)
        with self.assertRaises(FramingError):
            IncrementalFrameDecoder(FrameDirection.CLIENT, 12)
        with self.assertRaises(FramingError):
            IncrementalFrameDecoder(FrameDirection.SERVER, 10)
        decoder = IncrementalFrameDecoder(FrameDirection.CLIENT, 13)
        packet = client_fixture(1, 0, 0, b"x")
        with self.assertRaises(FramingError):
            decoder.feed(packet[:4])
        self.assertTrue(decoder.failed)

    def test_feed_byte_limit_is_checked_before_buffering(self):
        decoder = IncrementalFrameDecoder(FrameDirection.CLIENT)
        decoder.feed(b"\x01\x00")
        oversized_chunk = bytearray(MAX_FEED_BYTES + 1)
        with self.assertRaises(FramingError):
            decoder.feed(oversized_chunk)
        self.assertTrue(decoder.failed)
        self.assertEqual(decoder.buffered_bytes, 0)

    def test_feed_frame_count_limit_and_caller_chunking(self):
        packet = client_fixture(1, 0, 0, b"")
        decoder = IncrementalFrameDecoder(FrameDirection.CLIENT)
        with self.assertRaises(FramingError):
            decoder.feed(packet * (MAX_FRAMES_PER_FEED + 1))
        self.assertTrue(decoder.failed)
        self.assertEqual(decoder.buffered_bytes, 0)

        decoder = IncrementalFrameDecoder(FrameDirection.CLIENT)
        frames = decoder.feed(packet * MAX_FRAMES_PER_FEED)
        self.assertEqual(len(frames), MAX_FRAMES_PER_FEED)
        self.assertEqual(decoder.feed(packet), [decode_client_frame(packet)])

    def test_rejects_invalid_header_flags(self):
        client_bad_marker = bytearray(client_fixture(1, 0, 0, b""))
        client_bad_marker[4] = 9
        with self.assertRaises(FramingError):
            decode_client_frame(client_bad_marker)

        invalid_server_headers = []
        for offset, value in ((2, 2), (3, 1), (4, 2)):
            packet = bytearray(server_fixture(1, 0, 0, b""))
            packet[offset] = value
            invalid_server_headers.append(packet)
        for packet in invalid_server_headers:
            with self.subTest(header=bytes(packet)):
                with self.assertRaises(FramingError):
                    decode_server_frame(packet)

    def test_rejects_invalid_numeric_fields_and_bools(self):
        for value in (0, -1, True, 0x100000000):
            with self.subTest(client_command=value):
                with self.assertRaises(FramingError):
                    encode_client_frame(ClientFrame(value, 0, 0, b"", marker=7))
        for value in (-1, True, 0x10000):
            with self.subTest(index=value):
                with self.assertRaises(FramingError):
                    encode_client_frame(ClientFrame(1, value, 0, b"", marker=7))
        for value in (0, -1, True, 131072):
            with self.subTest(server_command=value):
                with self.assertRaises(FramingError):
                    encode_server_frame(ServerFrame(value, 0, 0, b"", compress=0))
        for value in (True, 2, -1):
            with self.subTest(compress=value):
                with self.assertRaises(FramingError):
                    encode_server_frame(ServerFrame(1, 0, 0, b"", compress=value))

    def test_rejects_short_sizes_and_extra_packet_bytes(self):
        with self.assertRaises(FramingError):
            decode_client_frame(struct.pack("<I", 8))
        with self.assertRaises(FramingError):
            decode_server_frame(struct.pack(">H", 8))
        with self.assertRaises(FramingError):
            decode_client_frame(client_fixture(1, 0, 0, b"") + b"extra")

    def test_eof_with_declared_truncated_frame_fails_stickily(self):
        packet = server_fixture(10039, 1, 2, b"body", 0)
        decoder = IncrementalFrameDecoder(FrameDirection.SERVER)
        self.assertEqual(decoder.feed(packet[:-1]), [])
        with self.assertRaises(FramingError):
            decoder.finish()
        self.assertTrue(decoder.failed)
        with self.assertRaises(FramingError):
            decoder.feed(packet[-1:])

    def test_eof_with_partial_prefix_fails_and_empty_boundary_succeeds(self):
        decoder = IncrementalFrameDecoder(FrameDirection.CLIENT)
        decoder.finish()
        self.assertTrue(decoder.finished)
        decoder.finish()
        with self.assertRaises(FramingError):
            decoder.feed(b"")
        self.assertFalse(decoder.failed)

        decoder = IncrementalFrameDecoder(FrameDirection.CLIENT)
        decoder.feed(b"\x01\x00")
        with self.assertRaises(FramingError):
            decoder.finish()
        with self.assertRaises(FramingError):
            decoder.finish()

    def test_bad_header_fails_immediately_and_decoder_stays_failed(self):
        packet = bytearray(server_fixture(1, 0, 0, b"unneeded-body", 0))
        packet[3] = 1
        decoder = IncrementalFrameDecoder(FrameDirection.SERVER)
        with self.assertRaises(FramingError):
            decoder.feed(packet[:11])
        self.assertTrue(decoder.failed)
        with self.assertRaises(FramingError):
            decoder.finish()


if __name__ == "__main__":
    unittest.main()
