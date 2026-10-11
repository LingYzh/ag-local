"""Pure framing for the current observed headers.

This profile describes observed header structure only; it does not establish
business readiness or infer meanings for the index fields or frame bodies.
Bodies are opaque bytes. The caller chooses the direction and supplies each
observed marker or compression flag explicitly.
"""

from dataclasses import dataclass
from enum import Enum
import struct
from typing import Final, Optional, Union


CURRENT_OBSERVED_PROFILE: Final[str] = (
    "current-observed: observed header only; does not establish business readiness"
)
MAX_CLIENT_FRAME_BYTES: Final[int] = 1024 * 1024
MAX_SERVER_FRAME_BYTES: Final[int] = 65537
MAX_FEED_BYTES: Final[int] = 1024 * 1024
MAX_FRAMES_PER_FEED: Final[int] = 4096

_MIN_DECLARED_SIZE: Final[int] = 9
_CLIENT_PREFIX_SIZE: Final[int] = 4
_SERVER_PREFIX_SIZE: Final[int] = 2
_CLIENT_HEADER_SIZE: Final[int] = 13
_SERVER_HEADER_SIZE: Final[int] = 11


class FramingError(ValueError):
    """A malformed, unsupported, oversized, or incomplete frame."""


class FrameDirection(Enum):
    """Direction selects one of the two observed wire layouts."""

    CLIENT = "client-to-server"
    SERVER = "server-to-client"


@dataclass(frozen=True)
class ClientFrame:
    """Observed client-to-server frame structure; field semantics may be unknown."""

    command: int
    index: int
    server_index: int
    body: bytes
    marker: int


@dataclass(frozen=True)
class ServerFrame:
    """Observed server-to-client frame structure; body remains wire bytes."""

    command: int
    index: int
    server_index: int
    body: bytes
    compress: int


Frame = Union[ClientFrame, ServerFrame]


def _uint(value: object, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int:
        raise FramingError("%s must be an integer" % name)
    if value < minimum or value > maximum:
        raise FramingError("%s must be between %d and %d" % (name, minimum, maximum))
    return value


def _byte_view(value: object, name: str, max_bytes: Optional[int] = None) -> memoryview:
    try:
        source = memoryview(value)
    except (TypeError, ValueError) as exc:
        raise FramingError("%s must be bytes-like" % name) from exc

    try:
        if not source.c_contiguous:
            raise FramingError("%s must be contiguous" % name)
        size = source.nbytes
        if max_bytes is not None and size > max_bytes:
            raise FramingError("%s exceeds the %d-byte limit" % (name, max_bytes))
        view = source.cast("B")
    except (TypeError, ValueError) as exc:
        if isinstance(exc, FramingError):
            raise
        raise FramingError("%s must be a contiguous byte buffer" % name) from exc
    finally:
        source.release()
    return view


def _body_view(body: object, name: str, max_bytes: int) -> memoryview:
    view = _byte_view(body, name, max_bytes)
    return view


def _client_header_fields(view: Union[bytes, bytearray, memoryview]) -> tuple:
    marker = view[4]
    if marker not in (7, 8):
        raise FramingError("unsupported client marker %d" % marker)
    command = struct.unpack_from("<I", view, 5)[0]
    if command == 0:
        raise FramingError("client command must be between 1 and 4294967295")
    index = struct.unpack_from("<H", view, 9)[0]
    server_index = struct.unpack_from("<H", view, 11)[0]
    return marker, command, index, server_index


def _server_header_fields(view: Union[bytes, bytearray, memoryview]) -> tuple:
    compression = view[2]
    reserved = view[3]
    command_high = view[4]
    if compression not in (0, 1):
        raise FramingError("unsupported server compression flag %d" % compression)
    if reserved != 0:
        raise FramingError("server reserved byte must be zero")
    if command_high not in (0, 1):
        raise FramingError("unsupported server command-high byte %d" % command_high)
    command_low = struct.unpack_from(">H", view, 5)[0]
    command = command_low + (65536 * command_high)
    if command == 0:
        raise FramingError("server command must be between 1 and 131071")
    index = struct.unpack_from(">H", view, 7)[0]
    server_index = struct.unpack_from(">H", view, 9)[0]
    return compression, command, index, server_index


def _client_declared_size(view: Union[bytes, bytearray, memoryview]) -> int:
    if len(view) < _CLIENT_PREFIX_SIZE:
        raise FramingError("client frame has a truncated length prefix")
    declared = struct.unpack_from("<I", view, 0)[0]
    if declared < _MIN_DECLARED_SIZE:
        raise FramingError("client declared size is below 9 bytes")
    return declared


def _server_declared_size(view: Union[bytes, bytearray, memoryview]) -> int:
    if len(view) < _SERVER_PREFIX_SIZE:
        raise FramingError("server frame has a truncated length prefix")
    declared = struct.unpack_from(">H", view, 0)[0]
    if declared < _MIN_DECLARED_SIZE:
        raise FramingError("server declared size is below 9 bytes")
    return declared


def encode_client_frame(frame: ClientFrame) -> bytes:
    if not isinstance(frame, ClientFrame):
        raise FramingError("frame must be a ClientFrame")
    command = _uint(frame.command, "command", 1, 0xFFFFFFFF)
    index = _uint(frame.index, "index", 0, 0xFFFF)
    server_index = _uint(frame.server_index, "server_index", 0, 0xFFFF)
    marker = _uint(frame.marker, "marker", 7, 8)
    if marker not in (7, 8):
        raise FramingError("marker must be 7 or 8")

    body = _body_view(frame.body, "body", MAX_CLIENT_FRAME_BYTES - _CLIENT_HEADER_SIZE)
    try:
        declared = _MIN_DECLARED_SIZE + body.nbytes
        return (
            struct.pack("<IBIHH", declared, marker, command, index, server_index)
            + body.tobytes()
        )
    finally:
        body.release()


def encode_server_frame(frame: ServerFrame) -> bytes:
    if not isinstance(frame, ServerFrame):
        raise FramingError("frame must be a ServerFrame")
    command = _uint(frame.command, "command", 1, 131071)
    index = _uint(frame.index, "index", 0, 0xFFFF)
    server_index = _uint(frame.server_index, "server_index", 0, 0xFFFF)
    compression = _uint(frame.compress, "compress", 0, 1)

    body = _body_view(frame.body, "body", MAX_SERVER_FRAME_BYTES - _SERVER_HEADER_SIZE)
    try:
        declared = _MIN_DECLARED_SIZE + body.nbytes
        command_high = command >> 16
        command_low = command & 0xFFFF
        return (
            struct.pack(
                ">HBBBHHH",
                declared,
                compression,
                0,
                command_high,
                command_low,
                index,
                server_index,
            )
            + body.tobytes()
        )
    finally:
        body.release()


def decode_client_frame(packet: object) -> ClientFrame:
    view = _byte_view(packet, "packet", MAX_CLIENT_FRAME_BYTES)
    try:
        declared = _client_declared_size(view)
        total = _CLIENT_PREFIX_SIZE + declared
        if total > MAX_CLIENT_FRAME_BYTES:
            raise FramingError("client frame exceeds the %d-byte limit" % MAX_CLIENT_FRAME_BYTES)
        if len(view) < total:
            raise FramingError("client frame is truncated")
        if len(view) > total:
            raise FramingError("client packet contains trailing bytes")
        marker, command, index, server_index = _client_header_fields(view)
        return ClientFrame(command, index, server_index, view[_CLIENT_HEADER_SIZE:].tobytes(), marker)
    finally:
        view.release()


def decode_server_frame(packet: object) -> ServerFrame:
    view = _byte_view(packet, "packet", MAX_SERVER_FRAME_BYTES)
    try:
        declared = _server_declared_size(view)
        total = _SERVER_PREFIX_SIZE + declared
        if total > MAX_SERVER_FRAME_BYTES:
            raise FramingError("server frame exceeds the %d-byte limit" % MAX_SERVER_FRAME_BYTES)
        if len(view) < total:
            raise FramingError("server frame is truncated")
        if len(view) > total:
            raise FramingError("server packet contains trailing bytes")
        compression, command, index, server_index = _server_header_fields(view)
        return ServerFrame(
            command,
            index,
            server_index,
            view[_SERVER_HEADER_SIZE:].tobytes(),
            compression,
        )
    finally:
        view.release()


class IncrementalFrameDecoder:
    """Incremental parser with bounded retained bytes and a sticky failure state.

    Choose ``FrameDirection.CLIENT`` or ``FrameDirection.SERVER`` explicitly.
    ``finish`` is a clean no-op at an empty frame boundary, and rejects any
    retained prefix, header, or body bytes as truncated EOF. Each feed accepts
    at most ``MAX_FEED_BYTES`` and returns at most ``MAX_FRAMES_PER_FEED``.
    """

    def __init__(self, direction: FrameDirection, max_frame_bytes: Optional[int] = None):
        if not isinstance(direction, FrameDirection):
            raise FramingError("direction must be selected explicitly")
        hard_limit = (
            MAX_CLIENT_FRAME_BYTES
            if direction is FrameDirection.CLIENT
            else MAX_SERVER_FRAME_BYTES
        )
        minimum_limit = (
            _CLIENT_HEADER_SIZE
            if direction is FrameDirection.CLIENT
            else _SERVER_HEADER_SIZE
        )
        if max_frame_bytes is None:
            limit = hard_limit
        else:
            limit = _uint(max_frame_bytes, "max_frame_bytes", minimum_limit, hard_limit)

        self.direction = direction
        self.profile = CURRENT_OBSERVED_PROFILE
        self.max_frame_bytes = limit
        self._prefix_size = (
            _CLIENT_PREFIX_SIZE if direction is FrameDirection.CLIENT else _SERVER_PREFIX_SIZE
        )
        self._header_size = (
            _CLIENT_HEADER_SIZE if direction is FrameDirection.CLIENT else _SERVER_HEADER_SIZE
        )
        self._buffer = bytearray()
        self._expected_total: Optional[int] = None
        self._header_validated = False
        self._failed_reason: Optional[str] = None
        self._finished = False

    @property
    def buffered_bytes(self) -> int:
        """Number of bytes retained for the current incomplete frame."""

        return len(self._buffer)

    @property
    def failed(self) -> bool:
        return self._failed_reason is not None

    @property
    def finished(self) -> bool:
        return self._finished

    def _fail(self, error: FramingError) -> None:
        self._failed_reason = str(error)
        self._buffer.clear()
        self._expected_total = None
        self._header_validated = False

    def _ensure_healthy(self) -> None:
        if self.failed:
            raise FramingError("decoder is failed: %s" % self._failed_reason)

    def _declared_size(self) -> int:
        if self.direction is FrameDirection.CLIENT:
            return _client_declared_size(self._buffer)
        return _server_declared_size(self._buffer)

    def _validate_header(self) -> None:
        if self.direction is FrameDirection.CLIENT:
            _client_header_fields(self._buffer)
        else:
            _server_header_fields(self._buffer)

    def _decode_complete(self) -> Frame:
        if self.direction is FrameDirection.CLIENT:
            return decode_client_frame(self._buffer)
        return decode_server_frame(self._buffer)

    def feed(self, data: object) -> list:
        """Consume a bytes-like chunk and return all complete frames in it."""

        self._ensure_healthy()
        if self._finished:
            raise FramingError("decoder is finished")
        try:
            view = _byte_view(data, "data", MAX_FEED_BYTES)
        except FramingError as exc:
            self._fail(exc)
            raise

        frames = []
        offset = 0
        try:
            while offset < view.nbytes:
                if self._expected_total is None:
                    target = self._prefix_size
                    take = min(target - len(self._buffer), view.nbytes - offset)
                    self._buffer.extend(view[offset : offset + take])
                    offset += take
                    if len(self._buffer) < target:
                        continue

                    declared = self._declared_size()
                    total = self._prefix_size + declared
                    if total > self.max_frame_bytes:
                        raise FramingError(
                            "%s frame exceeds the %d-byte configured limit"
                            % (self.direction.value, self.max_frame_bytes)
                        )
                    self._expected_total = total

                if not self._header_validated:
                    take = min(
                        self._header_size - len(self._buffer),
                        view.nbytes - offset,
                    )
                    if take:
                        self._buffer.extend(view[offset : offset + take])
                        offset += take
                    if len(self._buffer) < self._header_size:
                        continue
                    self._validate_header()
                    self._header_validated = True

                take = min(self._expected_total - len(self._buffer), view.nbytes - offset)
                if take:
                    self._buffer.extend(view[offset : offset + take])
                    offset += take
                if len(self._buffer) == self._expected_total:
                    if len(frames) >= MAX_FRAMES_PER_FEED:
                        raise FramingError(
                            "feed exceeds the %d-frame output limit" % MAX_FRAMES_PER_FEED
                        )
                    frames.append(self._decode_complete())
                    self._buffer.clear()
                    self._expected_total = None
                    self._header_validated = False
        except FramingError as exc:
            self._fail(exc)
            raise
        finally:
            view.release()

        if len(self._buffer) > self.max_frame_bytes:
            error = FramingError("decoder retained more than its configured frame limit")
            self._fail(error)
            raise error
        return frames

    def finish(self) -> None:
        """Mark EOF; an empty boundary succeeds, while any partial frame fails."""

        self._ensure_healthy()
        if self._finished:
            return
        if self._buffer:
            error = FramingError(
                "EOF with incomplete %s frame (%d of %s bytes buffered)"
                % (
                    self.direction.value,
                    len(self._buffer),
                    self._expected_total if self._expected_total is not None else "length-prefix",
                )
            )
            self._fail(error)
            raise error
        self._finished = True


__all__ = [
    "CURRENT_OBSERVED_PROFILE",
    "MAX_CLIENT_FRAME_BYTES",
    "MAX_FEED_BYTES",
    "MAX_FRAMES_PER_FEED",
    "MAX_SERVER_FRAME_BYTES",
    "ClientFrame",
    "FrameDirection",
    "Frame",
    "FramingError",
    "IncrementalFrameDecoder",
    "ServerFrame",
    "decode_client_frame",
    "decode_server_frame",
    "encode_client_frame",
    "encode_server_frame",
]
