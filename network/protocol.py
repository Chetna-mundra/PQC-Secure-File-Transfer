import struct


HEADER_SIZE = 4

# Maximum single message allowed by the protocol.
# Individual callers can use a smaller limit.
MAX_MESSAGE_SIZE = 100 * 1024 * 1024  # 100 MiB


def send_message(sock, data: bytes, max_size: int = MAX_MESSAGE_SIZE):
    """
    Send one complete length-prefixed message over TCP.

    Format:
        [4-byte big-endian message length][message bytes]
    """

    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")

    if not isinstance(max_size, int) or max_size < 0:
        raise ValueError("max_size must be a non-negative integer")

    if len(data) > max_size:
        raise ValueError(
            f"Message exceeds maximum allowed size of {max_size} bytes"
        )

    header = struct.pack("!I", len(data))

    sock.sendall(header + data)


def recv_exact(sock, size: int) -> bytes:
    """
    Receive exactly `size` bytes from the socket.
    """

    if size < 0:
        raise ValueError("size must be non-negative")

    data = bytearray()

    while len(data) < size:

        chunk = sock.recv(
            size - len(data)
        )

        if not chunk:
            raise ConnectionError(
                "Connection closed unexpectedly"
            )

        data.extend(chunk)

    return bytes(data)


def recv_message(
    sock,
    max_size: int = MAX_MESSAGE_SIZE
) -> bytes:
    """
    Receive one complete length-prefixed message.

    The message length is checked BEFORE the body is
    allocated/read, preventing malicious length headers
    from causing excessive memory allocation.
    """

    if not isinstance(max_size, int) or max_size < 0:
        raise ValueError("max_size must be a non-negative integer")

    header = recv_exact(
        sock,
        HEADER_SIZE
    )

    length = struct.unpack(
        "!I",
        header
    )[0]

    if length > max_size:
        raise ValueError(
            f"Message exceeds maximum allowed size of {max_size} bytes"
        )

    return recv_exact(
        sock,
        length
    )