import hashlib
import hmac
import json
import os
import socket
import sys
from pathlib import Path


# ---------------------------------------------------------
# Project root
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------
# Project imports
# ---------------------------------------------------------

from mlkem import MLKEM

from network.protocol import (
    send_message,
    recv_message
)


# ---------------------------------------------------------
# Cryptography imports
# ---------------------------------------------------------

from cryptography.exceptions import InvalidTag

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

HOST = "127.0.0.1"
PORT = 5000

PARAMETER_SET = "ML-KEM-768"

AES_KEY_SIZE = 32
NONCE_SIZE = 12

GCM_TAG_SIZE = 16
FILE_HASH_SIZE = 32

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MiB
MAX_METADATA_SIZE = 4 * 1024       # 4 KiB
MAX_RESPONSE_SIZE = 64 * 1024      # 64 KiB

SOCKET_TIMEOUT = 30

RECEIVED_DIR = (
    PROJECT_ROOT / "received_files"
)

RESPONSE_AAD = (
    b"PQC-Secure-File-Transfer-Server-Response"
)


# ---------------------------------------------------------
# Helper functions
# ---------------------------------------------------------

def derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Convert the ML-KEM shared secret into
    a 256-bit AES key using HKDF-SHA256.
    """

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=b"PQC-Secure-File-Transfer",
    )

    return hkdf.derive(shared_secret)


def send_secure_json(
    sock,
    aes_key: bytes,
    data: dict
):
    """
    Encrypt and authenticate a JSON response
    using AES-GCM.
    """

    nonce = os.urandom(
        NONCE_SIZE
    )

    plaintext = json.dumps(
        data,
        separators=(",", ":")
    ).encode("utf-8")

    encrypted_data = AESGCM(
        aes_key
    ).encrypt(
        nonce,
        plaintext,
        RESPONSE_AAD
    )

    envelope = json.dumps(
        {
            "nonce": nonce.hex(),
            "ciphertext": encrypted_data.hex()
        },
        separators=(",", ":")
    ).encode("utf-8")

    send_message(
        sock,
        envelope,
        max_size=MAX_RESPONSE_SIZE
    )


def sanitize_filename(
    filename: str
) -> str:
    """
    Validate a client-supplied filename.

    Prevents path traversal and unsafe Windows
    filenames.
    """

    if not isinstance(
        filename,
        str
    ):

        raise ValueError(
            "Filename must be a string"
        )

    if not filename:

        raise ValueError(
            "Filename cannot be empty"
        )

    if filename in {
        ".",
        ".."
    }:

        raise ValueError(
            "Invalid filename"
        )

    if len(filename) > 255:

        raise ValueError(
            "Filename is too long"
        )

    # Control characters
    if any(
        ord(char) < 32
        for char in filename
    ):

        raise ValueError(
            "Filename contains control characters"
        )

    # Path separators and Windows alternate streams
    if any(
        char in filename
        for char in (
            "/",
            "\\",
            ":"
        )
    ):

        raise ValueError(
            "Filename contains an invalid character"
        )

    if filename.endswith(
        (
            " ",
            "."
        )
    ):

        raise ValueError(
            "Filename cannot end with a space or period"
        )

    # Windows reserved device names
    stem = filename.split(
        ".",
        1
    )[0].upper()

    reserved_names = {
        "CON",
        "PRN",
        "AUX",
        "NUL"
    }

    reserved_names.update(
        f"COM{i}"
        for i in range(1, 10)
    )

    reserved_names.update(
        f"LPT{i}"
        for i in range(1, 10)
    )

    if stem in reserved_names:

        raise ValueError(
            "Filename uses a reserved device name"
        )

    return filename


def send_error_response(
    connection,
    aes_key,
    message
):
    """
    Send an authenticated error response when
    the shared AES key is already available.
    """

    if aes_key is None:
        return

    try:

        send_secure_json(
            connection,
            aes_key,
            {
                "status": "ERROR",
                "message": message
            }
        )

    except Exception:
        pass


# ---------------------------------------------------------
# Server
# ---------------------------------------------------------

def start_server(
    host: str = HOST,
    port: int = PORT,
    once: bool = True
):

    RECEIVED_DIR.mkdir(
        exist_ok=True
    )

    print("=" * 60)
    print(
        "       PQC SECURE FILE TRANSFER SERVER"
    )
    print("=" * 60)

    print()
    print(
        f"[+] ML-KEM parameter set: "
        f"{PARAMETER_SET}"
    )

    print(
        f"[+] Listening on "
        f"{host}:{port}"
    )

    print()

    # -----------------------------------------------------
    # Create ML-KEM object
    # -----------------------------------------------------

    kem = MLKEM(
        PARAMETER_SET
    )

    # -----------------------------------------------------
    # Create TCP server
    # -----------------------------------------------------

    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    # Windows-specific safer behavior.
    if hasattr(
        socket,
        "SO_EXCLUSIVEADDRUSE"
    ):

        server_socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_EXCLUSIVEADDRUSE,
            1
        )

    else:

        server_socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

    server_socket.bind(
        (
            host,
            port
        )
    )

    server_socket.listen(1)

    try:

        while True:

            print(
                "[+] Waiting for client..."
            )

            connection, address = (
                server_socket.accept()
            )

            connection.settimeout(
                SOCKET_TIMEOUT
            )

            print(
                f"[+] Client connected: "
                f"{address}"
            )

            print()

            aes_key = None

            result = {
                "status": "ERROR",
                "message": "Transfer failed"
            }

            try:

                # =============================================
                # 1. RECEIVE ML-KEM PUBLIC KEY
                # =============================================

                print(
                    "[1/6] Receiving ML-KEM public key..."
                )

                public_key = recv_message(
                    connection,
                    max_size=kem.ek_size
                )

                if len(public_key) != kem.ek_size:

                    raise ValueError(
                        "Invalid ML-KEM public key size"
                    )

                print(
                    f"      Received "
                    f"{len(public_key)} bytes"
                )

                # =============================================
                # 2. ML-KEM ENCAPSULATION
                # =============================================

                print(
                    "[2/6] Performing ML-KEM encapsulation..."
                )

                (
                    shared_secret_server,
                    ciphertext
                ) = kem.encaps(
                    public_key
                )

                if len(ciphertext) != kem.ct_size:

                    raise ValueError(
                        "Generated ML-KEM ciphertext "
                        "has invalid size"
                    )

                print(
                    f"      ML-KEM ciphertext: "
                    f"{len(ciphertext)} bytes"
                )

                print(
                    f"      Shared secret: "
                    f"{len(shared_secret_server)} bytes"
                )

                send_message(
                    connection,
                    ciphertext,
                    max_size=kem.ct_size
                )

                print(
                    "      Ciphertext sent to client."
                )

                # =============================================
                # 3. DERIVE AES KEY
                # =============================================

                print(
                    "[3/6] Deriving AES-256 key with HKDF..."
                )

                aes_key = derive_aes_key(
                    shared_secret_server
                )

                print(
                    "      AES key derived."
                )

                # =============================================
                # 4. RECEIVE METADATA
                # =============================================

                print(
                    "[4/6] Receiving file metadata..."
                )

                metadata_bytes = recv_message(
                    connection,
                    max_size=MAX_METADATA_SIZE
                )

                try:

                    metadata = json.loads(
                        metadata_bytes.decode(
                            "utf-8"
                        )
                    )

                except (
                    UnicodeDecodeError,
                    json.JSONDecodeError
                ) as error:

                    raise ValueError(
                        "Invalid metadata format"
                    ) from error

                if not isinstance(
                    metadata,
                    dict
                ):

                    raise ValueError(
                        "Metadata must be a JSON object"
                    )

                required_keys = {
                    "filename",
                    "size",
                    "nonce"
                }

                if set(metadata.keys()) != required_keys:

                    raise ValueError(
                        "Metadata contains invalid fields"
                    )

                filename = sanitize_filename(
                    metadata["filename"]
                )

                expected_size = metadata["size"]

                if (
                    isinstance(
                        expected_size,
                        bool
                    )
                    or not isinstance(
                        expected_size,
                        int
                    )
                ):

                    raise ValueError(
                        "Invalid encrypted file size"
                    )

                minimum_encrypted_size = (
                    FILE_HASH_SIZE
                    + GCM_TAG_SIZE
                )

                maximum_encrypted_size = (
                    FILE_HASH_SIZE
                    + MAX_FILE_SIZE
                    + GCM_TAG_SIZE
                )

                if expected_size < minimum_encrypted_size:

                    raise ValueError(
                        "Encrypted file size is too small"
                    )

                if expected_size > maximum_encrypted_size:

                    raise ValueError(
                        "Encrypted file exceeds "
                        "maximum allowed size"
                    )

                nonce_hex = metadata["nonce"]

                if (
                    not isinstance(
                        nonce_hex,
                        str
                    )
                    or len(nonce_hex)
                    != NONCE_SIZE * 2
                ):

                    raise ValueError(
                        "Invalid nonce encoding"
                    )

                try:

                    nonce = bytes.fromhex(
                        nonce_hex
                    )

                except ValueError as error:

                    raise ValueError(
                        "Invalid nonce encoding"
                    ) from error

                if len(nonce) != NONCE_SIZE:

                    raise ValueError(
                        "Invalid nonce size"
                    )

                print(
                    f"      Filename: "
                    f"{filename}"
                )

                print(
                    f"      Encrypted size: "
                    f"{expected_size} bytes"
                )

                # =============================================
                # 5. RECEIVE + DECRYPT FILE
                # =============================================

                print(
                    "[5/6] Receiving encrypted file..."
                )

                encrypted_data = recv_message(
                    connection,
                    max_size=maximum_encrypted_size
                )

                if (
                    len(encrypted_data)
                    != expected_size
                ):

                    raise ValueError(
                        "Received file size "
                        "does not match metadata"
                    )

                print(
                    f"      Received: "
                    f"{len(encrypted_data)} bytes"
                )

                print(
                    "      Decrypting using AES-256-GCM..."
                )

                try:

                    decrypted_payload = AESGCM(
                        aes_key
                    ).decrypt(
                        nonce,
                        encrypted_data,
                        metadata_bytes
                    )

                except InvalidTag as error:

                    raise ValueError(
                        "Decryption/authentication failed"
                    ) from error

                print(
                    "      AES-GCM authentication successful."
                )

                # =============================================
                # 6. VERIFY SHA-256
                # =============================================

                print(
                    "[6/6] Verifying SHA-256..."
                )

                if (
                    len(decrypted_payload)
                    < FILE_HASH_SIZE
                ):

                    raise ValueError(
                        "Decrypted payload is invalid"
                    )

                expected_digest = (
                    decrypted_payload[
                        :FILE_HASH_SIZE
                    ]
                )

                decrypted_data = (
                    decrypted_payload[
                        FILE_HASH_SIZE:
                    ]
                )

                if len(decrypted_data) > MAX_FILE_SIZE:

                    raise ValueError(
                        "Decrypted file exceeds "
                        "maximum allowed size"
                    )

                actual_digest = hashlib.sha256(
                    decrypted_data
                ).digest()

                if not hmac.compare_digest(
                    actual_digest,
                    expected_digest
                ):

                    raise ValueError(
                        "SHA-256 verification failed"
                    )

                actual_hash = (
                    actual_digest.hex()
                )

                output_path = (
                    RECEIVED_DIR
                    / filename
                )

                # Do not silently overwrite existing files.
                # If the filename already exists, use a numbered alternative.
                original_path = output_path

                for counter in range(101):
                    if counter == 0:
                        candidate_path = original_path
                    else:
                        candidate_path = (
                            original_path.parent
                            / f"{original_path.stem} ({counter}){original_path.suffix}"
                        )

                    try:
                        with open(
                            candidate_path,
                            "xb"
                        ) as file:

                            file.write(
                                decrypted_data
                            )

                        output_path = candidate_path
                        break

                    except FileExistsError:
                        if counter == 100:
                            raise ValueError(
                                "Could not find an available filename"
                            )

                else:
                    raise ValueError(
                        "Could not find an available filename"
                    )

                print()
                print("=" * 60)
                print(
                    "             TRANSFER SUCCESSFUL"
                )
                print("=" * 60)

                print(
                    f"File saved to: "
                    f"{output_path}"
                )

                print(
                    f"File size: "
                    f"{len(decrypted_data)} bytes"
                )

                print(
                    f"SHA-256: "
                    f"{actual_hash}"
                )

                print("=" * 60)

                result = {
                    "status": "SUCCESS",
                    "message":
                        "File received and verified successfully",
                    "filename":
                        output_path.name,
                    "size":
                        len(decrypted_data),
                    "sha256":
                        actual_hash
                }

                # The response is itself encrypted and
                # authenticated with the session AES key.
                send_secure_json(
                    connection,
                    aes_key,
                    result
                )

            except InvalidTag:

                # Do not expose cryptographic details.
                message = (
                    "Decryption/authentication failed"
                )

                print()
                print("=" * 60)
                print("SERVER ERROR")
                print("=" * 60)
                print(message)
                print("=" * 60)

                send_error_response(
                    connection,
                    aes_key,
                    message
                )

                result = {
                    "status": "ERROR",
                    "message": message
                }

            except Exception as error:

                print()
                print("=" * 60)
                print("SERVER ERROR")
                print("=" * 60)

                # Detailed diagnostic stays server-side.
                print(
                    f"{type(error).__name__}: "
                    f"{error}"
                )

                print("=" * 60)

                # Send only a safe, useful message to client.
                if isinstance(
                    error,
                    ValueError
                ):

                    safe_message = str(
                        error
                    )

                else:

                    safe_message = (
                        "Server failed to "
                        "process the transfer"
                    )

                send_error_response(
                    connection,
                    aes_key,
                    safe_message
                )

                result = {
                    "status": "ERROR",
                    "message": safe_message
                }

            finally:

                try:

                    connection.shutdown(
                        socket.SHUT_RDWR
                    )

                except OSError:
                    pass

                connection.close()

                print()
                print(
                    "[+] Client connection closed."
                )

            if once:

                return result

    finally:

        server_socket.close()

        print()
        print(
            "[+] Server stopped."
        )


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    start_server()
