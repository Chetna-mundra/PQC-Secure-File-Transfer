import hashlib
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


def recv_secure_json(
    sock,
    aes_key: bytes
):
    """
    Receive, decrypt and authenticate a JSON
    response from the server.
    """

    envelope_bytes = recv_message(
        sock,
        max_size=MAX_RESPONSE_SIZE
    )

    try:

        envelope = json.loads(
            envelope_bytes.decode("utf-8")
        )

    except (
        UnicodeDecodeError,
        json.JSONDecodeError
    ) as error:

        raise ValueError(
            "Invalid server response format"
        ) from error

    if not isinstance(
        envelope,
        dict
    ):

        raise ValueError(
            "Invalid server response"
        )

    if set(envelope.keys()) != {
        "nonce",
        "ciphertext"
    }:

        raise ValueError(
            "Invalid server response structure"
        )

    try:

        nonce = bytes.fromhex(
            envelope["nonce"]
        )

        encrypted_data = bytes.fromhex(
            envelope["ciphertext"]
        )

    except (
        TypeError,
        ValueError
    ) as error:

        raise ValueError(
            "Invalid server response encoding"
        ) from error

    if len(nonce) != NONCE_SIZE:

        raise ValueError(
            "Invalid server response nonce"
        )

    try:

        plaintext = AESGCM(
            aes_key
        ).decrypt(
            nonce,
            encrypted_data,
            RESPONSE_AAD
        )

    except InvalidTag as error:

        raise ValueError(
            "Server response authentication failed"
        ) from error

    try:

        result = json.loads(
            plaintext.decode("utf-8")
        )

    except (
        UnicodeDecodeError,
        json.JSONDecodeError
    ) as error:

        raise ValueError(
            "Invalid authenticated server response"
        ) from error

    if not isinstance(
        result,
        dict
    ):

        raise ValueError(
            "Invalid authenticated server response"
        )

    return result


# ---------------------------------------------------------
# Client
# ---------------------------------------------------------

def send_file(
    file_path: str,
    host: str = HOST,
    port: int = PORT
):
    """
    Send one file to the server.

    Returns a result dictionary on success.

    Raises an exception on failure so that callers such
    as Person 3's GUI can reliably detect failure.
    """

    file_path = Path(
        file_path
    )

    if not file_path.exists():

        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    if not file_path.is_file():

        raise ValueError(
            f"Not a file: {file_path}"
        )

    file_size = file_path.stat().st_size

    if file_size > MAX_FILE_SIZE:

        raise ValueError(
            f"File exceeds maximum allowed size "
            f"of {MAX_FILE_SIZE} bytes"
        )

    print("=" * 60)
    print(
        "       PQC SECURE FILE TRANSFER CLIENT"
    )
    print("=" * 60)

    print()
    print(
        f"[+] File: {file_path}"
    )

    print(
        f"[+] ML-KEM parameter set: "
        f"{PARAMETER_SET}"
    )

    print()

    # =====================================================
    # 1. GENERATE ML-KEM KEY PAIR
    # =====================================================

    print(
        "[1/7] Generating ML-KEM key pair..."
    )

    kem = MLKEM(
        PARAMETER_SET
    )

    public_key, private_key = (
        kem.keygen()
    )

    print(
        f"      Public key: "
        f"{len(public_key)} bytes"
    )

    print(
        f"      Private key: "
        f"{len(private_key)} bytes"
    )

    # =====================================================
    # CREATE SOCKET
    # =====================================================

    client_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    client_socket.settimeout(
        SOCKET_TIMEOUT
    )

    print()

    print(
        f"[+] Connecting to "
        f"{host}:{port}..."
    )

    try:

        client_socket.connect(
            (host, port)
        )

        print(
            "[+] Connected to server."
        )

        print()

        # =================================================
        # 2. SEND ML-KEM PUBLIC KEY
        # =================================================

        print(
            "[2/7] Sending ML-KEM public key..."
        )

        if len(public_key) != kem.ek_size:

            raise ValueError(
                "Generated public key has invalid size"
            )

        send_message(
            client_socket,
            public_key,
            max_size=kem.ek_size
        )

        print(
            "      Public key sent."
        )

        # =================================================
        # 3. RECEIVE ML-KEM CIPHERTEXT
        # =================================================

        print(
            "[3/7] Receiving ML-KEM ciphertext..."
        )

        ciphertext = recv_message(
            client_socket,
            max_size=kem.ct_size
        )

        if len(ciphertext) != kem.ct_size:

            raise ValueError(
                "Received ciphertext has invalid size"
            )

        print(
            f"      Received: "
            f"{len(ciphertext)} bytes"
        )

        # =================================================
        # 4. ML-KEM DECAPSULATION
        # =================================================

        print(
            "[4/7] Recovering shared secret..."
        )

        shared_secret_client = (
            kem.decaps(
                private_key,
                ciphertext
            )
        )

        print(
            f"      Shared secret: "
            f"{len(shared_secret_client)} bytes"
        )

        # =================================================
        # 5. DERIVE AES KEY
        # =================================================

        print(
            "[5/7] Deriving AES-256 key with HKDF..."
        )

        aes_key = derive_aes_key(
            shared_secret_client
        )

        print(
            "      AES key derived."
        )

        # =================================================
        # READ FILE
        # =================================================

        print()
        print(
            "[+] Reading file..."
        )

        with open(
            file_path,
            "rb"
        ) as file:

            original_data = file.read()

        if len(original_data) > MAX_FILE_SIZE:

            raise ValueError(
                "File exceeds maximum allowed size"
            )

        print(
            f"      Original size: "
            f"{len(original_data)} bytes"
        )

        # =================================================
        # SHA-256
        # =================================================

        original_digest = hashlib.sha256(
            original_data
        ).digest()

        original_hash = (
            original_digest.hex()
        )

        print(
            f"      SHA-256: "
            f"{original_hash}"
        )

        # =================================================
        # GENERATE NONCE
        # =================================================

        nonce = os.urandom(
            NONCE_SIZE
        )

        # =================================================
        # CREATE METADATA
        # =================================================
        #
        # IMPORTANT:
        #
        # The SHA-256 digest is no longer included
        # in plaintext metadata.
        #
        # Encrypted payload:
        #
        #   [32-byte SHA-256][original file]
        #
        # This entire payload is authenticated by
        # AES-GCM.
        #
        # =================================================

        encrypted_size = (
            FILE_HASH_SIZE
            + len(original_data)
            + GCM_TAG_SIZE
        )

        metadata = {
            "filename": file_path.name,
            "size": encrypted_size,
            "nonce": nonce.hex()
        }

        metadata_bytes = json.dumps(
            metadata,
            separators=(",", ":")
        ).encode("utf-8")

        if len(metadata_bytes) > MAX_METADATA_SIZE:

            raise ValueError(
                "Metadata exceeds maximum allowed size"
            )

        # =================================================
        # ENCRYPT FILE
        # =================================================

        print()
        print(
            "[+] Encrypting file using AES-256-GCM..."
        )

        encrypted_payload = (
            original_digest
            + original_data
        )

        aes = AESGCM(
            aes_key
        )

        encrypted_data = aes.encrypt(
            nonce,
            encrypted_payload,
            metadata_bytes
        )

        if len(encrypted_data) != encrypted_size:

            raise ValueError(
                "Unexpected encrypted data size"
            )

        print(
            f"      Nonce: "
            f"{len(nonce)} bytes"
        )

        print(
            f"      Encrypted data: "
            f"{len(encrypted_data)} bytes"
        )

        # =================================================
        # 6. SEND METADATA
        # =================================================

        print()
        print(
            "[6/7] Sending file metadata..."
        )

        send_message(
            client_socket,
            metadata_bytes,
            max_size=MAX_METADATA_SIZE
        )

        print(
            "      Metadata sent."
        )

        # =================================================
        # SEND ENCRYPTED FILE
        # =================================================

        print(
            "[+] Sending encrypted file..."
        )

        send_message(
            client_socket,
            encrypted_data,
            max_size=(
                FILE_HASH_SIZE
                + MAX_FILE_SIZE
                + GCM_TAG_SIZE
            )
        )

        print(
            "      Encrypted file sent."
        )

        # =================================================
        # 7. RECEIVE SERVER RESULT
        # =================================================

        print()
        print(
            "[7/7] Waiting for server verification..."
        )

        result = recv_secure_json(
            client_socket,
            aes_key
        )

        status = result.get(
            "status"
        )

        if status != "SUCCESS":

            raise RuntimeError(
                result.get(
                    "message",
                    "Server reported an error"
                )
            )

        server_hash = result.get(
            "sha256"
        )

        if server_hash != original_hash:

            raise RuntimeError(
                "Server returned an unexpected "
                "SHA-256 digest"
            )

        print()
        print("=" * 60)
        print(
            "             TRANSFER SUCCESSFUL"
        )
        print("=" * 60)

        message = result.get("message", "Transfer successful")
        print(f"Server message: {message}")	

        print(
            f"Server SHA-256: "
            f"{server_hash}"
        )

        print()
        print(
            "[OK] FILE INTEGRITY VERIFIED"
        )

        print("=" * 60)

        return {
            "status": "SUCCESS",
            "filename": result.get(
                "filename",
                file_path.name
            ),
            "size": result.get(
                "size",
                len(original_data)
            ),
            "sha256": original_hash,
            "server_sha256": server_hash
        }

    finally:

        client_socket.close()

        print()
        print(
            "[+] Client connection closed."
        )


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage:"
        )

        print(
            "python network\\client.py <file_path>"
        )

        sys.exit(1)

    try:

        send_file(
            sys.argv[1]
        )

    except Exception as error:

        print()
        print("=" * 60)
        print(
            "CLIENT ERROR"
        )
        print("=" * 60)

        print(
            f"Message: {error}"
        )

        print("=" * 60)

        sys.exit(1)
