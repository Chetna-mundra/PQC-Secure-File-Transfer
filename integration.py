import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mlkem import MLKEM

def run_secure_transfer():
    print("starting pqc secure file transfer...")

    kem = MLKEM("ML-KEM-768")

    #key gen
    client_ek, client_dk = kem.keygen()
    print(f"generated the MLKEM-768 keys..(ek: {len(client_ek)}B), (dk: {len(client_dk)}B)")

    #encapsulation
    server_shared_key, ciphertext = kem.encaps(client_ek)
    print(f"encapsulated shared secret into {len(ciphertext)}B ciphertext..(shared key preview: {server_shared_key.hex()[:8]})")

    #decapsulation
    client_shared_key = kem.decaps(client_dk, ciphertext)
    print(f"decapsulated shared secret from ciphertext...(shared key preview: {client_shared_key.hex()[:8]})")

    if server_shared_key == client_shared_key:
        print("key agreement verified as the shared secret matches.")
    else:
        print("error...key agreement failed as the shared secret doesnt match")
        return

    # 5.encryption using AES-256-GCM
    print("Enter a message to send (or press Enter to use the default test data): ")
    user_msg = input().strip()
    if not user_msg:
        test_data = b"This is a sample confidential message for testing."
    else:
        test_data = user_msg.encode("utf-8")

    aes_cipher = AESGCM(server_shared_key[:32])
    nonce = os.urandom(12) 
    encrypted_file = aes_cipher.encrypt(nonce, test_data, None)
    
    print("original message size is", len(test_data), "bytes")
    print("encrypted payload size is", len(encrypted_file), "bytes")

    decrypted_file = aes_cipher.decrypt(nonce, encrypted_file, None)
    print("Decrypted message:", decrypted_file.decode("utf-8"))

    original_hash = hashlib.sha256(test_data).hexdigest()
    decrypted_hash = hashlib.sha256(decrypted_file).hexdigest()

    print("Original Hash: ", original_hash)
    print("Decrypted Hash:", decrypted_hash)

    if original_hash == decrypted_hash:
        print("integrity verified as the SHA-256 hashes match.")
    else:
        print("integrity check failed as the SHA-256 Hashes dont match.")

if __name__ == "__main__":
    run_secure_transfer()