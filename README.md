# PQC Secure File Transfer

An educational Python project demonstrating file transfer over TCP using a custom **ML-KEM** implementation for shared-secret establishment, **HKDF-SHA256** for key derivation, and **AES-256-GCM** for authenticated encryption.

The project includes a terminal client/server, a Tkinter client GUI, and a separate local cryptography demonstration. The network application uses **ML-KEM-768**; the cryptographic module also supports ML-KEM-512 and ML-KEM-1024.

> This is a learning and demonstration project, not an audited or certified cryptographic product. The current handshake does not authenticate either endpoint's identity and is vulnerable to an active man-in-the-middle attack. Use non-sensitive files in a controlled test environment.

## Features

- Custom Python ML-KEM implementation: polynomial arithmetic, NTT, sampling, encoding, K-PKE, key generation, encapsulation, and decapsulation.
- TCP file upload using four-byte length-prefixed messages.
- A fresh client ML-KEM key pair for each transfer.
- HKDF-SHA256 derivation of a 32-byte AES key.
- AES-256-GCM encryption of the file and its SHA-256 digest.
- Authentication of file metadata through GCM associated data.
- Encrypted and authenticated server confirmation, with a matching SHA-256 check on the client.
- Filename validation, message-size limits, socket timeouts, and duplicate-filename handling.
- GUI file selection, editable host/port, status messages, and a digest display.

## Project files

Keep the following paths in the repository. In particular, the three networking files belong inside `network/`, because the application imports `network.client` and `network.protocol`.

| Path | Purpose |
| --- | --- |
| `mlkem.py` | ML-KEM implementation and a built-in key-agreement smoke test. |
| `network/protocol.py` | TCP framing and exact-length receiving helpers. |
| `network/client.py` | Generates keys, encrypts and uploads one file, and verifies the response. |
| `network/server.py` | Encapsulates a secret, receives and verifies a file, and saves it. |
| `app_gui.py` | Tkinter interface that calls the networking client. |
| `integration.py` | In-process ML-KEM and AES-GCM message demonstration; does not use TCP. |
| `.gitignore` | Excludes Python/environment artifacts and received file contents. |
| `README.md` | Setup, usage, and project documentation. |
| `received_files/` | Created automatically by the server for received files. |

## Setup

Use Python 3 with `pip` and virtual-environment support; Python 3.10 or newer is a suitable starting point. Tkinter and a desktop display are needed only for the GUI. The only third-party Python dependency imported by these files is `cryptography`.

Open a terminal in the repository root—the folder containing `mlkem.py` and `app_gui.py`. If cloning the repository, replace the placeholder with its actual GitHub URL:

```bash
git clone https://github.com/Chetna-mundra/PQC-Secure-File-Transfer.git
cd PQC-Secure-File-Transfer
```

If your clone has a different folder name, enter that folder instead. If you already have the project locally, skip cloning.

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install cryptography
```

If PowerShell blocks activation, use the environment's Python directly; no execution-policy change is necessary:

```powershell
.\.venv\Scripts\python.exe -m pip install cryptography
```

In that case, replace `python` in subsequent commands with `.\.venv\Scripts\python.exe`.

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install cryptography
```

For every new terminal, enter the project folder and activate the same environment again.

To check GUI support:

```bash
python -m tkinter
```

A small test window should open. If Tkinter is missing, install the Tcl/Tk support for your Python distribution. On Debian/Ubuntu with the system Python, this is typically supplied by `python3-tk`. Tkinter is not installed with `pip install tkinter`.

No `requirements.txt` is included in this version, so install `cryptography` directly as shown above.

## Run on one laptop

Start with a small, non-sensitive text file. Both the server and client use `127.0.0.1:5000` by default. This address means the same computer.

### 1. Start the server

In terminal 1, from the repository root:

```bash
python network/server.py
```

Wait for:

```text
[+] Waiting for client...
```

### 2. Send a file using the GUI

In terminal 2, from the same repository root:

```bash
python app_gui.py
```

1. Leave **Host** as `127.0.0.1` and **Port** as `5000`.
2. Click **Browse File** and select a file.
3. Click **Encrypt & Send File**.
4. Wait for the success dialog and verified hash.
5. Open `received_files/` in the server's project folder to find the received file.

The GUI is a client only: launching it does not start a server. Its stage badges summarize the transfer; they are not a live byte-progress indicator. Detailed network logs appear in the terminal that launched the GUI.

### Alternative: send from the terminal

With the server waiting, use:

```bash
python network/client.py "path/to/your/file.txt"
```

For example, on Windows:

```powershell
python network/client.py "C:\Users\YourName\Documents\sample.txt"
```

Quote paths containing spaces. A successful transfer prints:

```text
TRANSFER SUCCESSFUL
[OK] FILE INTEGRITY VERIFIED
```

**The default server handles one connection and then exits**, including after a failed transfer attempt. Restart it before the next transfer, or run the persistent mode below.

### Keep the server running

```bash
python -c "from network.server import start_server; start_server(once=False)"
```

This accepts successive connections, processing one at a time. Stop it with `Ctrl+C` in the server terminal. Each client connection uploads one file.

If a filename already exists, the server saves a numbered alternative such as `sample (1).txt` instead of overwriting it. It tries suffixes through `(100)` before reporting an error.

## Run between two laptops

Install the project and dependencies on both computers and connect them to the same trusted local network.

On the receiving laptop, run:

```bash
python -c "from network.server import start_server; start_server(host='0.0.0.0', port=5000, once=False)"
```

`0.0.0.0` tells the server to listen on all local IPv4 interfaces. It is not the address to type into the client.

Find the receiving laptop's local IPv4 address—for example, with `ipconfig` on Windows. On the sending laptop, open the GUI and set **Host** to that address, such as `192.168.1.20`, and **Port** to `5000`.

For a terminal transfer to a custom address:

```bash
python -c "from network.client import send_file; send_file('sample.txt', host='192.168.1.20', port=5000)"
```

Replace the example address and filename with your own. The regular `network/client.py` command accepts only the file path; it has no `--host` or `--port` options.

Allow inbound TCP connections to the chosen port on the receiving laptop's firewall for the trusted/private network. Received files are stored on the receiving laptop. Guest Wi-Fi or client isolation may prevent the laptops from communicating.

## Local cryptography demo

To demonstrate key agreement and message encryption without a running server:

```bash
python integration.py
```

Enter a message, or press Enter for the default message. The script generates ML-KEM-768 keys, compares the encapsulated and recovered secrets, encrypts/decrypts the message, and compares SHA-256 hashes.

This script runs entirely in one process. It uses the shared secret directly as an AES key and reuses the local AES object for decryption; the network application instead derives its AES key with HKDF. It also prints short shared-secret previews for demonstration, so avoid publishing its logs as real-session diagnostics.

## How the network transfer works

1. **Client key generation:** the client creates an ML-KEM-768 encapsulation key and private decapsulation key, and sends only the encapsulation key to the server.
2. **Server encapsulation:** the server creates a 32-byte shared secret and an ML-KEM ciphertext. It sends the ciphertext to the client.
3. **Client decapsulation:** the client recovers the shared secret using its private key.
4. **Key derivation:** both sides derive a 32-byte AES key using HKDF-SHA256, with `salt=None` and `info=b"PQC-Secure-File-Transfer"`.
5. **File encryption:** the client computes SHA-256 and encrypts `digest || file_bytes` using AES-256-GCM with a random 12-byte nonce. JSON metadata contains the filename, encrypted payload size, and nonce. Its exact bytes are supplied as associated data, so the metadata is authenticated but remains visible on the network.
6. **Server verification:** the server validates metadata and sizes, authenticates/decrypts the payload, checks the digest, and saves the file only after those checks succeed.
7. **Confirmation:** the server sends an AES-GCM-protected JSON result using a fresh random nonce and response-specific associated data. The client checks the success status and returned digest.

Each TCP message has a four-byte unsigned big-endian length followed by the message body. File data is sent as one encrypted message, not as independently encrypted chunks.

## Configuration and limits

| Setting | Current value / behavior |
| --- | --- |
| Default address | `127.0.0.1` |
| Default TCP port | `5000` |
| Network parameter set | `ML-KEM-768` |
| Maximum original file size | 100 MiB = 104,857,600 bytes |
| Maximum metadata size | 4 KiB |
| Maximum response envelope size | 64 KiB |
| Socket timeout | 30 seconds on client socket operations and accepted server connections |
| AES key / nonce / tag | 32 / 12 / 16 bytes |
| Encrypted file payload size | Original file size + 32-byte digest + 16-byte GCM tag |
| Output directory | `received_files/` beneath the server project root |
| Default server lifetime | One connection (`once=True`) |

File contents are read and encrypted in memory, so memory use can be substantially larger than the file itself. The server waits for an initial connection without the accepted-connection timeout.

The `MLKEM` class supports the following sizes:

| Parameter set | Encapsulation key | Decapsulation key | Ciphertext | Shared secret |
| --- | ---: | ---: | ---: | ---: |
| ML-KEM-512 | 800 bytes | 1,632 bytes | 768 bytes | 32 bytes |
| ML-KEM-768 | 1,184 bytes | 2,400 bytes | 1,088 bytes | 32 bytes |
| ML-KEM-1024 | 1,568 bytes | 3,168 bytes | 1,568 bytes | 32 bytes |

The network protocol does not negotiate a parameter set. Changing it requires matching changes to `PARAMETER_SET` in both client and server; GUI labels currently assume ML-KEM-768.

## Testing

Run the built-in ML-KEM smoke test:

```bash
python mlkem.py
```

It checks one randomly generated key-agreement round trip for each parameter set and prints `shared keys match` with the key/ciphertext sizes. This checks basic internal consistency, not full FIPS 203 conformance or interoperability.

For a manual end-to-end check:

1. Start the server and upload a small text file.
2. Confirm the client reports successful integrity verification.
3. Open the received file and compare it with the original.
4. Repeat with a binary file and an empty file.
5. Send the same filename again and check that the original received file is preserved.
6. Try a nonexistent input path and confirm the client reports an error.

When preparing this README, the supplied code passed the three-parameter ML-KEM smoke test, the default local integration demo, and a localhost terminal transfer whose received bytes matched the source. GUI interaction, two-computer networking, large-file limits, and adversarial cases were not tested in that check. There is no separate automated test suite in the supplied files.

## Troubleshooting

| Problem | What to check |
| --- | --- |
| `No module named cryptography` | Activate the correct environment and run `python -m pip install cryptography`. |
| `No module named network` or `mlkem` | Check file names and directory placement; run commands from the repository root. |
| Connection refused / Windows error 10061 | Start the server first. Restart it after its default single connection. Check host and port. |
| Address already in use / Windows error 10048 | Stop the existing server, or choose another port on both ends. |
| Timeout | Check the receiving IP, firewall, Wi-Fi isolation, and whether both programs are still running. |
| File not found | Use a valid path and quote it if it contains spaces. |
| File exceeds maximum allowed size | Choose a file no larger than 100 MiB. |
| Filename rejected | Use a simple filename without path separators, reserved device names, or a trailing space/period. |
| Decryption/authentication failed | Check that both sides use matching project versions and parameter sets; retry with an unmodified file/connection. |
| Tkinter missing or no display | Install Tk support and run in a desktop session, or use the terminal client. |

## Security scope and current limitations

- **Endpoint identity is not authenticated.** ML-KEM establishes a secret, but the current exchange has no signatures, certificates, or trusted identity binding. AES-GCM verification does not establish who the peer is.
- **The custom ML-KEM implementation is educational.** It has not been independently audited, certified, or demonstrated to be constant-time. Passing its round-trip test is not proof of standard conformance.
- **Metadata is visible.** The filename, nonce, and encrypted size are transmitted in plaintext and authenticated as associated data.
- **Received files are plaintext on disk.** Transfer encryption does not provide encryption at rest.
- **There is no user authentication, authorization, or quota system.** Keep the server within a controlled demonstration environment.
- **Transfers are one-way and memory-buffered.** This version has no download command, resume support, streaming encryption, or parallel connection handling.
- **The GUI is a demonstration interface.** It updates Tkinter widgets from a worker thread and does not receive live per-stage callbacks; robust main-thread UI dispatch and progress reporting remain future improvements.

Future work includes authenticated peer identities, independent ML-KEM test vectors, automated malformed-input/tampering tests, streaming transfers, and GUI thread-safety improvements.

## Development workflow

Use `mlkem` and `networking` for component work, `integration` for combining and testing changes, and `main` for the reviewed project version. After testing the combined system, merge `integration` into `main` through a pull request. Later changes to `integration` require another merge before they appear on `main`.

Received file contents are excluded by the supplied `.gitignore`. No license file is included in the supplied project; choose and add a license before making reuse permissions explicit.
