# NourCrypt

A client-side file encryption and decryption web application built using the native Web Crypto API and Web Workers.

NourCrypt processes all files locally inside your browser's Web Worker thread. No data is sent to a server or external network.

## Features

- **Local Processing**: Encrypts and decrypts files up to 500 MB directly in browser RAM.
- **AES-256-GCM Encryption**: Authenticated symmetric encryption with 128-bit authentication tags to prevent file tampering.
- **PBKDF2 Key Derivation**: Uses 100,000 iterations of SHA-256 with a unique 16-byte random salt for password hashing.
- **Chunked Streaming**: Splits files into 8 MB chunks processed via Web Workers to keep the UI responsive.
- **Text Encryption**: Option to encrypt and decrypt plain text messages directly in the browser.
- **Passphrase Generator**: Built-in cryptographically secure random password generator.

## Technical Overview

NourCrypt uses the browser's native `window.crypto.subtle` API for cryptographic operations:

1. A 16-byte salt and 12-byte master IV are generated using `crypto.getRandomValues`.
2. The user's password is key-stretched via PBKDF2 (`SHA-256`, 100,000 iterations) to derive a 256-bit AES-GCM key.
3. File metadata (original filename, size, MIME type) is encrypted using the derived key and master IV.
4. File data is split into 8 MB chunks, each encrypted with AES-256-GCM using a unique per-chunk 12-byte IV.
5. All binary components are serialized into a `.nour` container file.

## File Format Spec (.nour)

```text
[0..8]   Magic header: "NOURCRYPT" (ASCII 9 bytes)
[9..10]  Version: 0x0001 (2 bytes)
[11..26] Salt: 16 bytes
[27..38] Master IV: 12 bytes
[39..40] Encrypted metadata length (Big Endian uint16, 2 bytes)
[41..N]  Encrypted metadata JSON payload
[N..End] Sequence of chunks: [Chunk IV (12B) | Chunk length (4B) | Ciphertext + Tag]
```

## Running Locally

NourCrypt has no server dependencies or build steps. Clone the repository and serve the files with any HTTP server:

```bash
git clone https://github.com/itsraynour/nourcrypt.git
cd nourcrypt
python -m http.server 8000
```

Open `http://localhost:8000` in your web browser.

## Project Structure

```text
nourcrypt/
├── index.html                       # Main web application UI
├── how-it-works.html                # Architecture explanation page
├── privacy.html                     # Privacy policy
├── terms.html                       # Terms of service
├── css/
│   └── styles.css                   # Layout and theme styles
├── js/
│   ├── app.js                       # DOM handlers and worker message dispatcher
│   └── crypto-worker.js             # Web Worker background crypto engine
├── SECURITY_AND_ARCHITECTURE_AR.md # Technical documentation in Arabic
├── LICENSE                          # MIT License
└── README.md                        # Documentation
```

## License

[MIT](LICENSE)
