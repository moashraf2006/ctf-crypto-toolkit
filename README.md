# CTF Crypto Toolkit

A local-only Flask web application for common CTF transformations. It is intentionally a cryptography and encoding utility, not a remote shell, agent, downloader, or command-and-control framework.

## Features

- Base64, hex, URL, Morse, and Brainfuck decoding
- Repeating-key XOR
- MD5, SHA-1, SHA-2, and SHA-3 hashing
- AES, DES, and 3DES CBC/ECB operations
- PKCS#7, zero, and no-padding modes
- Base64, hex, and UTF-8 input/output formats
- Kali Linux command reference

## Run on Kali Linux

```bash
git clone https://github.com/moashraf2006/ctf-crypto-toolkit.git
cd ctf-crypto-toolkit
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000> in a browser. The server binds to localhost and has no feature that executes submitted commands or contacts a target server.

## AES format note

For the PowerShell sample supplied with this project, use AES, CBC, 256-bit key, zero padding, Base64 input, and an IV extracted from the first 16 decoded bytes. The sample prepends the IV to the ciphertext; this web tool deliberately leaves IV extraction explicit so challenge data is not silently misinterpreted.

## Security boundaries

- Runs locally by default.
- No shell execution, arbitrary code evaluation, uploads, persistence, or outbound HTTP requests.
- Request bodies are limited to 2 MiB.
- Brainfuck execution has a one-million-step limit.
- Do not use this tool against systems or data without authorization.
