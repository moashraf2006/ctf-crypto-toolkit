# CTF Crypto Toolkit

A local-only Flask web application for CTF encoding, decoding, cryptography, and a small offline helper chat. The chat gives explanations and safe Linux/Kali command references; it does not execute commands, run arbitrary code, or contact external AI services.

## Features

- Base64, hex, URL, Morse, Brainfuck, ROT13, Atbash, and Caesar transformations
- Repeating-key XOR and hash calculation
- AES, DES, and 3DES CBC/ECB operations
- PKCS#7, zero, and no-padding modes
- Offline helper chat for decoding guidance and Kali references
- Auto-decode mode to test likely common encodings
- Read-only/reference commands for files, text, encoding, crypto, archives, and analysis
- Localhost-only operation with a 2 MiB request limit

## Run on Kali Linux

```bash
git clone https://github.com/moashraf2006/ctf-crypto-toolkit.git
cd ctf-crypto-toolkit
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>. The chat is rule-based and works without an API key or Internet connection.

## Safety boundary

The toolkit intentionally does not execute shell commands, accept uploads, make outbound requests, provide C2 behavior, or run arbitrary code. Use the displayed commands manually and only in authorized CTF/lab environments.
