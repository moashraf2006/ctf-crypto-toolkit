# CyberTools CTF Workbench

A local-only, offline-first cybersecurity workbench for CTFs, labs, cryptography practice, and explicitly authorized testing.

## Included

- **Crypto and encoding:** Base64, URL, hex, Morse, ROT13/ROT47, Caesar, Atbash, Vigenere, XOR, hashes, HMAC, AES/DES/3DES.
- **CTF workbench:** explicit transformations, JWT structure decoder, regex tester, transparent outputs.
- **Utilities:** IPv4/CIDR calculator, URL parser, UUID/token/password generation, HTTP request explainer, hash comparison.
- **Kali reference:** parameterized references for nmap, ffuf, gobuster, curl, strings, readelf, objdump, OpenSSL, grep, tshark, John, and Hashcat. Commands are shown only.
- **Assistant:** offline rule-based explanations without an API key or external service.

## Run on Kali

```bash
cd ~/ctf-crypto-toolkit
git pull
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## Scope and safety

This project intentionally does not upload files, make outbound requests, execute shell commands, scan targets, automate credential attacks, provide persistence, or provide C2 behavior. Use displayed commands only inside an authorized CTF, lab, or test scope. Sensitive transformations should remain in the browser whenever practical.
