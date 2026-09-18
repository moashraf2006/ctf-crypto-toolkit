# CyberTools CTF Workbench

CyberTools is a local-only CTF and authorized-lab workbench. It combines the existing crypto transformer with an offline helper chat, auto-decode candidates, JWT inspection, timestamp/URL/regex/CIDR utilities, and safe Kali command references.

## Current modules

- **Workbench:** Base64, hex, URL, Morse, Brainfuck, XOR, ROT13, Atbash, Caesar, hashes, AES/DES/3DES, and auto-decode candidates.
- **Crypto:** local JWT structure inspection and hash comparison.
- **Kali reference:** parameterized reference generators for nmap, curl, strings, OpenSSL, and grep. Commands are displayed only and are never executed.
- **Utilities:** timestamp conversion, URL parsing, IPv4/CIDR calculations, and regex testing.
- **Assistant:** offline rule-based explanations with no API key or external service.

## Run

```bash
cd ~/ctf-crypto-toolkit
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>.

## Design and safety

Sensitive transformations run locally in the browser when practical; the existing Flask API is localhost-only. This project does not upload files, make outbound requests, execute shell commands, provide persistence/C2 behavior, or scan targets. Use generated commands only within an authorized CTF, lab, or test scope.

The command generator is intentionally a reference tool rather than an attack automation framework. More modules can be added incrementally, with client-side processing preferred for encodings, hashes, JWT structure, regex, and network calculations.
