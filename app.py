from flask import Flask, jsonify, render_template, request
import base64
import binascii
import hashlib
import os
import re
import urllib.parse

try:
    from Crypto.Cipher import AES, DES, DES3
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    AES = DES = DES3 = None
    pad = unpad = None

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024


def text_input(value):
    return "" if value is None else str(value)


def decode_bytes(value, encoding):
    value = text_input(value).strip()
    if value == "":
        return b""
    if encoding in ("hex", "hexadecimal"):
        return bytes.fromhex(value.replace(" ", ""))
    if encoding in ("base64", "b64"):
        return base64.b64decode(value, validate=True)
    if encoding in ("utf8", "utf-8", "utf_8", "text", "plain"):
        return value.encode("utf-8")
    raise ValueError(f"Unsupported encoding: {encoding}")


def encode_bytes(value, encoding):
    if encoding in ("hex", "hexadecimal"):
        return value.hex()
    if encoding in ("base64", "b64"):
        return base64.b64encode(value).decode("ascii")
    if encoding in ("utf8", "utf-8", "utf_8", "text", "plain"):
        return value.decode("utf-8", errors="replace")
    raise ValueError(f"Unsupported output encoding: {encoding}")


def crypt_transform(mode, algorithm, key, iv, padding, input_encoding, output_encoding, raw_input, operation):
    if AES is None:
        raise ValueError("Missing crypto dependency. Run: pip install -r requirements.txt")

    key_bytes = decode_bytes(key, input_encoding)
    iv_bytes = decode_bytes(iv, input_encoding) if text_input(iv) else None
    raw = decode_bytes(raw_input, input_encoding)

    if algorithm == "AES":
        if len(key_bytes) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes")
        cipher_cls, block_size = AES, AES.block_size
    elif algorithm == "DES":
        if len(key_bytes) != 8:
            raise ValueError("DES key must be 8 bytes")
        cipher_cls, block_size = DES, DES.block_size
    elif algorithm == "3DES":
        if len(key_bytes) not in (16, 24):
            raise ValueError("3DES key must be 16 or 24 bytes")
        cipher_cls, block_size = DES3, DES3.block_size
    else:
        raise ValueError("Unsupported algorithm: use AES, DES, or 3DES")

    if mode not in ("CBC", "ECB"):
        raise ValueError("Only CBC and ECB are supported")

    if mode == "CBC":
        if iv_bytes is None or len(iv_bytes) != block_size:
            raise ValueError(f"{algorithm} CBC requires an IV of {block_size} bytes")
        cipher = cipher_cls.new(key_bytes, cipher_cls.MODE_CBC, iv_bytes)
    else:
        cipher = cipher_cls.new(key_bytes, cipher_cls.MODE_ECB)

    if padding == "pkcs7":
        raw = pad(raw, block_size)
    elif padding == "zeros":
        if len(raw) % block_size != 0:
            raw += b"\0" * (block_size - (len(raw) % block_size))
    elif padding == "none":
        if len(raw) % block_size != 0:
            raise ValueError("Input must be a multiple of the block size when padding=none")
    else:
        raise ValueError("Unsupported padding mode: use pkcs7, zeros, or none")

    if operation == "encrypt":
        result = cipher.encrypt(raw)
    elif operation == "decrypt":
        result = cipher.decrypt(raw)
        if padding == "pkcs7":
            result = unpad(result, block_size)
        elif padding == "zeros":
            result = result.rstrip(b"\0")
    else:
        raise ValueError("Operation must be encrypt or decrypt")

    return encode_bytes(result, output_encoding)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("XOR key cannot be empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def caesar(text, shift):
    result = []
    for ch in text:
        if "a" <= ch.lower() <= "z":
            base = ord("a")
            offset = (ord(ch.lower()) - base + shift) % 26
            result.append(chr(base + offset))
        else:
            result.append(ch)
    return "".join(result)


def rot13(text):
    return caesar(text, 13)


def atbash(text):
    out = []
    for ch in text:
        if "a" <= ch.lower() <= "z":
            base = ord("a")
            out.append(chr(ord("z") - (ord(ch.lower()) - base)))
        else:
            out.append(ch)
    return "".join(out)


def morse_encode(text):
    table = {
        "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".",
        "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---",
        "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---",
        "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-",
        "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--",
        "Z": "--..", "0": "-----", "1": ".----", "2": "..---", "3": "...--",
        "4": "....-", "5": ".....", "6": "-....", "7": "--...", "8": "---..",
        "9": "----."
    }
    result = []
    for ch in text.upper():
        if ch in table:
            result.append(table[ch])
        elif ch == " ":
            result.append("/")
    return " ".join(result)


def morse_decode(value):
    table = {
        ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
        "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
        "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
        ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
        "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
        "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3",
        "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8",
        "----.": "9"
    }
    text = value.strip()
    if not text:
        return ""
    words = re.split(r"\s{2,}|/", text)
    out = []
    for word in words:
        letters = word.split()
        decoded = "".join(table.get(letter.upper(), "?") for letter in letters)
        out.append(decoded)
    return " ".join(out)


def brainfuck(source):
    code = re.sub(r"[^<>+\-.,\[\]]", "", source)
    cells = [0] * 30000
    pointer = 0
    pc = 0
    output = []
    jumps = {}
    stack = []

    for idx, ch in enumerate(code):
        if ch == "[":
            stack.append(idx)
        elif ch == "]":
            if not stack:
                raise ValueError("Unmatched ] in Brainfuck source")
            start = stack.pop()
            jumps[start] = idx
            jumps[idx] = start

    if stack:
        raise ValueError("Unmatched [ in Brainfuck source")

    steps = 0
    while pc < len(code):
        steps += 1
        if steps > 1_000_000:
            raise ValueError("Brainfuck execution limit exceeded")

        ch = code[pc]
        if ch == ">":
            pointer = (pointer + 1) % len(cells)
        elif ch == "<":
            pointer = (pointer - 1) % len(cells)
        elif ch == "+":
            cells[pointer] = (cells[pointer] + 1) % 256
        elif ch == "-":
            cells[pointer] = (cells[pointer] - 1) % 256
        elif ch == ".":
            output.append(chr(cells[pointer]))
        elif ch == "[":
            if cells[pointer] == 0:
                pc = jumps.get(pc, pc)
        elif ch == "]":
            if cells[pointer] != 0:
                pc = jumps.get(pc, pc)
        pc += 1

    return "".join(output)


BASH_REFERENCE = {
    "files": [
        "pwd",
        "ls -la",
        "find . -type f -maxdepth 2",
        "file ./sample",
        "stat ./sample",
        "strings -n 6 ./sample"
    ],
    "text": [
        "grep -Rni 'pattern' .",
        "awk '{print $1}' file",
        "cut -d: -f1 file",
        "sort -u file",
        "wc -c file",
        "tr -d '\n' < file"
    ],
    "encoding": [
        "printf '%s' 'text' | base64",
        "printf '%s' 'BASE64' | base64 -d",
        "printf '%s' 'text' | xxd -p",
        "printf '%s' 'HEX' | xxd -r -p",
        "python3 -c \"import urllib.parse; print(urllib.parse.unquote('VALUE'))\""
    ],
    "crypto": [
        "printf '%s' 'text' | sha256sum",
        "printf '%s' 'text' | md5sum",
        "openssl enc -aes-256-cbc -K KEY_HEX -iv IV_HEX -in input -out output",
        "openssl rand -hex 16",
        "openssl enc -d -aes-256-cbc -K KEY_HEX -iv IV_HEX -in input.enc -out output"
    ],
    "network": [
        "curl -I http://127.0.0.1:5000",
        "curl -s http://127.0.0.1:5000/api/health",
        "ss -tulpen",
        "dig example.org"
    ],
    "archives": [
        "unzip -l file.zip",
        "tar -tvf file.tar",
        "7z l file.7z",
        "binwalk file"
    ],
    "analysis": [
        "sha256sum file",
        "exiftool file",
        "xxd -g 1 -l 64 file",
        "readelf -h binary",
        "checksec --file=binary"
    ]
}


def try_auto_decoding(value):
    attempts = []
    original = value.strip()
    if not original:
        return attempts

    # base64
    try:
        decoded = base64.b64decode(original, validate=True)
        text = decoded.decode("utf-8", errors="replace")
        attempts.append({"type": "base64", "result": text})
    except Exception:
        pass

    # url
    try:
        decoded = urllib.parse.unquote(original)
        if decoded != original:
            attempts.append({"type": "url", "result": decoded})
    except Exception:
        pass

    # hex
    try:
        decoded = bytes.fromhex(original.replace(" ", ""))
        text = decoded.decode("utf-8", errors="replace")
        if text and text.isprintable():
            attempts.append({"type": "hex", "result": text})
    except Exception:
        pass

    # xor common keys
    common_keys = ["key", "secret", "password", "admin", "flag", "pass", "s3cr3t", "hidden"]
    for k in common_keys:
        key = k.encode("utf-8")
        plain = xor_bytes(original.encode("utf-8"), key)
        text = plain.decode("utf-8", errors="replace")
        if text and any(ch.isalpha() for ch in text):
            attempts.append({"type": f"xor:{k}", "result": text})

    # caesar shifts
    for shift in range(1, 26):
        decoded = caesar(original, shift)
        if decoded and any(ch.isalpha() for ch in decoded):
            attempts.append({"type": f"caesar:{shift}", "result": decoded})

    # rot13
    decoded = rot13(original)
    if decoded != original:
        attempts.append({"type": "rot13", "result": decoded})

    # atbash
    decoded = atbash(original)
    if decoded != original:
        attempts.append({"type": "atbash", "result": decoded})

    # morse
    try:
        decoded = morse_decode(original)
        if decoded and any(ch.isalpha() for ch in decoded):
            attempts.append({"type": "morse", "result": decoded})
    except Exception:
        pass

    # brainfuck
    try:
        decoded = brainfuck(original)
        if decoded and any(ch.isprintable() for ch in decoded):
            attempts.append({"type": "brainfuck", "result": decoded})
    except Exception:
        pass

    seen = set()
    unique = []
    for item in attempts:
        key = (item["type"], item["result"])
        if key not in seen:
            unique.append(item)
            seen.add(key)
    return unique[:12]


def assistant_reply(message):
    q = message.lower().strip()
    if q == "":
        return "Ask me about Base64, hex, XOR, Morse, AES, Brainfuck, or Kali commands."

    if any(x in q for x in ("kali", "linux", "bash", "command")):
        text = "Safe local CTF commands by category:\n\n"
        for section, items in BASH_REFERENCE.items():
            text += f"[{section}]\n"
            for item in items:
                text += f"  - {item}\n"
            text += "\n"
        return text.strip()

    if "base64" in q:
        return "Use Base64 decode in the toolkit. Kali example: printf '%s' 'VALUE' | base64 -d"
    if "hex" in q:
        return "Use Hex decode. Kali example: printf '%s' 'HEX' | xxd -r -p"
    if "morse" in q:
        return "Use Morse decode. Letters with spaces; words with two spaces or '/'."
    if "brainfuck" in q:
        return "Use Brainfuck decode. It is a local interpreter and capped at one million steps."
    if "aes" in q or "des" in q or "cipher" in q:
        return "For AES/DES, set the key and IV correctly, choose CBC/ECB, and use the right padding. CBC needs a full block-size IV."
    if "xor" in q:
        return "Test XOR with common keys like: key, secret, password, admin, flag, pass"
    if "hash" in q:
        return "Hashes are one-way. Use the Hash tool for MD5/SHA-1/SHA-256/etc. Without additional clues, hash decryption is not possible."
    if "decode" in q or "ciphertext" in q or "encrypted" in q:
        return "Try the order: Base64 -> URL -> Hex -> XOR -> Caesar -> ROT13 -> Atbash -> Morse -> Brainfuck."
    if "help" in q or "what can you do" in q:
        return "I can help with Base64, hex, URL, XOR, Caesar, Morse, Brainfuck, AES/DES, and Kali command suggestions."
    return "I am a local CTF helper. Ask about decoding, encryption, Linux commands, or paste ciphertext to try Auto Decode."


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/transform")
def transform():
    try:
        data = request.get_json(force=True, silent=True) or {}
        tool = data.get("tool")
        value = text_input(data.get("input"))

        if tool == "base64-encode":
            result = base64.b64encode(value.encode("utf-8")).decode("ascii")
        elif tool == "base64-decode":
            result = base64.b64decode(value, validate=True).decode("utf-8", errors="replace")
        elif tool == "hex-encode":
            result = value.encode("utf-8").hex()
        elif tool == "hex-decode":
            result = bytes.fromhex(value.replace(" ", "")).decode("utf-8", errors="replace")
        elif tool == "url-encode":
            result = urllib.parse.quote(value, safe="")
        elif tool == "url-decode":
            result = urllib.parse.unquote(value)
        elif tool == "morse-encode":
            result = morse_encode(value)
        elif tool == "morse-decode":
            result = morse_decode(value)
        elif tool == "brainfuck":
            result = brainfuck(value)
        elif tool == "xor":
            key = decode_bytes(data.get("key", ""), data.get("key_encoding", "utf8"))
            if not key:
                raise ValueError("XOR key cannot be empty")
            raw = decode_bytes(value, data.get("input_encoding", "utf8"))
            result = xor_bytes(raw, key)
            result = encode_bytes(result, data.get("output_encoding", "utf8"))
        elif tool == "rot13":
            result = rot13(value)
        elif tool == "atbash":
            result = atbash(value)
        elif tool == "caesar":
            shift = int(data.get("shift", 3))
            result = caesar(value, shift)
        elif tool == "hash":
            algorithm = data.get("algorithm", "sha256").lower()
            if algorithm not in hashlib.algorithms_available:
                raise ValueError(f"Unsupported hash algorithm: {algorithm}")
            result = hashlib.new(algorithm, value.encode("utf-8")).hexdigest()
        elif tool == "cipher":
            result = crypt_transform(
                data.get("mode", "CBC"),
                data.get("algorithm", "AES"),
                data.get("key", ""),
                data.get("iv", ""),
                data.get("padding", "pkcs7"),
                data.get("input_encoding", "utf8"),
                data.get("output_encoding", "base64"),
                value,
                data.get("operation", "encrypt"),
            )
        else:
            raise ValueError(f"Unknown tool: {tool}")

        return jsonify(result=result)

    except (ValueError, binascii.Error, UnicodeError) as exc:
        return jsonify(error=str(exc)), 400


@app.post("/api/chat")
def chat():
    data = request.get_json(force=True, silent=True) or {}
    message = text_input(data.get("message"))[:4000]
    if not message:
        return jsonify(error="Enter a question or command."), 400
    return jsonify(reply=assistant_reply(message))


@app.post("/api/autodecode")
def auto_decode():
    data = request.get_json(force=True, silent=True) or {}
    value = text_input(data.get("input"))
    if not value:
        return jsonify(error="Enter some ciphertext."), 400
    candidates = try_auto_decoding(value)
    return jsonify(results=candidates[:10])


@app.get("/api/health")
def health():
    return jsonify(status="ok", network_access="local-only")


if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    app.run(host=host, port=port, debug=False)
