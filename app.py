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
except ImportError:  # pragma: no cover
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
    if encoding in ("utf8", "utf-8", "utf_8", "text"):
        return value.encode("utf-8")
    raise ValueError(f"Unsupported encoding: {encoding}")


def encode_bytes(value, encoding):
    if encoding in ("hex", "hexadecimal"):
        return value.hex()
    if encoding in ("base64", "b64"):
        return base64.b64encode(value).decode("ascii")
    if encoding in ("utf8", "utf-8", "utf_8", "text"):
        return value.decode("utf-8", errors="replace")
    raise ValueError(f"Unsupported output encoding: {encoding}")


def require_crypto():
    if AES is None:
        raise ValueError("Missing crypto dependency. Run: pip install -r requirements.txt")


def normalize_input(raw, encoding):
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    return decode_bytes(raw, encoding)


def crypt_transform(mode, algorithm, key, iv, padding, input_encoding, output_encoding, raw_input, operation):
    require_crypto()
    key_bytes = normalize_input(key, input_encoding)
    iv_bytes = normalize_input(iv, input_encoding) if text_input(iv) else None
    raw = normalize_input(raw_input, input_encoding)

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
        raise ValueError("Unsupported algorithm: choose AES, DES, or 3DES")

    if mode not in ("CBC", "ECB"):
        raise ValueError("Only CBC and ECB are supported in this toolkit")

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
            raise ValueError("Input length must be a multiple of the block size when padding=none")
    else:
        raise ValueError("Unsupported padding mode: pkcs7, zeros, or none")

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


def decode_morse(value):
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
    normalized = value.strip()
    if not normalized:
        return ""
    words = re.split(r"\s{2,}|/", normalized)
    out = []
    for word in words:
        chars = word.split()
        decoded_chars = []
        for token in chars:
            decoded_chars.append(table.get(token.upper(), "?"))
        out.append("".join(decoded_chars))
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
        elif tool == "morse-decode":
            result = decode_morse(value)
        elif tool == "brainfuck":
            result = brainfuck(value)
        elif tool == "xor":
            key = decode_bytes(data.get("key", ""), data.get("key_encoding", "utf8"))
            if not key:
                raise ValueError("XOR key cannot be empty")
            raw = decode_bytes(value, data.get("input_encoding", "utf8"))
            result = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
            result = encode_bytes(result, data.get("output_encoding", "utf8"))
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


@app.get("/api/health")
def health():
    return jsonify(status="ok", network_access="local-only")


if __name__ == "__main__":
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    app.run(host=host, port=port, debug=False)
