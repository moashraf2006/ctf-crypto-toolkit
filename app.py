from flask import Flask, jsonify, render_template, request
import base64
import binascii
import hashlib
import hmac
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
    if encoding == "hex":
        return bytes.fromhex(value.replace(" ", ""))
    if encoding == "base64":
        return base64.b64decode(value, validate=True)
    return value.encode("utf-8")


def encode_bytes(value, encoding):
    if encoding == "hex":
        return value.hex()
    if encoding == "base64":
        return base64.b64encode(value).decode()
    return value.decode("utf-8", errors="replace")


def require_crypto():
    if AES is None:
        raise ValueError("Install cryptography dependencies with: pip install -r requirements.txt")


def crypt_transform(mode, algorithm, key, iv, padding, input_encoding, output_encoding):
    require_crypto()
    key_bytes = decode_bytes(key, input_encoding)
    iv_bytes = decode_bytes(iv, input_encoding) if text_input(iv) else None
    raw = decode_bytes(request.json.get("input", ""), input_encoding)
    if algorithm == "AES":
        if len(key_bytes) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes")
        cipher_cls, block_size = AES, AES.block_size
    elif algorithm == "DES":
        if len(key_bytes) != 8:
            raise ValueError("DES key must be 8 bytes")
        cipher_cls, block_size = DES, DES.block_size
    else:
        if len(key_bytes) not in (16, 24):
            raise ValueError("3DES key must be 16 or 24 bytes")
        cipher_cls, block_size = DES3, DES3.block_size
    if mode not in ("CBC", "ECB"):
        raise ValueError("Only CBC and ECB are supported for this classic CTF tool")
    if mode == "CBC":
        if iv_bytes is None or len(iv_bytes) != block_size:
            raise ValueError(f"{algorithm} CBC requires an IV of {block_size} bytes")
        cipher = cipher_cls.new(key_bytes, cipher_cls.MODE_CBC, iv_bytes)
    else:
        cipher = cipher_cls.new(key_bytes, cipher_cls.MODE_ECB)
    if mode == "ECB" and iv_bytes:
        pass
    if padding == "pkcs7":
        if mode == "ECB" or mode == "CBC":
            raw = pad(raw, block_size) if mode else raw
    elif padding == "zeros" and len(raw) % block_size:
        raw += b"\0" * (block_size - len(raw) % block_size)
    elif padding == "none" and len(raw) % block_size:
        raise ValueError("Input length must be a multiple of the block size with no padding")
    if mode == "CBC" or mode == "ECB":
        result = cipher.encrypt(raw) if mode in ("CBC", "ECB") and request.json.get("operation") == "encrypt" else cipher.decrypt(raw)
    if request.json.get("operation") == "decrypt" and padding == "pkcs7":
        result = unpad(result, block_size)
    elif request.json.get("operation") == "decrypt" and padding == "zeros":
        result = result.rstrip(b"\0")
    return encode_bytes(result, output_encoding)


def decode_morse(value):
    table = {".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F","--.":"G","....":"H","..":"I",".---":"J","-.-":"K",".-..":"L","--":"M","-.":"N","---":"O",".--.":"P","--.-":"Q",".-.":"R","...":"S","-":"T","..-":"U","...-":"V",".--":"W","-..-":"X","-.--":"Y","--..":"Z","-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",".....":"5","-....":"6","--...":"7","---..":"8","----.":"9"}
    return " ".join("".join(table.get(token.upper(), "?") for token in word.split()) for word in re.split(r"\s{2,}|/", value.strip()))


def brainfuck(source):
    code = re.sub(r"[^<>+\-.,\[\]]", "", source)
    cells, pointer, pc, output, stack = [0] * 30000, 0, 0, [], []
    jumps, pending = {}, []
    for index, char in enumerate(code):
        if char == "[": pending.append(index)
        elif char == "]":
            if not pending: raise ValueError("Unmatched ] in Brainfuck input")
            left = pending.pop(); jumps[left] = index; jumps[index] = left
    if pending: raise ValueError("Unmatched [ in Brainfuck input")
    steps = 0
    while pc < len(code):
        steps += 1
        if steps > 1_000_000: raise ValueError("Execution limit exceeded")
        char = code[pc]
        if char == ">": pointer = (pointer + 1) % len(cells)
        elif char == "<": pointer = (pointer - 1) % len(cells)
        elif char == "+": cells[pointer] = (cells[pointer] + 1) % 256
        elif char == "-": cells[pointer] = (cells[pointer] - 1) % 256
        elif char == ".": output.append(chr(cells[pointer]))
        elif char == "[" and cells[pointer] == 0: pc = jumps[pc]
        elif char == "]" and cells[pointer] != 0: pc = jumps[pc]
        pc += 1
    return "".join(output)


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/transform")
def transform():
    try:
        data = request.get_json(force=True) or {}
        tool = data.get("tool")
        value = text_input(data.get("input"))
        if tool == "base64-encode": result = base64.b64encode(value.encode()).decode()
        elif tool == "base64-decode": result = base64.b64decode(value, validate=True).decode("utf-8", errors="replace")
        elif tool == "hex-encode": result = value.encode().hex()
        elif tool == "hex-decode": result = bytes.fromhex(value.replace(" ", "")).decode("utf-8", errors="replace")
        elif tool == "url-encode": result = urllib.parse.quote(value, safe="")
        elif tool == "url-decode": result = urllib.parse.unquote(value)
        elif tool == "morse-decode": result = decode_morse(value)
        elif tool == "brainfuck": result = brainfuck(value)
        elif tool == "xor":
            key = decode_bytes(data.get("key"), data.get("key_encoding", "utf8"))
            if not key: raise ValueError("XOR key cannot be empty")
            raw = decode_bytes(value, data.get("input_encoding", "utf8"))
            result = encode_bytes(bytes(b ^ key[i % len(key)] for i, b in enumerate(raw)), data.get("output_encoding", "utf8"))
        elif tool == "hash":
            algorithm = data.get("algorithm", "sha256").lower()
            if algorithm not in hashlib.algorithms_available: raise ValueError("Unsupported hash algorithm")
            result = hashlib.new(algorithm, value.encode()).hexdigest()
        elif tool == "cipher":
            result = crypt_transform(data.get("mode", "CBC"), data.get("algorithm", "AES"), data.get("key"), data.get("iv"), data.get("padding", "pkcs7"), data.get("input_encoding", "utf8"), data.get("output_encoding", "base64"))
        else: raise ValueError("Unknown tool")
        return jsonify(result=result)
    except (ValueError, binascii.Error, UnicodeError) as exc:
        return jsonify(error=str(exc)), 400


@app.get("/api/health")
def health():
    return jsonify(status="ok", network_access="not used")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
