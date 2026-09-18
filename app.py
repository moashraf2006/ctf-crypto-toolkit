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
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024


def text_input(value):
    return '' if value is None else str(value)


def decode_bytes(value, encoding):
    value = text_input(value).strip()
    if not value:
        return b''
    if encoding in ('hex', 'hexadecimal'):
        return bytes.fromhex(value.replace(' ', ''))
    if encoding in ('base64', 'b64'):
        return base64.b64decode(value, validate=True)
    if encoding in ('utf8', 'utf-8', 'utf_8', 'text'):
        return value.encode('utf-8')
    raise ValueError(f'Unsupported encoding: {encoding}')


def encode_bytes(value, encoding):
    if encoding in ('hex', 'hexadecimal'):
        return value.hex()
    if encoding in ('base64', 'b64'):
        return base64.b64encode(value).decode('ascii')
    return value.decode('utf-8', errors='replace')


def crypt_transform(mode, algorithm, key, iv, padding, input_encoding, output_encoding, raw_input, operation):
    if AES is None:
        raise ValueError('Missing crypto dependency. Run: pip install -r requirements.txt')
    key_bytes = decode_bytes(key, input_encoding)
    iv_bytes = decode_bytes(iv, input_encoding) if text_input(iv) else None
    raw = decode_bytes(raw_input, input_encoding)
    if algorithm == 'AES':
        if len(key_bytes) not in (16, 24, 32): raise ValueError('AES key must be 16, 24, or 32 bytes')
        cipher_cls, block_size = AES, AES.block_size
    elif algorithm == 'DES':
        if len(key_bytes) != 8: raise ValueError('DES key must be 8 bytes')
        cipher_cls, block_size = DES, DES.block_size
    elif algorithm == '3DES':
        if len(key_bytes) not in (16, 24): raise ValueError('3DES key must be 16 or 24 bytes')
        cipher_cls, block_size = DES3, DES3.block_size
    else: raise ValueError('Unsupported algorithm')
    if mode not in ('CBC', 'ECB'): raise ValueError('Only CBC and ECB are supported')
    if mode == 'CBC':
        if iv_bytes is None or len(iv_bytes) != block_size: raise ValueError(f'{algorithm} CBC requires an IV of {block_size} bytes')
        cipher = cipher_cls.new(key_bytes, cipher_cls.MODE_CBC, iv_bytes)
    else: cipher = cipher_cls.new(key_bytes, cipher_cls.MODE_ECB)
    if padding == 'pkcs7': raw = pad(raw, block_size)
    elif padding == 'zeros': raw += b'\0' * ((-len(raw)) % block_size)
    elif padding == 'none' and len(raw) % block_size: raise ValueError('Input length must be a multiple of the block size')
    if operation == 'encrypt': result = cipher.encrypt(raw)
    elif operation == 'decrypt':
        result = cipher.decrypt(raw)
        if padding == 'pkcs7': result = unpad(result, block_size)
        elif padding == 'zeros': result = result.rstrip(b'\0')
    else: raise ValueError('Operation must be encrypt or decrypt')
    return encode_bytes(result, output_encoding)


def morse(value):
    table = dict(zip('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', ['.-','-...','-.-.','-..','.','..-.','--.','....','..','.---','-.-','.-..','--','-.','---','.--.','--.-','.-.','...','-','..-','...-','.--','-..-','-.--','--..','-----','.----','..---','...--','....-','.....','-....','--...','---..','----.']))
    reverse = {v: k for k, v in table.items()}
    return ' '.join(''.join(reverse.get(x.upper(), '?') for x in word.split()) for word in re.split(r'\s{2,}|/', value.strip()))


def brainfuck(source):
    code = re.sub(r'[^<>+\-.,\[\]]', '', source); cells = [0] * 30000; pointer = pc = 0; output = []; jumps = {}; stack = []
    for i, ch in enumerate(code):
        if ch == '[': stack.append(i)
        elif ch == ']':
            if not stack: raise ValueError('Unmatched ]')
            left = stack.pop(); jumps[left] = i; jumps[i] = left
    if stack: raise ValueError('Unmatched [')
    for steps in range(1000001):
        if pc >= len(code): return ''.join(output)
        ch = code[pc]
        if ch == '>': pointer = (pointer + 1) % len(cells)
        elif ch == '<': pointer = (pointer - 1) % len(cells)
        elif ch == '+': cells[pointer] = (cells[pointer] + 1) % 256
        elif ch == '-': cells[pointer] = (cells[pointer] - 1) % 256
        elif ch == '.': output.append(chr(cells[pointer]))
        elif ch == '[' and cells[pointer] == 0: pc = jumps[pc]
        elif ch == ']' and cells[pointer] != 0: pc = jumps[pc]
        pc += 1
    raise ValueError('Brainfuck execution limit exceeded')


BASH_REFERENCE = {
    'files': ['pwd', 'ls -la', 'find . -type f -maxdepth 2', 'file ./sample', 'stat ./sample', 'strings -n 6 ./sample'],
    'text': ["grep -Rni 'pattern' .", "awk '{print $1}' file", "cut -d: -f1 file", "sort -u file", 'wc -c file', 'tr -d "\\n" < file'],
    'encoding': ["printf '%s' 'text' | base64", "printf '%s' 'BASE64' | base64 -d", "printf '%s' 'text' | xxd -p", "printf '%s' 'HEX' | xxd -r -p", "python3 -c \"import urllib.parse; print(urllib.parse.unquote('VALUE'))\""],
    'crypto': ["printf '%s' 'text' | sha256sum", "printf '%s' 'text' | md5sum", 'openssl enc -aes-256-cbc -K KEY_HEX -iv IV_HEX -in input -out output', 'openssl rand -hex 16'],
    'network': ['curl -I http://127.0.0.1:5000', 'curl -s http://127.0.0.1:5000/api/health', 'ss -tulpen', 'dig example.org'],
    'archives': ['unzip -l file.zip', 'tar -tvf file.tar', '7z l file.7z', 'binwalk file'],
    'analysis': ['sha256sum file', 'exiftool file', 'xxd -g 1 -l 64 file', 'readelf -h binary', 'checksec --file=binary']
}


def assistant_reply(message):
    q = message.lower().strip()
    if any(x in q for x in ('bash', 'linux command', 'kali command', 'command reference')):
        return 'Here are safe, read-only or local CTF commands by category:\n\n' + '\n'.join(f'[{k}]\n' + '\n'.join(v) for k, v in BASH_REFERENCE.items())
    if 'base64' in q: return "Use Base64 Decode in the toolkit. Kali: printf '%s' 'VALUE' | base64 -d"
    if 'hex' in q: return "Use Hex Decode. Kali: printf '%s' 'HEX' | xxd -r -p"
    if 'morse' in q: return 'Select Morse decode and separate letters with spaces; separate words with two spaces or /. '
    if 'brainfuck' in q: return 'Select Brainfuck decode. The evaluator is local and capped at one million steps.'
    if 'aes' in q or 'cipher' in q: return 'For AES, specify the key and IV encoding, mode, operation, and padding. CBC needs a block-sized IV; the tool does not guess missing cryptographic parameters.'
    if 'hash' in q: return 'Hashes are one-way. Select Hash to calculate a digest; decryption is not possible without a weakness, dictionary, or authorized challenge context.'
    return 'I am a local CTF helper. Ask about Base64, hex, URL encoding, XOR, Morse, Brainfuck, hashes, AES/DES, or say “show Kali commands”. Paste ciphertext in the Transform panel for decoding.'


@app.get('/')
def index(): return render_template('index.html')


@app.post('/api/transform')
def transform():
    try:
        data = request.get_json(force=True, silent=True) or {}; tool = data.get('tool'); value = text_input(data.get('input'))
        if tool == 'base64-encode': result = base64.b64encode(value.encode()).decode()
        elif tool == 'base64-decode': result = base64.b64decode(value, validate=True).decode('utf-8', errors='replace')
        elif tool == 'hex-encode': result = value.encode().hex()
        elif tool == 'hex-decode': result = bytes.fromhex(value.replace(' ', '')).decode('utf-8', errors='replace')
        elif tool == 'url-encode': result = urllib.parse.quote(value, safe='')
        elif tool == 'url-decode': result = urllib.parse.unquote(value)
        elif tool == 'morse-decode': result = morse(value)
        elif tool == 'brainfuck': result = brainfuck(value)
        elif tool == 'xor':
            key = decode_bytes(data.get('key', ''), data.get('key_encoding', 'utf8'))
            if not key: raise ValueError('XOR key cannot be empty')
            raw = decode_bytes(value, data.get('input_encoding', 'utf8')); result = encode_bytes(bytes(b ^ key[i % len(key)] for i, b in enumerate(raw)), data.get('output_encoding', 'utf8'))
        elif tool == 'hash':
            algorithm = data.get('algorithm', 'sha256').lower(); result = hashlib.new(algorithm, value.encode()).hexdigest()
        elif tool == 'cipher': result = crypt_transform(data.get('mode','CBC'), data.get('algorithm','AES'), data.get('key',''), data.get('iv',''), data.get('padding','pkcs7'), data.get('input_encoding','utf8'), data.get('output_encoding','base64'), value, data.get('operation','encrypt'))
        else: raise ValueError(f'Unknown tool: {tool}')
        return jsonify(result=result)
    except (ValueError, binascii.Error, UnicodeError) as exc: return jsonify(error=str(exc)), 400


@app.post('/api/chat')
def chat():
    data = request.get_json(force=True, silent=True) or {}
    message = text_input(data.get('message'))[:4000]
    if not message: return jsonify(error='Enter a question or command.'), 400
    return jsonify(reply=assistant_reply(message))


@app.get('/api/health')
def health(): return jsonify(status='ok', network_access='local-only')


if __name__ == '__main__':
    app.run(host=os.getenv('HOST', '127.0.0.1'), port=int(os.getenv('PORT', '5000')), debug=False)
