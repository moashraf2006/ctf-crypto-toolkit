from flask import Flask, jsonify, render_template, request
import base64, binascii, hashlib, hmac, ipaddress, os, re, urllib.parse, uuid

try:
    from Crypto.Cipher import AES, DES, DES3
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    AES = DES = DES3 = None
    pad = unpad = None

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024


def text(value):
    return '' if value is None else str(value)


def decode_bytes(value, encoding='utf8'):
    value = text(value).strip()
    if encoding in ('hex', 'hexadecimal'):
        return bytes.fromhex(value.replace(' ', ''))
    if encoding in ('base64', 'b64'):
        return base64.b64decode(value, validate=True)
    return value.encode('utf-8')


def encode_bytes(value, encoding='utf8'):
    if encoding in ('hex', 'hexadecimal'):
        return value.hex()
    if encoding in ('base64', 'b64'):
        return base64.b64encode(value).decode()
    return value.decode('utf-8', errors='replace')


def caesar(value, shift):
    out = []
    for ch in value:
        if ch.isalpha() and ch.isascii():
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return ''.join(out)


def vigenere(value, key, decrypt=False):
    key = ''.join(x for x in key.upper() if x.isalpha())
    if not key:
        raise ValueError('Vigenere key is required')
    out, index = [], 0
    for ch in value:
        if ch.isalpha() and ch.isascii():
            shift = ord(key[index % len(key)]) - 65
            if decrypt: shift = -shift
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base + shift) % 26 + base)); index += 1
        else: out.append(ch)
    return ''.join(out)


def xor_bytes(data, key):
    if not key: raise ValueError('XOR key is required')
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def morse_decode(value):
    table = dict(zip('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', ['.-','-...','-.-.','-..','.','..-.','--.','....','..','.---','-.-','.-..','--','-.','---','.--.','--.-','.-.','...','-','..-','...-','.--','-..-','-.--','--..','-----','.----','..---','...--','....-','.....','-....','--...','---..','----.']))
    reverse = {v:k for k,v in table.items()}
    return ' '.join(''.join(reverse.get(x.upper(), '?') for x in word.split()) for word in re.split(r'\s{2,}|/', value.strip()))


def cipher_transform(data):
    if AES is None: raise ValueError('Install dependencies with pip install -r requirements.txt')
    algorithm, mode, operation = data.get('algorithm','AES'), data.get('mode','CBC'), data.get('operation','encrypt')
    enc = data.get('input_encoding','utf8'); key = decode_bytes(data.get('key',''), enc); raw = decode_bytes(data.get('input',''), enc)
    iv = decode_bytes(data.get('iv',''), enc) if text(data.get('iv')) else None
    if algorithm == 'AES': cls, size, valid = AES, 16, (16,24,32)
    elif algorithm == 'DES': cls, size, valid = DES, 8, (8,)
    elif algorithm == '3DES': cls, size, valid = DES3, 8, (16,24)
    else: raise ValueError('Unsupported algorithm')
    if len(key) not in valid: raise ValueError(f'Invalid {algorithm} key length')
    if mode == 'CBC':
        if iv is None or len(iv) != size: raise ValueError(f'{algorithm} CBC requires a {size}-byte IV')
        cipher = cls.new(key, cls.MODE_CBC, iv)
    elif mode == 'ECB': cipher = cls.new(key, cls.MODE_ECB)
    else: raise ValueError('Only CBC and ECB are available')
    padding = data.get('padding','pkcs7')
    if operation == 'encrypt':
        if padding == 'pkcs7': raw = pad(raw, size)
        elif padding == 'zeros': raw += b'\0' * ((-len(raw)) % size)
        elif padding == 'none' and len(raw) % size: raise ValueError('Input is not block aligned')
        result = cipher.encrypt(raw)
    elif operation == 'decrypt':
        if len(raw) % size: raise ValueError('Ciphertext is not block aligned')
        result = cipher.decrypt(raw)
        if padding == 'pkcs7': result = unpad(result, size)
        elif padding == 'zeros': result = result.rstrip(b'\0')
    else: raise ValueError('Invalid operation')
    return encode_bytes(result, data.get('output_encoding','base64'))


COMMANDS = {
    'nmap': {'description':'Network discovery for an explicitly authorized lab target.','template':'nmap {ports} {service} {scripts} {target}','fields':{'target':'TARGET','ports':'-p-','service':'-sV','scripts':'-sC'}},
    'curl': {'description':'Make an HTTP request and inspect the response.','template':'curl {headers} {url}','fields':{'url':'http://127.0.0.1:5000','headers':'-i'}},
    'ffuf': {'description':'Content discovery against an authorized web lab.','template':'ffuf -u {url}/FUZZ -w {wordlist} -mc {status}','fields':{'url':'http://127.0.0.1:5000','wordlist':'wordlist.txt','status':'200,204,301,302,307,401,403'}},
    'gobuster': {'description':'Directory enumeration against an authorized web lab.','template':'gobuster dir -u {url} -w {wordlist} -x {extensions}','fields':{'url':'http://127.0.0.1:5000','wordlist':'wordlist.txt','extensions':'php,txt,html'}},
    'strings': {'description':'Extract printable strings from a local artifact.','template':'strings -n {length} {file}','fields':{'file':'sample.bin','length':'6'}},
    'readelf': {'description':'Inspect ELF metadata locally.','template':'readelf -a {file}','fields':{'file':'binary'}},
    'objdump': {'description':'Disassemble or inspect a local object file.','template':'objdump -d -M intel {file}','fields':{'file':'binary'}},
    'openssl': {'description':'Perform a local OpenSSL AES operation with explicit parameters.','template':'openssl enc -aes-256-cbc -K {key} -iv {iv} -in {input} -out {output}','fields':{'key':'KEY_HEX','iv':'IV_HEX','input':'input.bin','output':'output.bin'}},
    'grep': {'description':'Search local text or source files.','template':'grep -Rni -- {pattern} {path}','fields':{'pattern':'pattern','path':'.'}},
    'tshark': {'description':'Inspect a local capture file.','template':'tshark -r {file} -Y {filter}','fields':{'file':'capture.pcapng','filter':'http'}},
    'hashcat': {'description':'Password-recovery command reference for an authorized lab hash.','template':'hashcat -m {mode} -a 0 {hashfile} {wordlist}','fields':{'mode':'0','hashfile':'hashes.txt','wordlist':'wordlist.txt'}},
    'john': {'description':'Password-recovery command reference for an authorized lab hash.','template':'john --wordlist={wordlist} {hashfile}','fields':{'wordlist':'wordlist.txt','hashfile':'hashes.txt'}}
}


def assistant(message):
    q = text(message).lower()
    if any(x in q for x in ('command','kali','bash','nmap','ffuf','gobuster')): return 'Use the Kali reference tab. It generates commands but never executes them. Only run them against systems and ranges you are authorized to test.'
    if 'base64' in q: return "Base64 is encoding, not encryption. Decode it first; Kali: printf '%s' 'VALUE' | base64 -d"
    if 'aes' in q or 'cipher' in q: return 'For AES, identify key bytes, IV bytes, mode, and padding. CBC needs a block-sized IV. The same parameters must be used for decryption.'
    if 'hash' in q: return 'A hash is not decrypted. Compare a calculated digest, or use an authorized challenge wordlist when appropriate.'
    if 'vigenere' in q: return 'Vigenere uses a repeating alphabetic key. Select Vigenere in the Workbench and try a challenge hint as the key.'
    if 'file' in q or 'pcap' in q: return 'Keep sensitive artifacts local. Use file, sha256sum, strings, xxd, readelf, exiftool, or tshark manually; this app does not upload or execute them.'
    return 'I am an offline CTF assistant. Ask about encodings, Vigenere, AES, hashes, files, CIDR, JWT structure, or Kali command references.'


@app.get('/')
def index(): return render_template('index.html')

@app.post('/api/transform')
def transform():
    try:
        d = request.get_json(force=True, silent=True) or {}; tool = d.get('tool'); value = text(d.get('input'))
        if tool == 'base64-encode': result = base64.b64encode(value.encode()).decode()
        elif tool == 'base64-decode': result = base64.b64decode(value, validate=True).decode('utf8','replace')
        elif tool == 'hex-encode': result = value.encode().hex()
        elif tool == 'hex-decode': result = bytes.fromhex(value.replace(' ','')).decode('utf8','replace')
        elif tool == 'url-encode': result = urllib.parse.quote(value, safe='')
        elif tool == 'url-decode': result = urllib.parse.unquote(value)
        elif tool == 'morse-decode': result = morse_decode(value)
        elif tool == 'rot13': result = caesar(value,13)
        elif tool == 'rot47': result = ''.join(chr(33+(ord(c)-33+47)%94) if 33<=ord(c)<=126 else c for c in value)
        elif tool == 'atbash': result = ''.join(chr((ord('Z') if c.isupper() else ord('z'))-(ord(c)-(ord('A') if c.isupper() else ord('a')))) if c.isalpha() and c.isascii() else c for c in value)
        elif tool == 'caesar': result = caesar(value,int(d.get('shift',3)))
        elif tool == 'vigenere': result = vigenere(value,d.get('key',''),d.get('operation')=='decrypt')
        elif tool == 'xor': result = encode_bytes(xor_bytes(decode_bytes(value,d.get('input_encoding','utf8')),decode_bytes(d.get('key',''),d.get('key_encoding','utf8'))),d.get('output_encoding','utf8'))
        elif tool == 'hash': result = hashlib.new(d.get('algorithm','sha256'),value.encode()).hexdigest()
        elif tool == 'hmac': result = hmac.new(decode_bytes(d.get('key',''),d.get('key_encoding','utf8')),value.encode(),d.get('algorithm','sha256')).hexdigest()
        elif tool == 'cipher': result = cipher_transform(d)
        else: raise ValueError('Unknown tool')
        return jsonify(result=result)
    except (ValueError, binascii.Error, UnicodeError) as exc: return jsonify(error=str(exc)),400

@app.post('/api/chat')
def chat():
    d=request.get_json(force=True,silent=True) or {}; message=text(d.get('message'))[:4000]
    return jsonify(reply=assistant(message)) if message else (jsonify(error='Enter a message'),400)

@app.get('/api/commands')
def commands(): return jsonify(commands=COMMANDS)

@app.get('/api/health')
def health(): return jsonify(status='ok',network_access='local-only')

if __name__ == '__main__': app.run(host=os.getenv('HOST','127.0.0.1'),port=int(os.getenv('PORT','5000')),debug=False)
