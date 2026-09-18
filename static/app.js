const $ = id => document.getElementById(id);
const tool = $('tool');

function val(id, fallback) {
  const el = $(id);
  return el ? el.value : fallback;
}

function renderOptions() {
  const t = tool.value;

  if (t === 'xor') {
    $('options').innerHTML = `
      <input id="key" placeholder="XOR key">
      <select id="key_encoding">
        <option value="utf8">Key UTF-8</option>
        <option value="hex">Key hex</option>
        <option value="base64">Key Base64</option>
      </select>
      <select id="input_encoding">
        <option value="utf8">Input UTF-8</option>
        <option value="hex">Input hex</option>
        <option value="base64">Input Base64</option>
      </select>
      <select id="output_encoding">
        <option value="utf8">Output UTF-8</option>
        <option value="hex">Output hex</option>
        <option value="base64">Output Base64</option>
      </select>
    `;
  } else if (t === 'hash') {
    $('options').innerHTML = `
      <select id="algorithm">
        <option>sha256</option>
        <option>md5</option>
        <option>sha1</option>
        <option>sha512</option>
        <option>sha3_256</option>
      </select>
    `;
  } else if (t === 'cipher') {
    $('options').innerHTML = `
      <select id="algorithm">
        <option>AES</option>
        <option>DES</option>
        <option>3DES</option>
      </select>
      <select id="operation">
        <option value="encrypt">Encrypt</option>
        <option value="decrypt">Decrypt</option>
      </select>
      <select id="mode">
        <option>CBC</option>
        <option>ECB</option>
      </select>
      <input id="key" placeholder="Key">
      <input id="iv" placeholder="IV (required for CBC)">
      <select id="input_encoding">
        <option value="base64">Input/key/IV Base64</option>
        <option value="hex">Input/key/IV hex</option>
        <option value="utf8">Input/key/IV UTF-8</option>
      </select>
      <select id="output_encoding">
        <option value="base64">Output Base64</option>
        <option value="hex">Output hex</option>
        <option value="utf8">Output UTF-8</option>
      </select>
      <select id="padding">
        <option value="pkcs7">PKCS#7</option>
        <option value="zeros">Zero padding</option>
        <option value="none">None</option>
      </select>
    `;
  } else if (t === 'caesar') {
    $('options').innerHTML = `
      <input id="shift" value="3" placeholder="Shift">
    `;
  } else {
    $('options').innerHTML = '';
  }
}

tool.addEventListener('change', renderOptions);
renderOptions();

async function runTransform() {
  $('status').textContent = 'Working...';
  $('output').value = '';

  const body = {
    tool: tool.value,
    input: $('input').value,
    key: val('key', ''),
    iv: val('iv', ''),
    algorithm: val('algorithm', 'sha256'),
    operation: val('operation', 'encrypt'),
    mode: val('mode', 'CBC'),
    padding: val('padding', 'pkcs7'),
    key_encoding: val('key_encoding', 'utf8'),
    input_encoding: val('input_encoding', 'utf8'),
    output_encoding: val('output_encoding', 'utf8'),
    shift: val('shift', '3')
  };

  try {
    const r = await fetch('/api/transform', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const j = await r.json();

    if (!r.ok) {
      throw new Error(j.error || 'Request failed');
    }

    $('output').value = j.result;
    $('status').textContent = 'Done';
  } catch (e) {
    $('status').textContent = e.message;
  }
}

$('run').addEventListener('click', runTransform);

function addChatMessage(text, who) {
  const el = document.createElement('div');
  el.className = 'msg ' + who;
  el.textContent = text;
  $('chat').appendChild(el);
  $('chat').scrollTop = $('chat').scrollHeight;
}

async function askAssistant() {
  const message = $('message').value.trim();
  if (!message) return;

  addChatMessage(message, 'user');
  $('message').value = '';

  try {
    const r = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message })
    });

    const j = await r.json();
    if (!r.ok) throw new Error(j.error || 'Request failed');

    addChatMessage(j.reply, 'bot');
  } catch (e) {
    addChatMessage('Error: ' + e.message, 'bot');
  }
}

$('ask').addEventListener('click', askAssistant);
$('message').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') askAssistant();
});

async function autoDecode() {
  const value = $('autodecode-input').value.trim();
  if (!value) {
    $('autodecode-results').innerHTML = '<div class="result-item">Enter ciphertext first.</div>';
    return;
  }

  try {
    const r = await fetch('/api/autodecode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: value })
    });

    const j = await r.json();
    if (!r.ok) throw new Error(j.error || 'Request failed');

    const list = j.results || [];
    if (!list.length) {
      $('autodecode-results').innerHTML = '<div class="result-item">No likely interpretation found.</div>';
      return;
    }

    $('autodecode-results').innerHTML = list.map(item => `
      <div class="result-item">
        <strong>${item.type}</strong>
        <pre>${item.result}</pre>
      </div>
    `).join('');
  } catch (e) {
    $('autodecode-results').innerHTML = '<div class="result-item">' + e.message + '</div>';
  }
}

$('autodecode-btn').addEventListener('click', autoDecode);
