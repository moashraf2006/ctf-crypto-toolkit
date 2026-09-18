const $ = id => document.getElementById(id);
const tool = $('tool');
function renderOptions() {
  const t = tool.value;
  if (t === 'xor') $('options').innerHTML = '<input id="key" placeholder="XOR key"><select id="key_encoding"><option value="utf8">Key UTF-8</option><option value="hex">Key hex</option><option value="base64">Key Base64</option></select><select id="input_encoding"><option value="utf8">Input UTF-8</option><option value="hex">Input hex</option><option value="base64">Input Base64</option></select><select id="output_encoding"><option value="utf8">Output UTF-8</option><option value="hex">Output hex</option><option value="base64">Output Base64</option></select>';
  else if (t === 'hash') $('options').innerHTML = '<select id="algorithm"><option>sha256</option><option>md5</option><option>sha1</option><option>sha512</option><option>sha3_256</option></select>';
  else if (t === 'cipher') $('options').innerHTML = '<select id="algorithm"><option>AES</option><option>DES</option><option>3DES</option></select><select id="operation"><option value="encrypt">Encrypt</option><option value="decrypt">Decrypt</option></select><select id="mode"><option>CBC</option><option>ECB</option></select><input id="key" placeholder="Key (hex/base64)"><input id="iv" placeholder="IV (hex/base64; required for CBC)"><select id="input_encoding"><option value="base64">Input/key/IV Base64</option><option value="hex">Input/key/IV hex</option><option value="utf8">Input/key/IV UTF-8</option></select><select id="output_encoding"><option value="base64">Output Base64</option><option value="hex">Output hex</option><option value="utf8">Output UTF-8</option></select><select id="padding"><option value="pkcs7">PKCS#7</option><option value="zeros">Zero padding</option><option value="none">None</option></select>';
  else $('options').innerHTML = '';
}
function val(id, fallback) { const e = $(id); return e ? e.value : fallback; }
tool.addEventListener('change', renderOptions); renderOptions();
$('run').addEventListener('click', async () => {
  $('status').textContent = 'Working…'; $('output').value = '';
  const body = {tool: tool.value, input: $('input').value, key: val('key',''), iv: val('iv',''), algorithm: val('algorithm','sha256'), operation: val('operation','encrypt'), mode: val('mode','CBC'), padding: val('padding','pkcs7'), key_encoding: val('key_encoding','utf8'), input_encoding: val('input_encoding','utf8'), output_encoding: val('output_encoding','utf8')};
  try { const r = await fetch('/api/transform', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)}); const j = await r.json(); if (!r.ok) throw new Error(j.error || 'Request failed'); $('output').value = j.result; $('status').textContent = 'Done'; } catch (e) { $('status').textContent = e.message; }
});
