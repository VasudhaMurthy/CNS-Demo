// app.js — Full demo logic (ready-to-use)
// - Shows keys/shifts/public keys only in algorithm panels
// - Hacker can intercept, edit, forward raw, or drop messages when allowed
// - Enforces policy: hacker edit/drop UI disabled when attacker can't actually read/tamper
// - Algorithms: Plain, Caesar, AES, RSA, Diffie–Hellman
// - Dynamically loads CryptoJS and JSEncrypt if not present

/* ===================== Crypto helpers ===================== */
function caesarEncrypt(text, shift) {
  shift = Number(shift) || 0;
  return text.split('').map(c => {
    const code = c.charCodeAt(0);
    if (code >= 65 && code <= 90) return String.fromCharCode(((code - 65 + shift) % 26) + 65);
    if (code >= 97 && code <= 122) return String.fromCharCode(((code - 97 + shift) % 26) + 97);
    return c;
  }).join('');
}
function caesarDecrypt(text, shift) { return caesarEncrypt(text, 26 - (Number(shift) || 0)); }
function aesEncrypt(text, pass) { return CryptoJS.AES.encrypt(text, pass).toString(); }
function aesDecrypt(ciphertext, pass) {
  try {
    const bytes = CryptoJS.AES.decrypt(ciphertext, pass);
    const pt = bytes.toString(CryptoJS.enc.Utf8);
    return pt || null;
  } catch (e) { return null; }
}
function genRSA() { const crypt = new JSEncrypt({ default_key_size: 2048 }); return { publicKey: crypt.getPublicKey(), privateKey: crypt.getPrivateKey() }; }
function rsaEncryptWithPub(text, pub) { const enc = new JSEncrypt(); enc.setPublicKey(pub); return enc.encrypt(text); }
function rsaDecryptWithPriv(cipher, priv) { const dec = new JSEncrypt(); dec.setPrivateKey(priv); return dec.decrypt(cipher); }

/* ===================== DOM refs ===================== */
const algoSelect = document.getElementById('algoSelect');
const aliceFeed = document.getElementById('aliceFeed');
const bobFeed = document.getElementById('bobFeed');
const hackerFeed = document.getElementById('hackerFeed');

const aliceMsg = document.getElementById('aliceMsg');
const bobMsg = document.getElementById('bobMsg');

const aliceSend = document.getElementById('aliceSend');
const bobSend = document.getElementById('bobSend');

const aliceAlgoPanel = document.getElementById('aliceAlgoPanel');
const bobAlgoPanel = document.getElementById('bobAlgoPanel');
const hackerAlgoPanel = document.getElementById('hackerAlgoPanel');

/* helper accessors for hacker options (may be missing early) */
function hackInterceptChecked() { const e = document.getElementById('hackIntercept'); return e ? e.checked : false; }
function hackHasKeyChecked() { const e = document.getElementById('hackHasKey'); return e ? e.checked : false; }
function hackMitmChecked() { const e = document.getElementById('hackMitm'); return e ? e.checked : false; }

/* ===================== state ===================== */
let bobRSA = null;
let aliceRSA = null;
window._hackerMitmPriv = null;
let pendingIntercept = null; // { payload, plain, algo, from, to, deliverFn }

/* ===================== small UI helpers ===================== */
function now() { return new Date().toLocaleTimeString(); }
function escapeHtml(s) { return (s || '').toString().replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;'); }
function createBubble(text, who) {
  const el = document.createElement('div');
  el.className = 'bubble ' + who;
  el.innerHTML = `<div>${escapeHtml(text)}</div><div class="meta">${now()}</div>`;
  return el;
}
function appendAlice(msg) { const b = createBubble(msg, 'me'); aliceFeed.appendChild(b); b.classList.add('show'); aliceFeed.scrollTop = aliceFeed.scrollHeight; }
function appendBob(msg) { const b = createBubble(msg, 'me'); bobFeed.appendChild(b); b.classList.add('show'); bobFeed.scrollTop = bobFeed.scrollHeight; }
function appendHacker(msg) { const b = createBubble(msg, 'hacker'); hackerFeed.appendChild(b); b.classList.add('show'); hackerFeed.scrollTop = hackerFeed.scrollHeight; }
function appendAliceFromOther(msg) { const b = createBubble(msg, 'them'); aliceFeed.appendChild(b); b.classList.add('show'); aliceFeed.scrollTop = aliceFeed.scrollHeight; }
function appendBobFromOther(msg) { const b = createBubble(msg, 'them'); bobFeed.appendChild(b); b.classList.add('show'); bobFeed.scrollTop = bobFeed.scrollHeight; }

/* ===================== Hacker edit UI ===================== */
function ensureHackerModifyUI() {
  if (document.getElementById('hackerModifyWrapper')) {
    bindHackerButtons(); // re-bind safe
    return;
  }

  const container = hackerAlgoPanel.parentElement;
  if (!container) return;
  const wrapper = document.createElement('div');
  wrapper.id = 'hackerModifyWrapper';
  wrapper.style.padding = '12px';
  wrapper.style.borderTop = '1px solid rgba(255,255,255,0.02)';
  wrapper.style.background = 'linear-gradient(90deg,#071029,#020617)';
  wrapper.style.display = 'none'; // hidden until interception / allowed

  wrapper.innerHTML = `
    <label style="color:#cbd5e1;display:block;margin-bottom:6px;font-size:13px">Intercepted payload (editable) — modify before forwarding</label>
    <textarea id="hackerModify" rows="4" style="width:100%;border-radius:8px;padding:10px;background:linear-gradient(90deg,#071029,#020617);border:1px solid rgba(255,255,255,0.03);color:#e6eef8;font-family:ui-monospace,monospace"></textarea>
    <div style="display:flex;gap:8px;margin-top:8px">
      <button id="hackerForward" class="send-btn">Modify & Forward</button>
      <button id="hackerForwardRaw" class="send-btn secondary">Forward Unmodified</button>
      <button id="hackerDrop" class="send-btn secondary">Drop</button>
    </div>
    <div id="hackerNote" style="margin-top:8px;color:#cbd5e1;font-size:12px"></div>
  `;

  container.insertBefore(wrapper, hackerAlgoPanel);
  bindHackerButtons();
}

/* safe binding of hacker buttons (removes old handlers by node-replace) */
function bindHackerButtons() {
  const f = document.getElementById('hackerForward');
  const fr = document.getElementById('hackerForwardRaw');
  const d = document.getElementById('hackerDrop');
  if (!f || !fr || !d) return;

  const fNew = f.cloneNode(true); f.parentNode.replaceChild(fNew, f);
  const frNew = fr.cloneNode(true); fr.parentNode.replaceChild(frNew, fr);
  const dNew = d.cloneNode(true); d.parentNode.replaceChild(dNew, d);

  document.getElementById('hackerForward').addEventListener('click', () => {
    if (!pendingIntercept) { appendHacker('No intercepted message to forward.'); return; }
    const modified = document.getElementById('hackerModify').value;
    finalizeIntercept({ action: 'forward', payload: modified });
  });
  document.getElementById('hackerForwardRaw').addEventListener('click', () => {
    if (!pendingIntercept) { appendHacker('No intercepted message to forward.'); return; }
    finalizeIntercept({ action: 'forward', payload: pendingIntercept.payload });
  });
  document.getElementById('hackerDrop').addEventListener('click', () => {
    if (!pendingIntercept) { appendHacker('No intercepted message to drop.'); return; }
    finalizeIntercept({ action: 'drop' });
  });
}

/* ===================== algorithm panels (show only needed fields) ===================== */
function renderPanels() {
  const algo = algoSelect.value;
  aliceAlgoPanel.innerHTML = '';
  bobAlgoPanel.innerHTML = '';
  hackerAlgoPanel.innerHTML = '';

  // ensure hacker editor exists (but stay hidden)
  ensureHackerModifyUI();

  if (algo === 'caesar') {
    aliceAlgoPanel.innerHTML = `<div class="panel-row"><label class="small-muted">Shift</label><input id="aliceShift" class="key-input" placeholder="3"/></div>`;
    bobAlgoPanel.innerHTML = `<div class="small-muted">Bob shift (must match Alice)</div><div class="panel-row"><input id="bobShift" class="key-input" placeholder="3"/></div>`;
    hackerAlgoPanel.innerHTML = `<div class="small-muted">Hacker: brute-force or use known shift</div>`;
  } else if (algo === 'aes') {
    aliceAlgoPanel.innerHTML = `<div class="small-muted">AES passphrase (shared secret)</div><div class="panel-row"><input id="alicePass" class="key-input" placeholder="STUDY123"/></div>`;
    bobAlgoPanel.innerHTML = `<div class="small-muted">Bob passphrase</div><div class="panel-row"><input id="bobPass" class="key-input" placeholder="STUDY123"/></div>`;
    hackerAlgoPanel.innerHTML = `<div class="small-muted">Hacker: ciphertext looks random unless key leaked</div>`;
  } else if (algo === 'rsa') {
    aliceAlgoPanel.innerHTML =
      `<div class="small-muted">Recipient public key (paste here)</div>
       <div class="panel-row"><textarea id="alicePubInput" class="key-input" placeholder="-----BEGIN PUBLIC KEY-----..." rows="3"></textarea></div>
       <div class="small-muted">Alice may generate an RSA keypair</div>
       <div class="panel-row"><button id="aliceGenRSA" class="send-btn secondary">Generate Alice RSA</button></div>`;
    bobAlgoPanel.innerHTML =
      `<div class="small-muted">Bob private key (PEM)</div>
       <div class="panel-row"><textarea id="bobPrivInput" class="key-input" rows="3" placeholder="-----BEGIN RSA PRIVATE KEY-----..."></textarea></div>
       <div class="panel-row"><button id="bobGenRSA" class="send-btn secondary">Generate Bob RSA</button></div>`;
    hackerAlgoPanel.innerHTML = `<div class="small-muted">Hacker: MITM can replace public key if you don't verify</div>`;
  } else if (algo === 'dh') {
    aliceAlgoPanel.innerHTML =
      `<div class="small-muted">Diffie–Hellman demo: choose base (g) and prime (p)</div>
       <div class="panel-row"><input id="gInput" class="key-input" placeholder="g (e.g., 5)"/><input id="pInput" class="key-input" placeholder="p (prime)"/></div>`;
    bobAlgoPanel.innerHTML = `<div class="small-muted">Bob will compute shared key</div>`;
    hackerAlgoPanel.innerHTML = `<div class="small-muted">Hacker sees public values but cannot compute secret</div>`;
  } else {
    aliceAlgoPanel.innerHTML = `<div class="small-muted">No crypto — message is plaintext</div>`;
    bobAlgoPanel.innerHTML = `<div class="small-muted">Readable by anyone</div>`;
  }

  setTimeout(bindGeneratedControls, 50);
  updateHackerControls(); // enforce hacker control policy after panel render
}

function bindGeneratedControls() {
  const aliceGenRSA = document.getElementById('aliceGenRSA');
  const bobGenRSA = document.getElementById('bobGenRSA');

  if (aliceGenRSA) {
    aliceGenRSA.onclick = () => {
      aliceRSA = genRSA();
      alert('Alice RSA generated — public key populated in Alice panel.');
      const pub = document.getElementById('alicePubInput');
      if (pub) pub.value = aliceRSA.publicKey;
      updateHackerControls();
    };
  }
  if (bobGenRSA) {
    bobGenRSA.onclick = () => {
      bobRSA = genRSA();
      const priv = document.getElementById('bobPrivInput');
      if (priv) priv.value = bobRSA.privateKey;
      alert('Bob RSA generated — private key placed in Bob panel (demo).');
      updateHackerControls();
    };
  }
}

/* ===================== hacker control policy ===================== */
/*
 Policy:
 - Plaintext & Caesar: hacker may intercept, edit, drop (controls enabled)
 - AES: hacker sees ciphertext; edit/drop allowed only if Has key is checked
 - RSA: edit/drop allowed only if MITM is ON (attacker replaced pubkey) OR Has key checked
 - DH: intercept allowed (public values) but no edit/drop (disabled)
*/
function updateHackerControls() {
  const algo = algoSelect.value;
  const interceptCheckbox = document.getElementById('hackIntercept');
  const hasKeyCheckbox = document.getElementById('hackHasKey');
  const mitmCheckbox = document.getElementById('hackMitm');
  const hackerWrapper = document.getElementById('hackerModifyWrapper');
  const hackerNote = document.getElementById('hackerNote');

  let allowIntercept = true;
  let allowEditDrop = false;

  if (algo === 'plain' || algo === 'caesar') {
    allowIntercept = true;
    allowEditDrop = true;
  } else if (algo === 'aes') {
    allowIntercept = true;
    allowEditDrop = !!(hasKeyCheckbox && hasKeyCheckbox.checked);
  } else if (algo === 'rsa') {
    allowIntercept = true;
    allowEditDrop = !!((mitmCheckbox && mitmCheckbox.checked) || (hasKeyCheckbox && hasKeyCheckbox.checked));
  } else if (algo === 'dh') {
    allowIntercept = true;
    allowEditDrop = false;
  } else {
    allowIntercept = true;
    allowEditDrop = false;
  }

  // Keep intercept checkbox enabled so we can show ciphertext capture when meaningful.
  if (interceptCheckbox) {
    // Optionally hide intercept when meaningless: interceptCheckbox.disabled = !allowIntercept;
    interceptCheckbox.disabled = false;
  }

  // Show/hide or enable/disable hacker editor and buttons
  if (hackerWrapper) {
    if (!allowEditDrop) {
      // If edit/drop not allowed -> hide editor and clear any pending intercept
      hackerWrapper.style.display = 'none';
      if (hackerNote) hackerNote.textContent = 'No ability to read or modify this message.';
      pendingIntercept = null;
    } else {
      // Editor ready (but hidden until a real intercept), update note
      hackerWrapper.style.display = 'none';
      if (hackerNote) hackerNote.textContent = 'You may view and modify intercepted plaintext.';
    }
  }
}

/* ===================== interception queue & finalize ===================== */
function queueIntercept(interceptObj) {
  // interceptObj = { payload, plain, algo, from, to, deliverFn }
  pendingIntercept = interceptObj;
  ensureHackerModifyUI(); // ensure UI exists
  updateHackerControls(); // re-evaluate policy before showing

  const wrapper = document.getElementById('hackerModifyWrapper');
  const edit = document.getElementById('hackerModify');
  const hackerNote = document.getElementById('hackerNote');

  // determine if edit/drop should be allowed now (policy double-check)
  const algo = interceptObj.algo;
  const allowEdit = (algo === 'plain' || algo === 'caesar')
    || (algo === 'aes' && hackHasKeyChecked())
    || (algo === 'rsa' && (hackMitmChecked() || hackHasKeyChecked()));

  if (!allowEdit) {
    // can't show editor — show a terse note in hacker feed and forward automatically after a short delay
    appendHacker(`Captured ciphertext (${algo}) — cannot decrypt or modify without key/MITM.`);
    // provide the ciphertext snippet for teaching purposes
    appendHacker((interceptObj.payload || '').slice(0, 140) + (interceptObj.payload && interceptObj.payload.length > 140 ? '...' : ''));
    // auto-forward original payload (simulate passive capture only)
    setTimeout(() => {
      if (typeof interceptObj.deliverFn === 'function') interceptObj.deliverFn(interceptObj.payload);
      appendHacker('Forwarded captured data (no modification).');
    }, 700);
    pendingIntercept = null;
    return;
  }

  // If we reach here, edit/drop is allowed — show editor and populate
  if (edit && wrapper) {
    edit.value = interceptObj.payload || interceptObj.plain || '';
    wrapper.style.display = 'block';
    try { edit.focus(); edit.select(); } catch (e) { /* ignore */ }
  }
  appendHacker(`Intercepted message ${interceptObj.from} → ${interceptObj.to} [${interceptObj.algo}]`);
}

function finalizeIntercept(actionObj) {
  if (!pendingIntercept) return;
  const obj = pendingIntercept;
  pendingIntercept = null;

  // hide editor UI if present
  const wrapper = document.getElementById('hackerModifyWrapper');
  if (wrapper) wrapper.style.display = 'none';

  if (actionObj.action === 'drop') {
    appendHacker('Hacker dropped the message. Delivery cancelled.');
    if (obj.from === 'alice' && obj.to === 'bob') appendBobFromOther('[Message dropped in transit]');
    if (obj.from === 'bob' && obj.to === 'alice') appendAliceFromOther('[Message dropped in transit]');
    return;
  }

  const forwardPayload = actionObj.payload;
  appendHacker('Hacker forwarded message (may be modified).');

  if (typeof obj.deliverFn === 'function') obj.deliverFn(forwardPayload);
}

/* ===================== transport logic ===================== */
function transportMessage(sender) {
  const algo = algoSelect.value;

  if (sender === 'alice') {
    const plain = (aliceMsg.value || '').toString();
    if (!plain) return;
    appendAlice(plain);

    let payload = '';
    let meta = '';

    if (algo === 'plain') {
      payload = plain; meta = 'plaintext';
    } else if (algo === 'caesar') {
      const shift = document.getElementById('aliceShift')?.value || '3';
      payload = caesarEncrypt(plain, shift); meta = `Caesar shift=${shift}`;
    } else if (algo === 'aes') {
      const pass = document.getElementById('alicePass')?.value || 'STUDY123';
      payload = aesEncrypt(plain, pass); meta = 'AES';
    } else if (algo === 'rsa') {
      let recipientPub = document.getElementById('alicePubInput')?.value || '';
      if (hackMitmChecked()) {
        const hackerRSA = genRSA();
        recipientPub = hackerRSA.publicKey;
        window._hackerMitmPriv = hackerRSA.privateKey;
        appendHacker('MITM: attacker replaced recipient public key.');
      }
      if (!recipientPub) { alert('RSA requires recipient public key in Alice panel.'); return; }
      payload = rsaEncryptWithPub(plain, recipientPub); meta = 'RSA';
    } else if (algo === 'dh') {
      const g = Number(document.getElementById('gInput')?.value) || 5;
      const p = Number(document.getElementById('pInput')?.value) || 23;
      const a = Math.floor(Math.random() * (p - 2)) + 2;
      const A = modPow(g, a, p);
      payload = `[DH public A=${A}] ${plain}`; meta = 'DH';
      const alicePubField = document.getElementById('alicePubInput');
      if (alicePubField) alicePubField.value = `A=${A}`;
    }

    const deliverToBob = (delPayload) => {
      setTimeout(() => {
        if (algo === 'plain') appendBobFromOther(delPayload);
        else if (algo === 'caesar') {
          const shift = document.getElementById('bobShift')?.value || document.getElementById('aliceShift')?.value || '3';
          appendBobFromOther(caesarDecrypt(delPayload, shift));
        } else if (algo === 'aes') {
          const pass = document.getElementById('bobPass')?.value || document.getElementById('alicePass')?.value || 'STUDY123';
          appendBobFromOther(aesDecrypt(delPayload, pass) || '[decryption failed]');
        } else if (algo === 'rsa') {
          const priv = document.getElementById('bobPrivInput')?.value || (bobRSA ? bobRSA.privateKey : null);
          if (priv) appendBobFromOther(rsaDecryptWithPriv(delPayload, priv) || '[decryption failed]');
          else appendBobFromOther('[Bob has no private key - cannot decrypt]');
        } else if (algo === 'dh') {
          const g = Number(document.getElementById('gInput')?.value) || 5;
          const p = Number(document.getElementById('pInput')?.value) || 23;
          const b = Math.floor(Math.random() * (p - 2)) + 2;
          const Araw = (document.getElementById('alicePubInput')?.value || '').match(/A=(\d+)/);
          const A = Araw ? Number(Araw[1]) : null;
          if (A) {
            const shared = modPow(A, b, p);
            appendBobFromOther(`Shared key: ${shared}. Message: ${plain}`);
          } else appendBobFromOther(`Bob computed B=${b}. Message: ${plain}`);
        }
      }, 800);
    };

    // If hacker intercepts, handle according to policy
    if (hackInterceptChecked()) {
      queueIntercept({ payload, plain, algo, from: 'alice', to: 'bob', deliverFn: deliverToBob });
    } else {
      setTimeout(() => { deliverToBob(payload); appendHacker(`Pass-through to Bob [${meta}]`); }, 700);
    }

    aliceMsg.value = '';
    return;
  }

  // sender === 'bob' (reply)
  if (sender === 'bob') {
    const plain = (bobMsg.value || '').toString();
    if (!plain) return;
    appendBob(plain);

    const algo = algoSelect.value;
    let payload = '';

    if (algo === 'plain') payload = plain;
    else if (algo === 'caesar') {
      const shift = document.getElementById('bobShift')?.value || document.getElementById('aliceShift')?.value || '3';
      payload = caesarEncrypt(plain, shift);
    } else if (algo === 'aes') {
      const pass = document.getElementById('bobPass')?.value || document.getElementById('alicePass')?.value || 'STUDY123';
      payload = aesEncrypt(plain, pass);
    } else if (algo === 'rsa') {
      const alicePub = document.getElementById('alicePubInput')?.value || (aliceRSA ? aliceRSA.publicKey : '');
      if (!alicePub) { alert('RSA reply requires Alice public key.'); return; }
      payload = rsaEncryptWithPub(plain, alicePub);
    } else if (algo === 'dh') payload = plain;

    const deliverToAlice = (delPayload) => {
      setTimeout(() => {
        if (algo === 'plain') appendAliceFromOther(delPayload);
        else if (algo === 'caesar') {
          const shift = document.getElementById('aliceShift')?.value || '3';
          appendAliceFromOther(caesarDecrypt(delPayload, shift));
        } else if (algo === 'aes') {
          const pass = document.getElementById('alicePass')?.value || 'STUDY123';
          appendAliceFromOther(aesDecrypt(delPayload, pass) || '[decryption failed]');
        } else if (algo === 'rsa') {
          const priv = (aliceRSA ? aliceRSA.privateKey : null);
          if (priv) appendAliceFromOther(rsaDecryptWithPriv(delPayload, priv) || '[decryption failed]');
          else appendAliceFromOther('[Alice has no private key - cannot decrypt]');
        } else if (algo === 'dh') appendAliceFromOther(delPayload);
      }, 700);
    };

    if (hackInterceptChecked()) {
      queueIntercept({ payload, plain, algo, from: 'bob', to: 'alice', deliverFn: deliverToAlice });
    } else {
      setTimeout(() => { deliverToAlice(payload); appendHacker('Pass-through reply to Alice'); }, 600);
    }

    bobMsg.value = '';
    return;
  }
}

/* ===================== small helpers ===================== */
function modPow(base, exp, mod) { let res = 1; base = base % mod; while (exp > 0) { if (exp % 2 == 1) res = (res * base) % mod; base = (base * base) % mod; exp = Math.floor(exp / 2); } return res; }

/* ===================== init & bindings ===================== */
renderPanels(); // initial render
algoSelect.onchange = () => { renderPanels(); updateHackerControls(); };

// Listen for hacker option changes to re-evaluate policy
document.addEventListener('change', (e) => {
  if (!e.target) return;
  const ids = ['hackHasKey', 'hackMitm', 'hackIntercept'];
  if (ids.includes(e.target.id)) updateHackerControls();
});

// Ensure hidden editor exists
ensureHackerModifyUI();
updateHackerControls();

// Buttons
aliceSend.onclick = () => transportMessage('alice');
bobSend.onclick = () => transportMessage('bob');

// Initial demo content
appendAlice('Hey — check Question 2 and tell me when you submit.');
appendBob('Okay. I will check and submit later.');
appendHacker('Hacker active — toggle options to see effects.');

/* ===================== dynamic lib loader ===================== */
(function ensureLibs() {
  if (typeof CryptoJS === 'undefined') {
    const s = document.createElement('script');
    s.src = 'https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js';
    document.head.appendChild(s);
  }
  if (typeof JSEncrypt === 'undefined') {
    const s2 = document.createElement('script');
    s2.src = 'https://cdn.jsdelivr.net/npm/jsencrypt@3.0.0-rc.1/bin/jsencrypt.min.js';
    document.head.appendChild(s2);
  }
})();
