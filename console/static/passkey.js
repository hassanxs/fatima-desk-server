// Passkeys (WebAuthn) for the Console: adding one, signing in with one, and
// confirming a Security form with one instead of a code.
(() => {
  const b64u = {
    dec: s => {
      s = s.replace(/-/g, '+').replace(/_/g, '/');
      s += '='.repeat((4 - (s.length % 4)) % 4);
      return Uint8Array.from(atob(s), c => c.charCodeAt(0)).buffer;
    },
    enc: buf => btoa(String.fromCharCode(...new Uint8Array(buf)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  };

  const supported = () => !!(window.PublicKeyCredential && navigator.credentials);

  async function call(url, body) {
    const res = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: body === undefined ? '{}' : JSON.stringify(body),
    });
    let data = {};
    try { data = await res.json(); } catch (_) {}
    if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
    return data;
  }

  const descriptors = list => (list || []).map(c => ({ ...c, id: b64u.dec(c.id) }));

  async function create(opts) {
    const pk = opts.publicKey;
    pk.challenge = b64u.dec(pk.challenge);
    pk.user.id = b64u.dec(pk.user.id);
    pk.excludeCredentials = descriptors(pk.excludeCredentials);
    const cred = await navigator.credentials.create({ publicKey: pk });
    const r = cred.response;
    return {
      id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults(),
      response: {
        clientDataJSON: b64u.enc(r.clientDataJSON),
        attestationObject: b64u.enc(r.attestationObject),
        transports: r.getTransports ? r.getTransports() : [],
      },
    };
  }

  async function get(opts) {
    const pk = opts.publicKey;
    pk.challenge = b64u.dec(pk.challenge);
    pk.allowCredentials = descriptors(pk.allowCredentials);
    const cred = await navigator.credentials.get({ publicKey: pk });
    const r = cred.response;
    return {
      id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults(),
      response: {
        clientDataJSON: b64u.enc(r.clientDataJSON),
        authenticatorData: b64u.enc(r.authenticatorData),
        signature: b64u.enc(r.signature),
        userHandle: r.userHandle ? b64u.enc(r.userHandle) : null,
      },
    };
  }

  const friendly = e => (e && e.name === 'NotAllowedError')
    ? 'Cancelled, or the passkey wasn\'t available.'
    : (e && e.name === 'InvalidStateError') ? 'This passkey is already added.'
    : (e && e.message) || String(e);

  document.addEventListener('DOMContentLoaded', () => {
    const csrfEl = document.getElementById('csrf');
    const q = () => '?csrf=' + encodeURIComponent(csrfEl ? csrfEl.value : '');
    const msg = document.getElementById('passkey-msg');
    const say = (text, isErr) => {
      if (!msg) return;
      msg.textContent = text;
      msg.hidden = !text;
      msg.classList.toggle('err', !!isErr);
    };

    // Security page: add a passkey.
    const add = document.getElementById('passkey-add');
    if (add) {
      if (!supported()) { add.disabled = true; say('This browser does not support passkeys.', true); }
      add.addEventListener('click', async () => {
        const nameEl = document.getElementById('passkey-name');
        const name = (nameEl && nameEl.value.trim()) || 'Passkey';
        add.disabled = true;
        say('Follow the prompt from Windows, your phone or your security key…');
        try {
          const opts = await call('/security/passkeys/register/begin' + q());
          const cred = await create(opts);
          await fetch('/security/passkeys/register/finish' + q() + '&name=' + encodeURIComponent(name), {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(cred),
          }).then(async r => { if (!r.ok) throw new Error((await r.json()).error || ('HTTP ' + r.status)); });
          location.href = '/security?ok=' + encodeURIComponent('Passkey "' + name + '" added.') + '#passkeys';
        } catch (e) {
          say(friendly(e), true);
          add.disabled = false;
        }
      });
    }

    // Security page: confirm a form with a passkey instead of a code.
    document.querySelectorAll('[data-passkey-confirm]').forEach(btn => {
      if (!supported()) { btn.hidden = true; return; }
      btn.addEventListener('click', async () => {
        const form = btn.closest('form');
        btn.disabled = true;
        try {
          const opts = await call('/security/passkeys/verify/begin' + q());
          const assertion = await get(opts);
          const res = await fetch('/security/passkeys/verify/finish' + q(), {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(assertion),
          });
          const data = await res.json();
          if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
          form.querySelector('input[name=passkey_token]').value = data.token;
          form.requestSubmit();
        } catch (e) {
          alert(friendly(e));
        } finally {
          btn.disabled = false;
        }
      });
    });

    // Sign-in code page: use a passkey instead of the code.
    const login = document.getElementById('passkey-login');
    if (login) {
      if (!supported()) { login.hidden = true; return; }
      login.addEventListener('click', async () => {
        login.disabled = true;
        say('');
        try {
          const opts = await call('/login/passkey/begin');
          const assertion = await get(opts);
          const data = await call('/login/passkey/finish', assertion);
          location.href = data.next || '/';
        } catch (e) {
          say(friendly(e), true);
          login.disabled = false;
        }
      });
    }
  });
})();
