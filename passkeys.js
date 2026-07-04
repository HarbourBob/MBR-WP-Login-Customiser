/**
 * MBR Login Customiser — passkeys (WebAuthn) client ceremonies.
 *
 * Handles both contexts from one file, selected by mbrPasskeys.context:
 *   - 'login'   : the "Sign in with a passkey" button on wp-login.php
 *   - 'profile' : the "Register a passkey" button on the profile screen
 *
 * All binary values cross the wire as base64url strings; this file converts
 * to/from ArrayBuffers for the WebAuthn API.
 */
(function () {
	'use strict';

	var cfg = window.mbrPasskeys || {};
	var i18n = cfg.i18n || {};

	/* --- base64url helpers --- */
	function b64urlToBuf(s) {
		s = String(s).replace(/-/g, '+').replace(/_/g, '/');
		var pad = s.length % 4;
		if (pad) { s += '===='.slice(pad); }
		var bin = atob(s);
		var buf = new Uint8Array(bin.length);
		for (var i = 0; i < bin.length; i++) { buf[i] = bin.charCodeAt(i); }
		return buf.buffer;
	}

	function bufToB64url(buf) {
		var bytes = new Uint8Array(buf);
		var bin = '';
		for (var i = 0; i < bytes.length; i++) { bin += String.fromCharCode(bytes[i]); }
		return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
	}

	function supported() {
		return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
	}

	function post(action, data) {
		var body = new URLSearchParams();
		body.set('action', action);
		Object.keys(data || {}).forEach(function (k) {
			if (Array.isArray(data[k])) {
				data[k].forEach(function (v) { body.append(k + '[]', v); });
			} else {
				body.set(k, data[k]);
			}
		});
		return fetch(cfg.ajaxUrl, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: body.toString()
		}).then(function (r) { return r.json(); });
	}

	function setStatus(el, msg, isError) {
		if (!el) { return; }
		el.textContent = msg || '';
		el.style.color = isError ? '#d63638' : '';
	}

	/* ================= LOGIN ================= */

	function initLogin() {
		var btn = document.getElementById('mbr-passkey-login');
		var status = document.getElementById('mbr-passkey-status');
		var proofField = document.getElementById('mbr-passkey-proof');
		if (!btn) { return; }

		if (!supported()) {
			// Leave the button hidden; password form is unaffected.
			return;
		}
		btn.style.display = '';

		btn.addEventListener('click', function () {
			btn.disabled = true;
			setStatus(status, i18n.working || '');

			post('mbr_passkey_login_options', {}).then(function (res) {
				if (!res || !res.success) {
					throw new Error((res && res.data && res.data.message) || 'options');
				}
				var opt = res.data;
				var publicKey = {
					challenge: b64urlToBuf(opt.challenge),
					rpId: opt.rpId,
					timeout: opt.timeout || 120000,
					userVerification: opt.userVerification || 'preferred',
					allowCredentials: [] // discoverable / usernameless
				};
				return navigator.credentials.get({ publicKey: publicKey }).then(function (assertion) {
					return { assertion: assertion, challengeId: opt.challengeId };
				});
			}).then(function (bundle) {
				var a = bundle.assertion;
				var r = a.response;
				var trustBox = document.querySelector('input[name="mbr_trust_device"]');
				return post('mbr_passkey_login_verify', {
					challengeId: bundle.challengeId,
					id: a.id,
					authenticatorData: bufToB64url(r.authenticatorData),
					clientDataJSON: bufToB64url(r.clientDataJSON),
					signature: bufToB64url(r.signature),
					userHandle: r.userHandle ? bufToB64url(r.userHandle) : '',
					redirectTo: cfg.redirectTo || '',
					mbr_trust_device: (trustBox && trustBox.checked) ? '1' : ''
				});
			}).then(function (res) {
				if (!res || !res.success) {
					throw new Error((res && res.data && res.data.message) || (i18n.failed || 'failed'));
				}
				if (res.data.twofa) {
					// Second-factor mode: stash the proof, let the user submit the
					// password form normally.
					if (proofField) { proofField.value = res.data.proof; }
					setStatus(status, res.data.message || '');
					btn.disabled = false;
					var form = document.getElementById('loginform');
					var pw = document.getElementById('user_pass');
					if (pw) { pw.focus(); }
					return;
				}
				// Passwordless: redirect.
				setStatus(status, res.data.message || '');
				window.location.href = res.data.redirect || (cfg.redirectTo || '/wp-admin/');
			}).catch(function (err) {
				btn.disabled = false;
				var msg = (err && err.name === 'NotAllowedError') ? (i18n.cancelled || '') : (i18n.failed || '');
				setStatus(status, msg, true);
			});
		});
	}

	/* ================= REGISTRATION ================= */

	function initRegister() {
		var btn = document.getElementById('mbr-passkey-register');
		var status = document.getElementById('mbr-passkey-reg-status');
		if (!btn) { return; }

		if (!supported()) {
			btn.disabled = true;
			setStatus(status, i18n.unsupported || '', true);
			return;
		}

		btn.addEventListener('click', function () {
			btn.disabled = true;
			setStatus(status, i18n.working || '');

			post('mbr_passkey_register_options', { nonce: cfg.nonce }).then(function (res) {
				if (!res || !res.success) {
					throw new Error((res && res.data && res.data.message) || 'options');
				}
				var opt = res.data;
				var publicKey = {
					challenge: b64urlToBuf(opt.challenge),
					rp: opt.rp,
					user: {
						id: b64urlToBuf(opt.user.id),
						name: opt.user.name,
						displayName: opt.user.displayName
					},
					pubKeyCredParams: opt.pubKeyCredParams,
					timeout: opt.timeout || 120000,
					authenticatorSelection: opt.authenticatorSelection || {},
					excludeCredentials: (opt.excludeCredentials || []).map(function (c) {
						return { type: 'public-key', id: b64urlToBuf(c.id) };
					}),
					attestation: 'none'
				};
				return navigator.credentials.create({ publicKey: publicKey });
			}).then(function (cred) {
				var label = '';
				if (typeof window.prompt === 'function') {
					label = window.prompt(i18n.namePrompt || 'Name this passkey:', '') || '';
				}
				var r = cred.response;
				return post('mbr_passkey_register_verify', {
					nonce: cfg.nonce,
					clientDataJSON: bufToB64url(r.clientDataJSON),
					attestationObject: bufToB64url(r.attestationObject),
					label: label
				});
			}).then(function (res) {
				if (!res || !res.success) {
					btn.disabled = false;
					throw new Error((res && res.data && res.data.message) || (i18n.failed || 'failed'));
				}
				// Show the confirmation briefly, then refresh so the new passkey
				// appears in the registered list.
				setStatus(status, res.data.message || i18n.registered || '');
				setTimeout(function () { window.location.reload(); }, 900);
			}).catch(function (err) {
				btn.disabled = false;
				var msg = (err && err.name === 'NotAllowedError') ? (i18n.cancelled || '') : (err && err.message) || (i18n.failed || '');
				setStatus(status, msg, true);
			});
		});
	}

	function boot() {
		if (cfg.context === 'profile') {
			initRegister();
		} else {
			initLogin();
		}
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', boot);
	} else {
		boot();
	}
})();
