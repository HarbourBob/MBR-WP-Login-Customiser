<div align="center">

# 🔐 MBR Login Customiser

### Lock down and smarten up the part of your WordPress site attackers hit first — the login page.

Passkeys · Two-Factor · Security Alerts · Trusted Devices · Custom Login URL · Brute-Force Protection

<br>

![Version](https://img.shields.io/badge/version-2.0.0-2b6cb0)
![License](https://img.shields.io/badge/license-GPL--2.0%2B-2f855a)
![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-21759b)
![PHP](https://img.shields.io/badge/PHP-8.0%2B-777bb4)
![No telemetry](https://img.shields.io/badge/telemetry-none-1a1a1a)
![Price](https://img.shields.io/badge/price-free%20forever-6b46c1)

</div>

---

## Why it exists

Nine out of ten attacks on a WordPress site start at the same door: `/wp-login.php`. Bots find it, hammer it, and never get tired. **MBR Login Customiser** moves that door, bolts it, watches it, and — when you're ready — replaces the key with a passkey.

It's a full login-security suite that also happens to make your login page look great. And it does the whole job on **your own server**:

- 🆓 **Free forever.** No premium tier, no locked features, no "upgrade to unlock."
- 🕵️ **No telemetry.** Nothing about your site or your users is phoned home. Ever.
- 🌐 **No external services, no CDN.** Passkey verification, 2FA QR codes, the lot — all generated and checked in pure PHP, on your box.
- 📖 **GPL and open.** Read every line. Fork it. Ship it.

Built and maintained by one person who thinks good security shouldn't be a paywall.

---

## ✨ What's new in 2.0

Three headline features, all verified entirely on your own server — no third-party calls.

### 🔑 Passkeys (WebAuthn / FIDO2)
Passwordless, phishing-resistant sign-in using a fingerprint, face, screen lock, or a hardware security key. The genuinely hard part — decoding the authenticator's response and verifying its signature — is done in **pure PHP** using the platform's own OpenSSL and libsodium. No Composer libraries, no external validation services, and the private key never leaves the user's device. Supports ES256, RS256 and EdDSA credentials, in either **passwordless** or **second-factor** mode.

### 🚨 Security Alerts
Your login log stops being something you have to remember to check. Get an **email** or a **Slack / Discord webhook** the moment an IP is locked out, an administrator signs in from an IP not seen before, or failed logins spike past a threshold you set. Per-alert cooldowns mean an ongoing attack can't flood your inbox, and there's a one-click "send test alert" button.

### 📱 Trusted Devices
Let people tick *"trust this device"* to skip the second factor on browsers they choose — the friction-killer that stops users disabling 2FA altogether. Backed by an **HMAC-signed, server-side revocable cookie** with a hard expiry, so trust is time-limited and can be pulled from a user's profile at any time. Only the second step is skipped — the password or passkey is **always** required.

---

## 🧰 The full toolkit

<table>
<tr>
<td width="50%" valign="top">

### 🚪 Access & obfuscation
- **Custom login URL** — replace `/wp-admin` & `/wp-login.php` with your own slug
- **Block standard login** — proper 404s for the default URLs
- **Emergency access** — signed backup URL + a `wp-config` kill switch
- **IP allow / block lists** — with full **CIDR** support (IPv4 & IPv6)
- **Time-based access** — only allow logins during set hours, overnight windows included

</td>
<td width="50%" valign="top">

### 🛡️ Attack protection
- **Brute-force protection** — rate limiting with escalating lockouts
- **Offence memory** — persistent attackers get progressively longer bans
- **Login logging** — filterable log with automatic retention
- **Post-login/logout redirects** — by role or individual user
- **Multisite ready** — network-wide security policy from Network Admin

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🔐 Strong authentication
- **Passkeys (WebAuthn / FIDO2)** — passwordless & phishing-resistant
- **Two-factor (TOTP)** — works with Google Authenticator, Authy, 1Password
- **Pure-PHP QR enrolment** — the enrolment QR is drawn on your server
- **AES-256-GCM** encryption of 2FA secrets at rest
- **Recovery codes** + admin & `wp-config` recovery paths

</td>
<td width="50%" valign="top">

### 🎨 Make it yours
- **Dark mode & glassmorphism** form styles out of the box
- **Custom logo**, link, welcome message & footer
- **Fonts, animations, shadows** and button colours
- **Full custom CSS** for anything else
- Looks like *your* brand, not a stock WordPress form

</td>
</tr>
</table>

---

## 🚀 Quick start

1. **Download** the latest release (see [Releases](../../releases), or grab it from [littlewebshack.com](https://littlewebshack.com)).
2. In your dashboard go to **Plugins → Add New → Upload Plugin**, choose the `.zip`, and **Activate**. *(Or drop the `mbr-login-customiser` folder into `/wp-content/plugins/`.)*
3. Open the **MBR Login Customiser** settings and work through the tabs — each feature is off until you switch it on.
4. **Set your custom login URL first and test it in a private window before logging out.** (There's an emergency URL and a kill switch if you ever lock yourself out — see below.)

> 💡 **Tip:** turn features on one at a time. Set your custom URL, confirm you can still get in, then layer on 2FA, passkeys, alerts and trusted devices as you go.

---

## ⚙️ A quick tour of the tabs

| Tab | What it does |
|-----|--------------|
| **Login URL** | Your custom slug, standard-login blocking, emergency access key |
| **Appearance** | Logo, colours, dark mode, glassmorphism, fonts, custom CSS |
| **Security** | Rate limiting, escalating lockouts, IP blacklist |
| **Access** | IP allow/block (CIDR) and time-based access windows |
| **Logs** | Login event history with retention control |
| **Redirects** | Where users land after login / logout, by role or user |
| **Schedule** | Permitted login hours in your site's timezone |
| **Two-Factor** | TOTP enrolment, recovery codes, app-password policy |
| **Passkeys** | Enable WebAuthn, choose passwordless or second-factor mode |
| **Alerts** | Email / webhook notifications and thresholds |
| **Trusted Devices** | Enable "remember this device" and set the trust duration |

Passkeys and trusted devices are managed per user on their own **Users → Profile** screen.

---

## 🆘 Locked out? Don't panic.

There's always a way back in.

**Emergency URL** — the backup access link (find it on the Login URL tab and keep it safe):
```
https://yoursite.com/?mbr_emergency=YOUR_EMERGENCY_KEY
```

**Kill switches** — if you have FTP/SSH, add one of these to `wp-config.php`, log in normally, then remove it:
```php
define('MBR_EMERGENCY_DISABLE', true);       // disables login-URL protection
define('MBR_LOGIN_PASSKEYS_DISABLE', true);  // disables passkeys site-wide
```

Recovery codes and administrator overrides are also available for two-factor and passkeys, so a lost phone never means a locked account.

---

## 🔒 Security philosophy

- **Everything happens on your server.** No request about your site or your users is ever sent to a third party. Passkey ceremonies, TOTP verification and QR generation are all local, in pure PHP.
- **Additive by default.** Passwordless passkey sign-in sits *alongside* the normal login — it can never lock a legitimate user out.
- **Least surprise.** Every feature ships off, and every risky action has a documented recovery path.
- **Independently audited surface.** A security-audit report covering the codebase is bundled with the plugin.

### What it does **not** claim to be
- It isn't an edge firewall or a CDN — pair it with your host's WAF or Cloudflare for network-level filtering.
- It doesn't replace good hygiene — strong passwords and keeping WordPress updated still matter.

---

## 📦 Requirements

| | |
|---|---|
| **WordPress** | 6.0 or higher |
| **PHP** | 8.0 or higher (8.3 recommended) |
| **Extensions** | OpenSSL & libsodium (standard on modern PHP) — needed for passkeys |
| **HTTPS** | Required for passkeys (a browser rule), recommended everywhere |
| **Multisite** | ✅ Supported |

---

## 🔄 Updates

Updates are **self-hosted** and delivered straight to your dashboard via the [Plugin Update Checker](https://github.com/YahnisElsts/plugin-update-checker) — no marketplace account, no telemetry. When a new version is published you'll see the usual update prompt under Plugins, just like any other.

---

## 🗺️ Roadmap

Much of the original roadmap is now shipped ✅ — multisite, logging, IP lists, time-based access, 2FA, redirects and brute-force protection all landed. On the horizon:

- [ ] **Login firewall / request hardening** — a focused, monitor-mode-first ruleset for the login, XML-RPC and REST auth surfaces (reusing the existing IP, rate-limit and logging engine)
- [ ] More authenticator/attestation options for passkeys
- [ ] Additional alert channels

Got a feature request? [Open an issue](../../issues) — this plugin is shaped by the people using it.

---

<details>
<summary>📜 <strong>Version history</strong> (click to expand)</summary>

### 2.0.0
- **New:** Passkeys (WebAuthn / FIDO2) — passwordless, phishing-resistant sign-in, verified in pure PHP (CBOR decode, COSE key reconstruction, signature checks) with no external services. Passwordless and second-factor modes; ES256, RS256 and EdDSA support.
- **New:** Security Alerts — email and Slack/Discord webhook notifications on lockouts, new-IP admin sign-in and failed-login spikes, with per-type cooldowns and a test button.
- **New:** Trusted Devices — skip the second factor on trusted browsers via an HMAC-signed, revocable, time-limited cookie.

### 1.9.x
- Two-factor authentication (TOTP) with pure-PHP QR enrolment, AES-256-GCM secret encryption, recovery codes and a formal security audit.
- Multisite support with network-wide policy.

### 1.x
- Custom login URL, emergency access, appearance customisation, colour pickers and custom CSS.
- Login logging, IP allow/block with CIDR, time-based access, redirect rules and brute-force protection.

*Full, detailed changelog lives in `readme.txt`.*

</details>

<details>
<summary>🎨 <strong>Custom CSS examples</strong> (click to expand)</summary>

**Modern flat design**
```css
#login { padding: 5% 0 0; }
.login form {
    border: none;
    box-shadow: 0 10px 40px rgba(0,0,0,0.1);
    border-radius: 10px;
}
.login input[type="text"],
.login input[type="password"] {
    border-radius: 5px;
    border: 1px solid #ddd;
    padding: 10px 15px;
}
```

**Dark theme** *(or just flip on the built-in Dark Mode style)*
```css
body.login { background: #1a1a1a; }
.login form { background: #2a2a2a; border: 1px solid #3a3a3a; }
.login label { color: #fff; }
.login input[type="text"],
.login input[type="password"] {
    background: #3a3a3a; border: 1px solid #4a4a4a; color: #fff;
}
.login #backtoblog a, .login #nav a { color: #fff !important; }
```

</details>

<details>
<summary>🧩 <strong>Playing nicely with caching</strong> (click to expand)</summary>

If a caching plugin interferes with your custom login URL, exclude it from caching:

- **WP Rocket** → *Never Cache URL(s)*
- **W3 Total Cache** → *Never cache the following pages*
- **WP Super Cache** → *Rejected URLs*

On SiteGround, also exclude it from SG Optimizer's dynamic cache if needed.

</details>

---

## 🤝 Contributing

Issues, ideas and pull requests are all welcome. If you've found a security concern, please report it responsibly rather than opening a public issue.

## 📄 License

Released under the **GPL v2 or later**. Use it, study it, change it, share it.

## 👋 Author

Built with care by **Robert Palmer** — a solo freelance WordPress developer in Cleethorpes, UK, giving away a suite of genuinely-free, no-nonsense plugins.

- 🌐 [littlewebshack.com](https://littlewebshack.com) · [madebyrobert.co.uk](https://madebyrobert.co.uk)
- 🐙 GitHub: [@HarbourBob](https://github.com/HarbourBob)

<div align="center">
<br>
<em>If MBR Login Customiser keeps the bots off your door, a ⭐ on the repo is always appreciated.</em>
</div>
