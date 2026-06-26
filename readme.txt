=== MBR Login Customiser ===
Contributors: Robert Palmer
Tags: login, security, customization, branding, custom-login
Requires at least: 5.0
Tested up to: 7.00
Stable tag: 1.9.1
Requires PHP: 7.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Secure and customize your WordPress login page with custom URLs, stunning visual styles, and complete branding control.

== Description ==

MBR Login Customiser is a comprehensive security and customization plugin that allows you to completely transform your WordPress login experience. Hide your login page from automated attacks by using a custom URL, then brand it beautifully with modern design options including Dark Mode and Glassmorphism effects.

Full security audit is bundled into the zip file.

= Security Features =

* **Custom Login URL** - Replace /wp-admin and /wp-login.php with your own custom slug
* **Block Standard Login** - Automatically returns 404 errors for default WordPress login URLs
* **Emergency Access** - Secure backup URL in case you forget your custom login slug
* **Session Token Management** - Secure authentication handling

= Visual Customization =

* **Custom Logo** - Upload your own logo via the WordPress Media Library
* **Background Options** - Choose from solid colors, gradients, or full background images
* **Form Styles** - Default, Dark Mode, or Glassmorphism (frosted glass effect)
* **Custom Fonts** - 10+ Google Fonts or system font stacks
* **Animations** - Fade, Slide, Zoom, or Bounce entrance effects
* **Box Shadows** - Five shadow depths including a colored glow effect
* **Button Colors** - Full color picker for the login button
* **Welcome Message** - Add custom text above the login form
* **Footer Text** - Custom footer content with HTML support
* **Advanced CSS** - Add your own CSS for complete control

= Perfect For =

* Web designers creating branded client sites
* Security-conscious site owners
* Agencies managing multiple WordPress installations
* Anyone wanting a professional, modern login page

= Modern Effects =

**Dark Mode** - Perfect for colorful backgrounds, with light text on dark semi-transparent forms.

**Glassmorphism** - Stunning frosted glass effect with backdrop blur, ideal for gradient or image backgrounds.

== Installation ==

1. Upload the plugin files to `/wp-content/plugins/mbr-login-customiser/` directory, or install through the WordPress plugins screen
2. Activate the plugin through the 'Plugins' screen in WordPress
3. Go to Settings > Custom Login to configure the plugin
4. Set your custom login URL and save your emergency access key
5. Customize the appearance to match your brand

== Frequently Asked Questions ==

= What happens if I forget my custom login URL? =

Use your emergency access key! The emergency URL format is: `yoursite.com/?mbr_emergency=YOUR_KEY`

You can find your emergency key in Settings > Custom Login > Login URL tab.

= Can I still access wp-admin if I'm already logged in? =

Yes! Once authenticated, you have full access to the WordPress admin area as normal.

= Will this work with caching plugins? =

Yes, but you may need to exclude your custom login URL from caching. Add your custom login slug to the "Never Cache" list in your caching plugin settings.

= Does this work with multisite? =

Not currently. Multisite support is planned for a future release.

= What browsers support the Glassmorphism effect? =

The backdrop-filter effect works on all modern browsers: Chrome, Firefox, Safari, and Edge. Older browsers will show the glass panel without the blur effect.

= I'm locked out! How do I regain access? =

If you have FTP/SSH access:
1. Connect to your server
2. Edit `wp-config.php`
3. Add: `define('MBR_EMERGENCY_DISABLE', true);`
4. Log in normally at `yoursite.com/wp-admin`
5. Reset your settings in Settings > Custom Login
6. Remove the line from `wp-config.php`

= Can I use my own fonts? =

Yes! Use the Custom CSS field to load and apply any web font you like, or choose from the 10+ included Google Fonts.

= Does this replace other security plugins? =

No. This plugin focuses on login URL customization and appearance. Use it alongside proper security measures like strong passwords, two-factor authentication, and security plugins.

== Changelog ==

= 1.9.1 =
* Security: Two-factor secrets now use authenticated encryption (AES-256-GCM) at rest, which also detects tampering. Secrets stored by earlier versions keep working and upgrade to GCM when the user next re-enrols
* Security: New Application Passwords policy on the Two-Factor tab. By default, Application Passwords are disabled for users who have two-factor enabled, removing any password-only path that would skip the second factor. Switch to "Allow" if those users rely on API or app integrations
* Security: The pending (pre-activation) two-factor secret is now also encrypted at rest
* Internal: Tidied a mismatched code comment; no functional change

= 1.9.0 =
* New: Multisite support. Per-site settings remain independent per site, with a new Network Admin settings screen for network-wide security policy
* New: Network-wide IP blacklist (applied on every site), force two-factor across all sites, and force login limiting across all sites
* New: New sites added to a network automatically get the log table and pruning cron set up
* Internal: Network options flow through the same options wrapper introduced in the 1.2.0 refactor; single-site installs are unaffected

= 1.8.1 =
* New: QR code on the two-factor setup screen. Generated entirely on your server as an inline SVG (no external services, no third-party QR sites), so the secret never leaves your site. The manual setup key remains as a fallback
* Improved: The Two-Factor tab now points to Users → Profile with a direct link, and clarifies the administrator reset path

= 1.8.0 =
* New: Two-factor authentication (TOTP) compatible with Google Authenticator, Authy, 1Password and similar apps. Pure PHP, no external services
* New: Per-user, opt-in enrolment from the profile screen with single-use recovery codes. Wrong codes count toward the existing lockout
* New: Lock-out recovery on three levels: recovery codes, an administrator reset on the user's profile, and a wp-config emergency constant (MBR_LOGIN_2FA_DISABLE)
* Security: TOTP secrets are encrypted at rest with a key derived from the site salts; recovery codes are hashed and single-use
* New: Two-Factor tab with a master toggle and enrolled-user count
* Note: QR-code display and forced enrolment by role are planned follow-ups; setup currently uses the manual key / otpauth link, which every authenticator app accepts

= 1.7.0 =
* New: Time-based access restrictions. A new Schedule tab lets you permit logins only within set hours per day of the week, using your site timezone
* New: Supports per-day windows, all-day access, and overnight windows (e.g. 22:00 to 06:00). Attempts outside permitted hours are blocked and logged
* Note: Whitelisted IPs bypass the schedule, and it only affects new logins, not existing sessions

= 1.6.0 =
* New: Custom login redirect rules. Send users to a chosen destination after login based on their role or a specific username, with user rules taking precedence over role rules
* New: Optional site-wide default login redirect and a logout redirect
* New: Redirects tab with an add/remove rule builder. Destinations accept a full URL or a site path such as /dashboard

= 1.5.0 =
* New: Progressive (escalating) lockouts. Each repeat lockout for the same IP lasts longer (configurable multiplier), up to a maximum, so persistent attackers are shut out for increasingly long periods
* New: Offence memory. An IP's offence count is remembered for a configurable window and survives the attempt-window reset, then resets after a quiet period
* Improved: A lockout is now logged the moment an IP crosses the threshold, not only when it retries while locked
* Improved: The Currently Locked Out table now shows each IP's offence count
* Note: Deliberately avoids artificial per-request delays, which can tie up server workers under attack; escalation provides the deterrence instead

= 1.4.0 =
* New: IP blacklist. Listed IP addresses (or CIDR ranges) are blocked from signing in and recorded in the log as a 'blocked' event
* New: Exclusive access mode, an optional "allow login only from trusted IPs" toggle. It is only enforced while the trusted list is non-empty, so it cannot lock everyone out, and warns if your current IP is not listed
* Improved: The whitelist is now a true trusted list, bypassing both lockouts and the blacklist, and both lists accept CIDR ranges (IPv4 and IPv6) as well as single addresses
* Internal: IP access checks moved into a dedicated module on the authenticate chain, with shared IP-matching used by the lockout check

= 1.3.0 =
* New: Login attempt logging. Failed logins, successful logins and lockout hits are recorded to a dedicated database table, with a new Logs tab showing a filterable, paginated view
* New: Logging is on by default with a configurable retention period (default 30 days). A daily cleanup prunes old entries, with a hard row cap as a safety net. Includes an enable toggle and a nonce-protected Clear Log action
* Note: Logged data includes IP addresses. Disable logging or shorten retention on the Logs tab if preferred

= 1.2.3 =
* Fixed: The admin colour pickers, logo uploader and background-image uploader did not load at all after the 1.2.0 restructure. The admin script was being requested from the includes/ folder (a 404) because its URL was built from the moved file's path; it now uses the plugin-root URL

= 1.2.2 =
* Fixed: The Gradient Start, Gradient End and Button colour fields now show a working colour picker. They are initialised when their fields become visible, so the gradient pickers no longer render collapsed when revealed

= 1.2.1 =
* Fixed: Fatal error on the login page (E_ERROR, undefined method sanitize_css) introduced by the 1.2.0 restructure. The login-page output path no longer depends on the admin module

= 1.2.0 =
* Internal: Restructured the plugin into per-concern modules (URL, appearance, security, admin) under an includes/ directory, with a slim bootstrap loader. Behaviour is unchanged; this is groundwork for upcoming features
* Internal: Added an options-access wrapper as the single seam for future multisite/network support

= 1.1.2 =
* Compliance: Prepared for the WordPress.org plugin repository. The plugin folder, main file and text domain are now aligned to the mbr-login-customiser slug. Existing settings are preserved
* Security: All output is now run through the appropriate escaping functions (esc_html, esc_attr, esc_html_e, esc_html__)
* Security: Custom CSS is sanitised against a </style> tag breakout before being printed
* i18n: Added a languages/mbr-login-customiser.pot translation template and translators comments for every string that contains a placeholder
* Fixed: Replaced parse_url() with wp_parse_url() for consistent results across PHP versions
* Fixed: The Google Fonts stylesheet is now registered with wp_enqueue_style() instead of being printed as a raw link tag

= 1.1.1 =
* Security: Hardened brute-force protection against spoofed proxy headers. Behind a proxy/CDN the visitor IP is now read from a single, admin-selected trusted header instead of guessing across several spoofable ones
* Security: Added a "Trusted IP Header" selector to the Security tab (Cloudflare, Akamai/True-Client-IP, nginx X-Real-IP, or generic X-Forwarded-For)
* Security: Emergency access key is now compared in constant time (hash_equals) to remove a theoretical timing side-channel
* Security: Constrained the gradient direction value to a fixed allowlist to remove a CSS-injection vector
* Security: Login pass-through cookie now sets SameSite=Lax (PHP 7.3+)
* Hardening: Capped the stored failed-attempt records to prevent unbounded option growth under distributed attacks
* Hardening: Added wp_unslash() to request data read from $_SERVER and $_GET

= 1.1.0 =
* Added: Limit Login Attempts - lock out an IP after a configurable number of failed logins
* Added: Security tab with max attempts, attempt window and lockout duration controls
* Added: IP whitelist so trusted addresses are never locked out
* Added: Proxy/CDN toggle for correct visitor IP detection behind Cloudflare etc.
* Added: Currently Locked Out panel with one-click unlock and Clear All

= 1.02 =
* Added: Custom font selection (Google Fonts + System Fonts)
* Added: Form entrance animations (Fade, Slide, Zoom, Bounce)
* Added: Box shadow options including colored glow effect
* Added: Custom footer text with HTML support
* Improved: Dark Mode styling with better specificity
* Improved: Glassmorphism effect with enhanced blur
* Fixed: Button color not applying correctly
* Fixed: Form visibility issues in Dark Mode

= 1.01 =
* Added: Dark Mode form style
* Added: Glassmorphism form style
* Added: Gradient background support with direction control
* Added: Background image upload via Media Library
* Added: Color pickers for all color options
* Added: Logo upload via Media Library
* Improved: Admin interface with tabbed settings
* Improved: CSS specificity for better override control

= 1.0 =
* Initial release
* Custom login URL functionality
* Emergency access system
* Basic login page customization
* Logo customization
* Background color selection
* Button color customization
* Welcome message
* Custom CSS support

== Upgrade Notice ==

= 1.1.2 =
WordPress.org compliance release: output escaping, internationalisation and coding-standards fixes. Your existing settings are preserved. Recommended for all users.

= 1.1.1 =
Security hardening release. Strengthens brute-force protection behind proxies/CDNs, makes the emergency-key check constant-time, and tightens input handling. Recommended for all users.

= 1.02 =
Major update adding custom fonts, animations, enhanced shadows, and footer text. Improved Dark Mode and Glassmorphism styling. Highly recommended upgrade.

= 1.01 =
Adds stunning Dark Mode and Glassmorphism effects, plus gradient and image backgrounds. Significant visual upgrade.

= 1.0 =
Initial release.

== Additional Info ==

**Note:** This is a security-focused plugin. Always test thoroughly on a staging site before deploying to production, and always maintain backup access methods.

== Privacy ==

This plugin does not collect, store, or transmit any user data. All settings are stored locally in your WordPress database.

