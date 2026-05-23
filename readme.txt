=== MBR Login Customiser ===
Contributors: madebyrob
Tags: login, security, customization, branding, custom-login
Requires at least: 5.0
Tested up to: 6.7
Stable tag: 1.02
Requires PHP: 7.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Secure and customise your WordPress login page with custom URLs, stunning visual styles, and complete branding control.

== Description ==

MBR Login Customiser is a comprehensive security and customisation plugin that allows you to completely transform your WordPress login experience. Hide your login page from automated attacks by using a custom URL, then brand it beautifully with modern design options, including Dark Mode and Glassmorphism effects.

= Security Features =

* **Custom Login URL** - Replace /wp-admin and /wp-login.php with your own custom slug
* **Block Standard Login** - Automatically returns 404 errors for default WordPress login URLs
* **Emergency Access** - Secure backup URL in case you forget your custom login slug
* **Session Token Management** - Secure authentication handling

= Visual Customization =

* **Custom Logo** - Upload your own logo via the WordPress Media Library
* **Background Options** - Choose from solid colours, gradients, or full background images
* **Form Styles** - Default, Dark Mode, or Glassmorphism (frosted glass effect)
* **Custom Fonts** - 10+ Google Fonts or system font stacks
* **Animations** - Fade, Slide, Zoom, or Bounce entrance effects
* **Box Shadows** - Five shadow depths, including a colored glow effect
* **Button Colours** - Full colour picker for the login button
* **Welcome Message** - Add custom text above the login form
* **Footer Text** - Custom footer content with HTML support
* **Advanced CSS** - Add your own CSS for complete control

= Perfect For =

* Web designers creating branded client sites
* Security-conscious site owners
* Agencies managing multiple WordPress installations
* Anyone wanting a professional, modern login page

= Modern Effects =

**Dark Mode** - Perfect for colourful backgrounds, with light text on dark semi-transparent forms.

**Glassmorphism** - Stunning frosted glass effect with backdrop blur, ideal for gradient or image backgrounds.

== Installation ==

1. Upload the plugin files to `/wp-content/plugins/mbr-login-customiser/` directory, or install through the WordPress plugins screen
2. Activate the plugin through the 'Plugins' screen in WordPress
3. Go to Settings > Custom Login to configure the plugin
4. Set your custom login URL and save your emergency access key
5. Customise the appearance to match your brand

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

No. This plugin focuses on login URL customisation and appearance. Use it alongside proper security measures like strong passwords, two-factor authentication, and security plugins.

== Screenshots ==

1. Login URL settings with custom slug and emergency access key
2. Appearance settings with background options, form styles, and colours
3. Dark Mode login page with custom background
4. Glassmorphism effect with gradient background
5. Font, animation, and shadow customisation options
6. Custom logo and welcome message example

== Changelog ==

= 1.02 =
* Added: Custom font selection (Google Fonts + System Fonts)
* Added: Form entrance animations (Fade, Slide, Zoom, Bounce)
* Added: Box shadow options, including colored glow effect
* Added: Custom footer text with HTML support
* Improved: Dark Mode styling with better specificity
* Improved: Glassmorphism effect with enhanced blur
* Fixed: Button colour not applying correctly
* Fixed: Form visibility issues in Dark Mode

= 1.01 =
* Added: Dark Mode form style
* Added: Glassmorphism form style
* Added: Gradient background support with direction control
* Added: Background image upload via Media Library
* Added: Colour pickers for all colour options
* Added: Logo upload via Media Library
* Improved: Admin interface with tabbed settings
* Improved: CSS specificity for better override control

= 1.0 =
* Initial release
* Custom login URL functionality
* Emergency access system
* Basic login page customisation
* Logo customization
* Background color selection
* Button color customisation
* Welcome message
* Custom CSS support

== Upgrade Notice ==

= 1.02 =
Major update adding custom fonts, animations, enhanced shadows, and footer text. Improved Dark Mode and Glassmorphism styling. Highly recommended upgrade.

= 1.01 =
Adds stunning Dark Mode and Glassmorphism effects, plus gradient and image backgrounds. Significant visual upgrade.

= 1.0 =
Initial release.

== Additional Info ==

**Created by:** Made by Robert / Little Web Shack
**Support:** For support and feature requests, please visit https://littlewebshack.com

**Note:** This is a security-focused plugin. Always test thoroughly on a staging site before deploying to production, and always maintain backup access methods.

== Privacy ==

This plugin does not collect, store, or transmit any user data. All settings are stored locally in your WordPress database.

== Credits ==

Developed by Robert Palmer from Little Web Shack with a focus on security, usability, and modern design aesthetics.
