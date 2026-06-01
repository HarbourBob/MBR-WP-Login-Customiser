# MBR Custom Login - WordPress Plugin

A security-focused WordPress plugin that allows you to customize your login URL and appearance, protecting your site from automated attacks on standard login pages.

## Features

### Security Features
- **Custom Login URL**: Replace `/wp-admin` and `/wp-login.php` with your own custom slug
- **Block Standard Login**: Automatically blocks access to default WordPress login URLs
- **Emergency Access**: Secure backup URL in case you forget your custom login slug
- **404 Responses**: Returns proper 404 errors for blocked login attempts

### Appearance Customization
- **Custom Logo**: Upload your own logo for the login page
- **Logo Link**: Set where the logo links to (defaults to homepage)
- **Welcome Message**: Display a custom message above the login form
- **Color Customization**: Change background and button colors
- **Custom CSS**: Add your own CSS for advanced customization

## Installation

1. Upload the `mbr-custom-login.php` file to your `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to **Settings > Custom Login** to configure the plugin

## Configuration

### Login URL Settings

Navigate to **Settings > Custom Login > Login URL** tab:

1. **Custom Login Slug**: Enter your desired login URL slug (e.g., "secure-entry")
   - Your new login URL will be: `yoursite.com/your-slug`
   - Avoid using reserved words like: wp-admin, admin, login, wp-login

2. **Emergency Access Key**: A randomly generated key for backup access
   - Save this key somewhere safe!
   - Emergency URL format: `yoursite.com?mbr_emergency=YOUR_KEY`
   - Use the "Generate New Key" button to create a new one if needed

### Appearance Settings

Navigate to **Settings > Custom Login > Appearance** tab:

1. **Custom Logo URL**: Full URL to your logo image
   - Recommended size: 320x80 pixels
   - Supports: JPG, PNG, SVG

2. **Logo Link URL**: Where the logo should link (default: homepage)

3. **Logo Title Text**: Hover text for the logo

4. **Welcome Message**: Optional message displayed above login form
   - Supports basic HTML formatting

5. **Background Color**: Page background color (hex color picker)

6. **Button Color**: Login button color (hex color picker)

7. **Custom CSS**: Advanced CSS customization
   - Target `.login` class elements
   - No `<style>` tags needed - just pure CSS

## Security Considerations

### Best Practices
1. **Choose a unique slug**: Don't use obvious names like "login2" or "admin-panel"
2. **Keep your emergency key safe**: Store it in a password manager
3. **Test before deployment**: Make sure you can access the new URL before leaving the settings page
4. **Use HTTPS**: This plugin works best on SSL-enabled sites

### What This Plugin Does NOT Do
- Does NOT protect against determined attackers who already know your login URL
- Does NOT replace proper security measures (strong passwords, 2FA, etc.)
- Does NOT block access to REST API endpoints or XML-RPC

### Compatibility
- **WordPress Version**: 5.0 or higher
- **PHP Version**: 7.0 or higher
- **Multisite**: Not currently supported (planned for future version)

## How It Works

### URL Blocking
1. Plugin intercepts all requests to standard WordPress login URLs
2. If user is not authenticated and doesn't have valid session token, shows 404
3. Custom login slug is recognized and processed normally
4. Emergency key provides backup access method

### Session Management
- When accessing custom login URL, plugin sets a temporary token (5 minutes)
- Token allows actual wp-login.php to load without triggering 404
- Token is cleared after use or expiration

## Troubleshooting

### "I can't access my login page!"
Use your emergency access URL:
```
yoursite.com/?mbr_emergency=YOUR_EMERGENCY_KEY
```

### "I forgot my emergency key!"
If you have FTP/SSH access:
1. Connect to your server
2. Edit `wp-config.php`
3. Add: `define('MBR_EMERGENCY_DISABLE', true);`
4. This temporarily disables the plugin protection
5. Log in normally at `yoursite.com/wp-admin`
6. Go to Settings > Custom Login to get your key
7. Remove the line from `wp-config.php`

### "Getting redirected to 404 after login"
Clear your browser cookies and cache, then try again.

### "Plugin conflicts with my caching plugin"
You may need to exclude your custom login URL from caching:
- WP Super Cache: Add to "Rejected URLs"
- W3 Total Cache: Add to "Never cache the following pages"
- WP Rocket: Add to "Never Cache URL(s)"

## Customization Examples

### Custom CSS Example 1: Modern Flat Design
```css
#login {
    padding: 5% 0 0;
}

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

### Custom CSS Example 2: Dark Theme
```css
body.login {
    background: #1a1a1a;
}

.login form {
    background: #2a2a2a;
    border: 1px solid #3a3a3a;
}

.login label {
    color: #ffffff;
}

.login input[type="text"],
.login input[type="password"] {
    background: #3a3a3a;
    border: 1px solid #4a4a4a;
    color: #ffffff;
}

.login #backtoblog a,
.login #nav a {
    color: #ffffff !important;
}
```

## Changelog

### Version 1.0.0
- Initial release
- Custom login URL functionality
- Emergency access system
- Login page appearance customization
- Color picker integration
- Custom CSS support

## Roadmap

Future features being considered:
- [ ] Multisite support
- [ ] Login attempt logging
- [ ] IP whitelist/blacklist
- [ ] Time-based access restrictions
- [ ] Two-factor authentication integration
- [ ] Custom login redirect rules
- [ ] Brute force protection

## Support

For support, feature requests, or bug reports, please visit:
- Website: https://littlewebshack.com
- Documentation: (Coming soon)

## License

This plugin is licensed under GPL v2 or later.

## Credits

Developed by **Made by Robert**
- Website: https://littlewebshack.com
- WordPress Profile: (Add your profile)

---

**Note**: This is a security plugin. Always test thoroughly on a staging site before deploying to production, and always maintain backup access methods.
