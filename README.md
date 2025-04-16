# Hosting Basic Authentication

![WordPress Plugin Version](https://img.shields.io/wordpress/plugin/v/pressable-basic-authentication) 
![License](https://img.shields.io/badge/license-GPL--2.0%20only-blue)

Forces Basic Authentication on all WordPress pages.

## Features
- Protects entire site with HTTP Basic Auth
- Auto-login for valid WordPress users
- Bypass for Super Admins (Multisite)
- Clean logout handling

## Installation
1. Upload to `/wp-content/plugins/`
2. Activate in WordPress admin

## Usage
No configuration needed. Visitors will see a browser login prompt.

**Logout URL:**  
`https://yoursite.com/?basic-auth-logout=1`

## Development
```bash
# Install dependencies
composer install

# Run linter
composer lint

# Fix linting errors
composer lint-fix