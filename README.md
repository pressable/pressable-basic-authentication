# Hosting Basic Authentication

A WordPress plugin that forces all users to authenticate using Basic Authentication before accessing any page on the site.

## Description

This plugin implements server-level Basic Authentication for your WordPress site, requiring valid credentials before any page can be accessed. It's particularly useful for:

- Sites that should not be publicly accessible
- Sites under maintenance
- Sites that need an additional layer of security before the WordPress login

Key features:
- Forces Basic Authentication for all requests (except AJAX, CRON, and CLI)
- Integrates with WordPress user database for authentication
- Handles logout functionality properly
- Prevents caching of authentication requests
- Logs failed authentication attempts
- Bypasses authentication for Super Admins in multisite installations
- Redirects authenticated users away from wp-login.php

## Requirements

- WordPress 6.7 or higher
- PHP 8.1 or higher
- Server must support PHP_AUTH_USER and PHP_AUTH_PW server variables (most standard hosting environments do)

## Frequently Asked Questions

### Why am I getting constant authentication prompts?

This typically means:
1. Your credentials are incorrect - verify your WordPress username and password
2. Your server is stripping authentication headers - contact your hosting provider
3. There may be a caching layer interfering - try clearing all caches

### Can I bypass Basic Authentication for certain users?

In a multisite installation, Super Admins can bypass the authentication. For single site installations, you would need to modify the plugin code.

### How do I disable the plugin if I'm locked out?

1. Access your site via FTP/SFTP or file manager
2. Rename or delete the `hosting-basic-authentication` folder in `/wp-content/plugins/`
3. This will deactivate the plugin

## Changelog

## License

This plugin is licensed under the GPL2 license. See the [LICENSE](LICENSE) file for details.