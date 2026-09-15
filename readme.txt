=== Pressable Basic Authentication ===
Contributors: pressable
Tags: pressable, basic auth, authentication, security
Requires at least: 6.7
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 1.0.5
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

== Description ==

The Pressable Basic Authentication plugin enforces HTTP Basic Authentication across your WordPress site, requiring users to authenticate before accessing any page. This is particularly useful for development environments, ensuring that only authorized users can view or interact with the site during development or testing phases.​

== FEATURES ==​

* Enforces HTTP Basic Authentication on all front-end and back-end pages.
* Installed on sites to restrict public access.
* Allows super administrators to bypass authentication for seamless management.
* Integrates with WordPress's authentication system for user verification.
* Provides a mechanism to log out of Basic Authentication sessions.​

== Frequently Asked Questions ==​

= How do I use this plugin? =​

No manual configuration is required. When accessing a protected site, you'll be prompted to enter your WordPress credentials.​

= Can I disable Basic Authentication on my site? =​

Basic Authentication is enforced on sites to protect your site during development. To remove this protection, you can promote your site to a live environment through the MyPressable Control Panel.​

= What credentials should I use to authenticate? =​

Use your WordPress username and password associated with the site. Ensure that your user account has the necessary permissions to access the site.​

== Installation ==​

No manual installation is necessary.​

== Screenshots ==​

* Initial release​

== Changelog ==

= 1.0.5 =
* Fixed: Basic Authentication could be bypassed entirely on any URL, with no
  credentials, by making the request resemble one of the endpoints excluded from
  authentication -- either by naming one in the query string
  (`/?x=wp-json/wp/v2`) or by reaching a gated page through one
  (`/xmlrpc.php/../wp-login.php`). Both served the login form and allowed a full
  WordPress sign-in. Exclusions now match the decoded request path only, and are
  refused for any path containing a `.` or `..` segment.
* Fixed: logging out on a site also running User Switching caused a fatal error.
* Fixed: a logout request no longer reaches wp_logout() without valid credentials.
* Fixed: a logout URL without action=logout is no longer redirected away from the
  logout while still signed in.

= 1.0.4 =
* Reverted the 1.0.3 changes pending verification. Functionally identical to 1.0.2.

= 1.0.3 =
* Deferred logout handling to init to avoid the User Switching conflict. Withdrawn
  in 1.0.4; re-issued, with the exclusion fix above, in 1.0.5.

= 1.0.2 =
* PHP 8.4 compatibility.
