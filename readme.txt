=== Pressable Basic Authentication === Contributors: pressable Tags: pressable, basic auth, authentication, sandbox, security Requires at least: 6.0 Tested up to: 6.1 Requires PHP: 7.4 Stable tag: 1.0.0 License: GPLv2 or later License URI: http://www.gnu.org/licenses/gpl-2.0.html​

== Description ==​

The Pressable Basic Authentication plugin enforces HTTP Basic Authentication across your WordPress site, requiring users to authenticate before accessing any page. This is particularly useful for sandbox and staging environments, ensuring that only authorized users can view or interact with the site during development or testing phases.​

FEATURES​

Enforces HTTP Basic Authentication on all front-end and back-end pages.
Automatically installed on sandbox environments to restrict public access.
Allows super administrators to bypass authentication for seamless management.
Integrates with WordPress's authentication system for user verification.
Provides a mechanism to log out of Basic Authentication sessions.​
== Frequently Asked Questions ==​

= How do I use this plugin? =​

This plugin is automatically installed and activated on sandbox environments within Pressable. No manual configuration is required. When accessing a protected site, you'll be prompted to enter your WordPress credentials.​

= Can I disable Basic Authentication on my site? =​

Basic Authentication is enforced on sandbox environments to protect your site during development. To remove this protection, you can promote your site to a live environment through the MyPressable Control Panel.​

= What credentials should I use to authenticate? =​

Use your WordPress username and password associated with the site. Ensure that your user account has the necessary permissions to access the site.​

== Installation ==​

This plugin is automatically installed and activated on sandbox environments within Pressable. No manual installation is necessary.​

== Screenshots ==​

Basic Authentication prompt when accessing a protected site.​
== Changelog ==​

= 1.0.0 =

Initial release​