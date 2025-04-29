<?php
/**
 * Hosting Basic Authentication
 *
 * @package HostingBasicAuthentication
 */

/*
Plugin Name: Hosting Basic Authentication
Description: Forces all users to authenticate using Basic Authentication before accessing any page.
Version: 1.0.1
License: GPL2
Text Domain: hosting-basic-authentication
*/

// If this file is called directly, abort.
if ( ! defined( 'ABSPATH' ) ) {
	exit; // Prevent direct access
}

/**
 * Main plugin class
 */
class Pressable_Basic_Auth {

	/**
	 * Constructor
	 */
	public function __construct() {
		if ( is_multisite() ) {
			add_action( 'ms_loaded', array( $this, 'init' ), 1 );
		} else {

			add_action( 'plugins_loaded', array( $this, 'init' ), 1 );
		}

		// Add filter for logout URL.
		add_filter( 'logout_url', array( $this, 'modify_logout_url' ), 10, 2 );

		// Hook into login page early
		add_action( 'login_init', array( $this, 'handle_login_redirect' ), 0 );
	}

	/**
	 * Initialize the plugin
	 */
	public function init() {
		// Skip if we're doing AJAX.
		if ( $this->is_ajax_request() ) {
			return;
		}

		// Skip if we're doing CRON.
		if ( $this->is_cron_request() ) {
			return;
		}

		// Skip if we're in CLI mode.
		if ( $this->is_cli_request() ) {
			return;
		}

		// Handle logout request.
		if ( isset( $_GET['basic-auth-logout'] ) && isset( $_GET['_basic_auth_nonce'] ) && wp_verify_nonce( $_GET['_basic_auth_nonce'], 'basic-auth-logout' ) ) {
			$this->handle_basic_auth_logout();
		}

		// Force authentication.
		$this->force_basic_authentication();
	}

	/**
	 * Force Basic Authentication
	 */
	private function force_basic_authentication() {		
		// Prevent caching of authentication requests.
		$this->prevent_caching();

		// Extract credentials from headers.
		$this->extract_basic_auth_credentials();

		// Allow Super Admins to bypass authentication.
		if ( is_multisite() && is_super_admin() ) {
			return;
		}

		// Check if the user is already logged in.
		if ( is_user_logged_in() ) {
			return;
		}

		// Check for Basic Authentication credentials.
		$auth_user = isset( $_SERVER['PHP_AUTH_USER'] ) ? sanitize_text_field( wp_unslash( $_SERVER['PHP_AUTH_USER'] ) ) : null;
		$auth_pass = isset( $_SERVER['PHP_AUTH_PW'] ) ? wp_unslash( $_SERVER['PHP_AUTH_PW'] ) : null;

		if ( ! $auth_user || ! $auth_pass ) {
			$this->log_failed_auth( 'Missing credentials' );
			$this->send_auth_headers();
		}

		// Validate credentials against WordPress users table.
		$user = wp_authenticate( $auth_user, $auth_pass );
		if ( is_wp_error( $user ) ) {
			$this->log_failed_auth( "Invalid credentials for user: $auth_user" );
			$this->send_auth_headers();
		}

		// Log the user in programmatically.
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID );
	}

	/**
	 * Logs failed authentication attempts to the error log.
	 *
	 * @param string $message The message to log.
	 */
	private function log_failed_auth( $message ) {
		if ( apply_filters( 'basic_auth_log_errors', defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) ) {
			error_log(
				sprintf(
					'[%s] Basic Auth Failed: %s',
					gmdate( 'Y-m-d H:i:s' ),
					$message
				)
			);
		}
	}

	/**
	 * Sends authentication headers.
	 */
	private function send_auth_headers() {
		header( 'WWW-Authenticate: Basic realm="Restricted Area"' );
		header( 'HTTP/1.1 401 Unauthorized' );
		echo '<h1>' . esc_html__( 'Authentication Required', 'hosting-basic-authentication' ) . '</h1>';
		exit;
	}

	/**
	 * Use getallheaders() for Servers That Strip Authorization Headers
	 */
	private function extract_basic_auth_credentials() {
		if ( ! empty( $_SERVER['PHP_AUTH_USER'] ) && ! empty( $_SERVER['PHP_AUTH_PW'] ) ) {
			// Sanitize credentials even when just checking
			$_SERVER['PHP_AUTH_USER'] = sanitize_text_field( wp_unslash( $_SERVER['PHP_AUTH_USER'] ) );
			// No sanitization for password to preserve special characters
			$_SERVER['PHP_AUTH_PW'] = wp_unslash( $_SERVER['PHP_AUTH_PW'] );
			return;
		}

		// Attempt to fetch credentials from Authorization header.
		$auth_header = $this->get_authorization_header();

		if ( ! $auth_header ) {
			return;
		}

		if ( 0 === stripos( $auth_header, 'basic ' ) ) {
			$auth_encoded = substr( $auth_header, 6 );
			$auth_decoded = base64_decode( $auth_encoded );
			if ( $auth_decoded && strpos( $auth_decoded, ':' ) !== false ) {
				list( $user, $pw ) = explode( ':', $auth_decoded, 2 );
				$_SERVER['PHP_AUTH_USER'] = sanitize_text_field( $user );
				$_SERVER['PHP_AUTH_PW'] = $pw;
			}
		}
	}

	/**
	 * Get the authorization header
	 *
	 * @return string|null The authorization header value or null
	 */
	private function get_authorization_header() {
		if ( function_exists( 'getallheaders' ) ) {
			$headers = getallheaders();

			// Check for Authorization header (case-insensitive).
			foreach ( $headers as $key => $value ) {
				if ( strtolower( $key ) === 'authorization' ) {
					return $value;
				}
			}
		}

		// Try common alternative locations.
		if ( isset( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			return wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] );
		} elseif ( isset( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ) {
			return wp_unslash( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] );
		}

		return null;
	}

	/**
	 * Handles Basic Auth logout by forcing a 401 response and then redirecting.
	 */
	private function handle_basic_auth_logout() {
		wp_logout(); // Log out from WordPress.

		// Clear Basic Auth credentials by forcing a 401.
		header( 'WWW-Authenticate: Basic realm="Restricted Area"' );
		header( 'HTTP/1.1 401 Unauthorized' );

		// After the 401 is processed, instruct the browser to navigate away.
		header( 'Refresh: 1; url=' . home_url() );

		// Prevent caching of this response.
		$this->prevent_caching(); // Good practice to prevent caching of the 401/logout page

		// Output minimal HTML with a meta refresh tag for redirection.
		// This gives the browser a moment to process the 401 before redirecting.
		$redirect_url = esc_url( home_url() );
		?>
		<!DOCTYPE html>
		<html>
		<head>
			<meta charset="<?php bloginfo( 'charset' ); ?>">
			<title><?php esc_html_e( 'Logging Out...', 'hosting-basic-authentication' ); ?></title>
			<meta http-equiv="refresh" content="1;url=<?php echo $redirect_url; ?>">
			<style>body { font-family: sans-serif; padding: 20px; }</style>
		</head>
		<body>
			<h1><?php esc_html_e( 'Logout Successful', 'hosting-basic-authentication' ); ?></h1>
			<p><?php esc_html_e( 'You have been logged out. You will be redirected shortly.', 'hosting-basic-authentication' ); ?></p>
			<p><a href="<?php echo $redirect_url; ?>"><?php esc_html_e( 'Click here if you are not redirected.', 'hosting-basic-authentication' ); ?></a></p>
		</body>
		</html>
		<?php

		// End execution to prevent further processing and ensure headers are sent.
		exit;
	
	}

	/**
	 * Modifies the default WordPress logout URL to trigger Basic Auth logout.
	 *
	 * @param string $logout_url The WordPress logout URL.
	 * @param string $redirect   The redirect URL after logout.
	 * @return string Modified logout URL
	 */
	public function modify_logout_url( $logout_url, $redirect ) {
		$nonce = wp_create_nonce( 'basic-auth-logout')
		return add_query_arg( array(
			'basic-auth-logout' => '1', 
			'_basic_auth_nonce' => $nonce,
		), $logout_url );
	}

	/**
	 * Redirects from wp-login.php to home page when user is already authenticated via Basic Auth
	 * Public method that can be used as a hook callback
	 */
	public function handle_login_redirect() {
		global $pagenow;

		// Sanitize auth credentials before checking
		$auth_user = isset($_SERVER['PHP_AUTH_USER']) ? sanitize_text_field(wp_unslash($_SERVER['PHP_AUTH_USER'])) : '';
		$auth_pw   = isset($_SERVER['PHP_AUTH_PW']) ? wp_unslash($_SERVER['PHP_AUTH_PW']) : ''; // No sanitization needed for password comparison

		// Check if we're on the login page and have Basic Auth credentials
		// Also check we're not performing an action like logout, password reset, etc.
		if ( 'wp-login.php' === $pagenow && is_user_logged_in() &&
		     ! empty( $auth_user ) &&
		     ! empty( $auth_pw ) &&
		     ! isset( $_GET['action'] ) && // Exclude actions like 'logout', 'rp', 'register'
		     ! isset( $_GET['loggedout'] ) && // Exclude message after logout
		     ! isset( $_POST['log'] ) ) { // Exclude actual login form submission

			// Determine the correct redirect URL
			$redirect_url = '';
			if ( is_multisite() ) {
				// Use get_current_blog_id() for reliability in multisite
				$current_blog_id = get_current_blog_id();
				$redirect_url = get_home_url( $current_blog_id );

				//fallback to network home URL if site-specific home URL is somehow unavailable
				if ( empty( $redirect_url ) ) {
					$redirect_url = network_home_url();
				}
			} else {
				// Single site: just use the regular home URL
				$redirect_url = home_url();
			}

			//Ensure we have a valid URL before redirecting
			if ( ! empty( $redirect_url ) ) {
				// Safe redirect to the determined home page
				wp_safe_redirect( $redirect_url );
				exit;
			} else {
				wp_die("Could not determine redirect URL. ");
			}

		}
	}

	/**
	 * Prevent caching of authentication requests
	 */
	private function prevent_caching() {
		header( 'Cache-Control: no-cache, must-revalidate, max-age=0' );
		header( 'Pragma: no-cache' );
		header( 'Expires: Wed, 11 Jan 1984 05:00:00 GMT' );
	}

	/**
	 * Check if the current request is an AJAX request
	 *
	 * @return bool
	 */
	private function is_ajax_request() {
		return ( defined( 'DOING_AJAX' ) && DOING_AJAX ) ||
		       ( ! empty( $_SERVER['HTTP_X_REQUESTED_WITH'] ) && 'xmlhttprequest' === strtolower( $_SERVER['HTTP_X_REQUESTED_WITH'] ) );
	}

	/**
	 * Check if the current request is a cron request
	 *
	 * @return bool
	 */
	private function is_cron_request() {
		return defined( 'DOING_CRON' ) && DOING_CRON;
	}

	/**
	 * Check if the current request is a CLI request
	 *
	 * @return bool
	 */
	private function is_cli_request() {
		return ( 'cli' === php_sapi_name() || ( defined( 'WP_CLI' ) && WP_CLI ) );
	}
}

// Initialize the plugin.
new Pressable_Basic_Auth();
