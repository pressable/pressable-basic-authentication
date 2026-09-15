<?php
/**
 * Hosting Basic Authentication
 *
 * @package HostingBasicAuthentication
 */

/*
Plugin Name: Hosting Basic Authentication
Description: Forces all users to authenticate using Basic Authentication before accessing any page.
Version: 1.0.5
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
		// Hook into WordPress before anything is outputted.
		add_action( 'plugins_loaded', array( $this, 'init' ), 1 );

		// Logout is handled on `init`, deliberately later than the rest of `init()`.
		// wp_logout() fires the `wp_logout` action, and its subscribers may rely on
		// constants their own plugin defines in a `plugins_loaded` callback. Firing it
		// from `plugins_loaded` priority 1 races that setup, and which plugin wins the
		// race depends on load order -- `active_plugins` ordering, anything filtering
		// it, and network-activated plugins, which load earlier still. User Switching
		// defines its cookie constants that way, so wherever this plugin happens to run
		// first, User Switching's `wp_logout` subscriber fatals on a constant it has
		// not defined yet. Hooking to `init` drops the dependency on load order
		// entirely: every `plugins_loaded` callback has completed by then.
		add_action( 'init', array( $this, 'handle_logout_request' ), 1 );

		// Add filter for logout URL.
		add_filter( 'logout_url', array( $this, 'modify_logout_url' ), 10, 2 );

		// Hook into login page early
		add_action( 'login_init', array( $this, 'maybe_redirect_from_login_page' ), 0 );
	}

	/**
	 * Initialize the plugin
	 */
	public function init() {
		if ( $this->skip_request() ) {
			return;
		}

		// Redirect from wp-login.php when already authenticated via Basic Auth
		$this->maybe_redirect_from_login_page();

		// Force authentication.
		$this->force_basic_authentication();
	}

	/**
	 * Handles the Basic Auth logout request.
	 *
	 * Hooked to `init` rather than running with the rest of init() on
	 * `plugins_loaded` -- see the hook registration in the constructor for why.
	 */
	public function handle_logout_request() {
		if ( $this->skip_request() ) {
			return;
		}

		if ( ! isset( $_GET['basic-auth-logout'] ) ) {
			return;
		}

		$this->handle_basic_auth_logout();
	}

	/**
	 * Whether this request is outside the scope of Basic Authentication.
	 *
	 * @return bool
	 */
	private function skip_request() {
		return $this->is_ajax_request()
			|| $this->is_cron_request()
			|| $this->is_cli_request()
			|| $this->should_skip_auth();
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
		$auth_pass = isset( $_SERVER['PHP_AUTH_PW'] ) ? $_SERVER['PHP_AUTH_PW'] : null;

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

		// A request asking to log out must still clear the authentication gate above --
		// that is what keeps an anonymous caller from reaching wp_logout() -- but it must
		// not be given a session that handle_logout_request() discards moments later on
		// `init`. Establishing one fires set_auth_cookie and set_logged_in_cookie on what
		// is only ever a logout, which an audit or session-tracking plugin can reasonably
		// record as a real login.
		//
		// Skipping wp_set_current_user() as well as the cookies is correct, not a
		// shortcut: execution only reaches here when nobody is logged in -- a live session
		// returns above -- so there is no established identity for the following
		// wp_logout() to report. It passes whatever get_current_user_id() actually holds,
		// which is 0, instead of one this method manufactured moments earlier purely to
		// tear it down again.
		//
		// Placement is load-bearing in both directions. Above the credential handling this
		// would skip the 401 as well, readmitting the unauthenticated caller it exists to
		// exclude; below the cookie calls it would do nothing at all.
		if ( isset( $_GET['basic-auth-logout'] ) ) {
			return;
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
		error_log(
			sprintf(
				'[%s] Basic Auth Failed: %s',
				gmdate( 'Y-m-d H:i:s' ),
				$message
			)
		);
	}

	/**
     * Check if the current request should skip authentication
     *
     * @return bool
     */
    private function should_skip_auth() {
        // List of endpoints to exclude from Basic Auth
        $excluded_endpoints = array(
            'xmlrpc.php',
            'wp-json/jetpack',
            'wp-json/wp/v2',
            'wp-json/wp/v3'
        );

        // Get current request details
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        $script_name = $_SERVER['SCRIPT_NAME'] ?? '';

        // Check if this is a direct xmlrpc.php request
        if (basename($script_name) === 'xmlrpc.php') {
            return true;
        }

        // Check all excluded endpoints
        foreach ($excluded_endpoints as $endpoint) {
            if (strpos($request_uri, $endpoint) !== false) {
                return true;
            }
        }

        // Check WordPress constants
        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
            return true;
        }

        if (defined('REST_REQUEST') && REST_REQUEST) {
            return true;
        }

        return false;
    }

	/**
	 * Sends authentication headers.
	 */
	private function send_auth_headers() {
		header( 'WWW-Authenticate: Basic realm="Restricted Area"' );
		header( 'HTTP/1.1 401 Unauthorized' );
		echo '<h1>' . esc_html__( 'Authentication Required', 'pressable-basic-auth' ) . '</h1>';
		exit;
	}

	/**
	 * Use getallheaders() for Servers That Strip Authorization Headers
	 */
	private function extract_basic_auth_credentials() {
		if ( ! empty( $_SERVER['PHP_AUTH_USER'] ) && ! empty( $_SERVER['PHP_AUTH_PW'] ) ) {
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
				list( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] ) = explode( ':', $auth_decoded, 2 );
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

		// Output a JavaScript-based redirect after the 401 response.
		echo '<script>
			setTimeout(function() {
				window.location.href = "' . esc_url( home_url() ) . '";
			}, 1000);
		</script>';

		// End execution to prevent further processing.
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
		return add_query_arg( 'basic-auth-logout', '1', $logout_url );
	}

	/**
	 * Redirects from wp-login.php to home page when user is already authenticated via Basic Auth
	 */
	public function maybe_redirect_from_login_page() {
		global $pagenow;

		// A request that asks to log out is never redirected away from the logout. This
		// guard only matters on wp-login.php, and only for a logout URL that omits
		// `action=logout` -- the URL modify_logout_url() builds always carries it. Since
		// the logout moved to `init`, this method now runs first, and without the guard
		// such a request would redirect to the home page still logged in, with no error.
		if ( isset( $_GET['basic-auth-logout'] ) ) {
			return;
		}

		// Check if we're on the login page and have Basic Auth credentials
		if ( 'wp-login.php' === $pagenow &&
		     ! empty( $_SERVER['PHP_AUTH_USER'] ) &&
		     ! empty( $_SERVER['PHP_AUTH_PW'] ) &&
		     ! isset( $_GET['action'] ) &&
		     ! isset( $_GET['loggedout'] ) &&
		     ! isset( $_POST['log'] ) ) {

			// Get appropriate home URL for either multisite or regular WordPress
			if ( is_multisite() ) {
				$redirect_url = network_home_url();

				// If we can determine the current blog, go to its home instead
				if ( isset( $_SERVER['HTTP_HOST'] ) ) {
					$blog_details = get_blog_details( array( 'domain' => $_SERVER['HTTP_HOST'] ) );
					if ( $blog_details ) {
						$redirect_url = get_home_url( $blog_details->blog_id );
					}
				}
			} else {
				$redirect_url = home_url();
			}

			// Safe redirect
			wp_safe_redirect( $redirect_url );
			exit;
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