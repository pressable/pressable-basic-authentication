<?php
/**
 * Router for tests/onepress-dispatch-test.php, served by PHP's built-in web server.
 *
 * Loads the plugin, stands in for the few WordPress functions its request path calls
 * and for the OnePress Login plugin, then fires `plugins_loaded` the way WordPress
 * does. The response says which happened: Basic Auth challenged (401), or the
 * request reached OnePress's handler.
 *
 * It runs under the cli-server SAPI on purpose: the plugin waives every CLI request,
 * so only a non-CLI request exercises the real dispatch.
 *
 * @package HostingBasicAuthentication
 */

// Only ever a fixture for the dispatch test, never something a site should serve.
// `/tests export-ignore` keeps it out of the release zip; this is the second layer.
if ( 'cli-server' !== php_sapi_name() ) {
	exit( 1 );
}

define( 'ABSPATH', __DIR__ );

// Mirrors the values tests/onepress-dispatch-test.php mints its token from.
const DISPATCH_SECRET  = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
const DISPATCH_USER_ID = 7;

$GLOBALS['wp_filter'] = array();
$GLOBALS['pagenow']   = basename( strtok( $_SERVER['REQUEST_URI'] ?? '/', '?' ) );

function add_action( $hook, $callback, $priority = 10, $accepted_args = 1 ) {
	$GLOBALS['wp_filter'][ $hook ][ $priority ][] = $callback;
}

function add_filter( $hook, $callback, $priority = 10, $accepted_args = 1 ) {
	add_action( $hook, $callback, $priority, $accepted_args );
}

function do_action( $hook ) {
	$by_priority = $GLOBALS['wp_filter'][ $hook ] ?? array();
	ksort( $by_priority );

	foreach ( $by_priority as $callbacks ) {
		foreach ( $callbacks as $callback ) {
			call_user_func( $callback );
		}
	}
}

function is_multisite() {
	return false;
}

function is_super_admin() {
	return false;
}

function is_user_logged_in() {
	return false;
}

function wp_installing() {
	return false;
}

function wp_doing_ajax() {
	return false;
}

function wp_doing_cron() {
	return false;
}

function esc_html__( $text, $domain = 'default' ) {
	return htmlspecialchars( $text, ENT_QUOTES );
}

function get_user_meta( $user_id, $key = '', $single = false ) {
	if ( DISPATCH_USER_ID !== $user_id || 'mpcp_auth_token' !== $key ) {
		return '';
	}

	return array( 'value' => md5( DISPATCH_SECRET ), 'exp' => time() + 30 );
}

/**
 * Stand-in for Pressable OnePress Login: registers on the same hook and priority, under
 * the same condition, and reports that it was reached instead of logging anyone in.
 */
final class Pressable_OnePress_Login_Plugin {
	public function __construct() {
		if ( 'wp-login.php' === $GLOBALS['pagenow'] && isset( $_REQUEST['mpcp_token'] ) ) {
			add_action( 'plugins_loaded', array( $this, 'handle_server_login_request' ) );
		}
	}

	public function handle_server_login_request() {
		echo 'ONEPRESS-HANDLED';
		exit;
	}
}

require __DIR__ . '/../../pressable-basic-authentication.php';
new Pressable_OnePress_Login_Plugin();

do_action( 'plugins_loaded' );

echo 'NOT-CHALLENGED-NOR-HANDLED';
