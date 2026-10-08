<?php
/**
 * Regression tests for the Basic Auth plugin's hook wiring and its authentication
 * waivers: the User Switching logout conflict, the logout guard's placement, the
 * excluded-endpoint matching, the AJAX check, and the OnePress one-click login waiver.
 *
 * wp_logout() fires the `wp_logout` action, whose subscribers may rely on constants
 * their own plugin defines in a `plugins_loaded` callback. Calling it from this
 * plugin's own `plugins_loaded` callback races that setup and fatals whichever way
 * the load order happens to fall. The logout must therefore stay on `init`, which
 * runs after every `plugins_loaded` callback has completed.
 *
 * Deliberately dependency-free: the repo has no composer/PHPUnit setup. Hook wiring
 * is read from recorded registrations and the methods' source, and request handling
 * is exercised through the private methods with stand-ins for the few WordPress
 * functions they call, so it needs neither WordPress nor a database. Run it with: php tests/hook-registration-test.php
 *
 * @package HostingBasicAuthentication
 */

// This file defines ABSPATH itself, so the usual `defined( 'ABSPATH' ) || exit`
// plugin guard cannot protect it. It sits inside the plugin directory, which the
// web server serves directly without loading WordPress -- so without this guard it
// would print its own output on a site where Basic Authentication returns 401 for
// everything else. The exit status is not an HTTP status: the request still answers
// 200, just with an empty body. `/tests export-ignore` keeps the file out of the
// release zip entirely; this guard is the second layer, for a checkout served direct.
if ( 'cli' !== php_sapi_name() ) {
	exit( 1 );
}

define( 'ABSPATH', __DIR__ );

// Any warning or notice the plugin raises is a failure: one that coerces an
// unexpected input type can otherwise fail closed by coincidence and pass.
$GLOBALS['php_errors'] = array();
set_error_handler(
	function ( $errno, $errstr, $errfile, $errline ) {
		$GLOBALS['php_errors'][] = basename( $errfile ) . ":$errline $errstr";
		return true;
	}
);

$GLOBALS['hooks'] = array();

function add_action( $hook, $callback, $priority = 10, $accepted_args = 1 ) {
	$GLOBALS['hooks'][] = array( 'hook' => $hook, 'callback' => $callback, 'priority' => $priority );
}

function add_filter( $hook, $callback, $priority = 10, $accepted_args = 1 ) {
	$GLOBALS['hooks'][] = array( 'hook' => $hook, 'callback' => $callback, 'priority' => $priority );
}

$GLOBALS['user_meta']         = array();
$GLOBALS['deleted_user_meta'] = array();

function get_user_meta( $user_id, $key = '', $single = false ) {
	return $GLOBALS['user_meta'][ $user_id ][ $key ] ?? '';
}

function delete_user_meta( $user_id, $meta_key, $meta_value = '' ) {
	$GLOBALS['deleted_user_meta'][] = array( $user_id, $meta_key );
	return true;
}

function wp_installing() {
	return ! empty( $GLOBALS['wp_installing'] );
}

// Filterable in WordPress, so either can be true without DOING_AJAX / DOING_CRON.
function wp_doing_ajax() {
	return ! empty( $GLOBALS['wp_doing_ajax'] );
}

function wp_doing_cron() {
	return ! empty( $GLOBALS['wp_doing_cron'] );
}

require __DIR__ . '/../pressable-basic-authentication.php';

$failures = array();

/**
 * Records a single assertion.
 *
 * @param bool   $passed      Whether the assertion held.
 * @param string $description What was asserted.
 */
function check( $passed, $description ) {
	global $failures;

	if ( $passed ) {
		echo "  PASS  $description\n";
		return;
	}

	$failures[] = $description;
	echo "  FAIL  $description\n";
}

/**
 * Finds the hook a given method of the plugin class was registered against.
 *
 * @param string $method Method name.
 * @return array|null The recorded registration, or null when unregistered.
 */
function registration_for( $method ) {
	foreach ( $GLOBALS['hooks'] as $registration ) {
		if ( is_array( $registration['callback'] ) && $registration['callback'][1] === $method ) {
			return $registration;
		}
	}

	return null;
}

/**
 * Returns the source of one method of the plugin class.
 *
 * @param string $method Method name.
 * @return string
 */
function source_of( $method ) {
	if ( ! method_exists( 'Pressable_Basic_Auth', $method ) ) {
		return '';
	}

	$reflected = new ReflectionMethod( 'Pressable_Basic_Auth', $method );
	$lines     = file( $reflected->getFileName() );

	return implode(
		'',
		array_slice( $lines, $reflected->getStartLine() - 1, $reflected->getEndLine() - $reflected->getStartLine() + 1 )
	);
}

echo "Basic Auth hook registration\n";

$logout = registration_for( 'handle_logout_request' );
check( null !== $logout, 'the logout handler is registered' );
check( null !== $logout && 'init' === $logout['hook'], "the logout handler is hooked to 'init'" );

$boot = registration_for( 'init' );
check( null !== $boot && 'plugins_loaded' === $boot['hook'], "init() is still hooked to 'plugins_loaded'" );
check( null !== $boot && 1 === $boot['priority'], 'init() still runs at priority 1, so enforcement stays early' );

// Asserted from both sides on purpose. The negative check alone would pass
// vacuously if handle_basic_auth_logout() were renamed -- silently losing the
// coverage this test exists for -- so the positive check pins the name as live.
// Both match on the trailing "(" so a rename to a superstring (…_logout_renamed)
// does not satisfy either check.
check(
	false !== strpos( source_of( 'handle_logout_request' ), 'handle_basic_auth_logout(' ),
	'the init callback reaches the logout handler'
);

check(
	false === strpos( source_of( 'init' ), 'handle_basic_auth_logout(' ),
	'init() does not invoke the logout handler, so wp_logout() cannot fire on plugins_loaded'
);

check(
	// Short-circuits so a missing method reports a failure rather than throwing a
	// ReflectionException, which would abort the run and hide any later check.
	method_exists( 'Pressable_Basic_Auth', 'handle_logout_request' )
		&& ( new ReflectionMethod( 'Pressable_Basic_Auth', 'handle_logout_request' ) )->isPublic(),
	'the logout handler is public, as a hook callback must be'
);

// The guard that skips session setup on a logout request is bracketed rather than
// merely ordered, because both neighbours are hazards. Above the credential
// handling it would suppress the spurious session -- so the symptom it was added
// for would look fixed -- while also skipping the 401, readmitting the
// unauthenticated caller the logout move excluded. Below the cookie calls it would
// be inert. Anchoring on the LAST send_auth_headers() rather than wp_authenticate()
// is deliberate: between the two, a guard still clears every ordering check yet lets
// INVALID credentials bypass the challenge.
$force          = source_of( 'force_basic_authentication' );
$guard_at       = strpos( $force, "\$_GET['basic-auth-logout']" );
$last_challenge = strrpos( $force, 'send_auth_headers(' );
$cookie_at      = strpos( $force, 'wp_set_auth_cookie(' );

check(
	false !== $guard_at && false !== $last_challenge && $guard_at > $last_challenge,
	'the logout guard sits after every credential challenge, so a logout still requires valid credentials'
);

check(
	false !== $guard_at && false !== $cookie_at && $guard_at < $cookie_at,
	'the logout guard sits before wp_set_auth_cookie(), so a logout establishes no session'
);

// Position alone would be satisfied by a guard whose body no longer returns.
check(
	1 === preg_match( '/if \(\s*isset\(\s*\$_GET\[.basic-auth-logout.\]\s*\)\s*\)\s*\{\s*return;\s*\}/', $force ),
	'the logout guard actually returns, rather than only appearing in the right place'
);

/**
 * Whether should_skip_auth() would waive Basic Authentication for a request URI.
 *
 * Invoked for real rather than inspected as source: the method touches only PHP
 * built-ins and the WordPress stand-ins above, so it runs without WordPress, and a
 * behavioural assertion cannot be satisfied by a rewrite that merely looks different.
 *
 * @param string $uri         Value to place in REQUEST_URI.
 * @param string $script_name Value to place in SCRIPT_NAME -- the script the server
 *                            resolved, which is what xmlrpc.php is matched on and
 *                            what a PATH_INFO request leaves pointing at the script
 *                            rather than at the endpoint trailing it.
 * @return bool
 */
function skips_auth_for( $uri, $script_name = '/index.php' ) {
	// $_SERVER is restored and the plugin instance reused so these checks leave no
	// state behind: every hook-wiring check above reads $GLOBALS['hooks'] and
	// $_SERVER, and a later one appended below this point would otherwise read
	// whatever the last URI here happened to set.
	static $plugin = null;

	if ( null === $plugin ) {
		$plugin = new Pressable_Basic_Auth();
	}

	$original = $_SERVER;

	$_SERVER['REQUEST_URI'] = $uri;
	$_SERVER['SCRIPT_NAME'] = $script_name;

	try {
		$method = new ReflectionMethod( 'Pressable_Basic_Auth', 'should_skip_auth' );
		$method->setAccessible( true );

		return (bool) $method->invoke( $plugin );
	} finally {
		$_SERVER = $original;
	}
}

// An excluded endpoint appearing in the QUERY STRING must never waive
// authentication. Matching those needles against the whole REQUEST_URI let any
// caller disable the plugin on any URL -- `/?x=wp-json/wp/v2` served the front
// page, and the same string on wp-login.php exposed the login form and allowed a
// full WordPress login with no Basic Auth at all.
foreach ( array(
	'/?x=wp-json/wp/v2',
	'/?foo=xmlrpc.php',
	'/?x=wp-json/jetpack',
	'/?x=wp-json/wp/v3',
	'/wp-login.php?x=wp-json/wp/v2',
	'/?p=1&x=wp-json/wp/v2',
) as $uri ) {
	check( false === skips_auth_for( $uri ), "an excluded endpoint in the query string does not waive auth: $uri" );
}

// Trailing segments after a real script land in PATH_INFO: the server executes the
// script and hands the rest to it, so an endpoint spelled there is decoration on a
// gated page. `/wp-login.php/wp-json/wp/v2/` served the login form and allowed a
// full WordPress sign-in with no Basic Auth at all. SCRIPT_NAME is passed as the
// server would set it, and the guard holds on the path alone regardless.
foreach ( array(
	array( '/wp-login.php/wp-json/wp/v2/', '/wp-login.php' ),
	array( '/wp-login.php/xmlrpc.php/', '/wp-login.php' ),
	array( '/index.php/wp-json/wp/v2/', '/index.php' ),
	array( '/wp-login.PHP/wp-json/wp/v2/', '/wp-login.PHP' ),
	array( '/sub1/wp-login.php/wp-json/wp/v2/', '/wp-login.php' ),
	array( '/index.php/wp-json/wp/v2/', '/index.php' ),
	array( '/index.PHP/wp-json/wp/v2/', '/index.php' ),
	array( '/index.php/hello-world/wp-json/wp/v2/', '/index.php' ),
) as $case ) {
	check( false === skips_auth_for( $case[0], $case[1] ), "a PATH_INFO endpoint after a script does not waive auth: {$case[0]}" );
}

// The endpoint must not be preceded by a script the server would execute -- but a
// `.php` segment AFTER it is part of the REST route and must still be excluded.
// Scanning the whole path for `.php` instead, as an earlier fix did, wrongly
// demanded authentication for a valid REST request (caught by the Codex pre-PR
// review, verified against a live install: WordPress dispatches
// /wp-json/wp/v2/custom-route.php to the REST API and returns rest_no_route).
foreach ( array(
	'/wp-json/wp/v2/custom-route.php',
	'/wp-json/wp/v2/media/thing.php',
	'/wp-json/jetpack/v4/x.php',
	'/wp-json/wp/v3/anything.php',
) as $uri ) {
	check( true === skips_auth_for( $uri ), "a .php segment INSIDE a REST route still waives auth: $uri" );
}

// A target beginning `//` must not lose its first segment. parse_url() reads such a
// target as protocol-relative and discards that segment as an authority, so
// `//wp-login.php/wp-json/wp/v2/` parsed to `/wp-json/wp/v2/` with nothing left
// before the endpoint -- while the server preserved it, ran wp-login.php and served
// the login form with no Basic Auth at all. Caught by the Codex pre-PR review.
foreach ( array(
	array( '//wp-login.php/wp-json/wp/v2/', '/wp-login.php' ),
	array( '///wp-login.php/wp-json/wp/v2/', '/wp-login.php' ),
	array( '//index.php/wp-json/wp/v2/', '/index.php' ),
	array( '//wp-login.php/wp-json%2Fwp%2Fv2', '/wp-login.php' ),
) as $case ) {
	check( false === skips_auth_for( $case[0], $case[1] ), "a protocol-relative-looking target keeps its first segment: {$case[0]}" );
}

// Collapsing those leading slashes must not break the endpoint underneath them.
check( true === skips_auth_for( '//wp-json/wp/v2' ), 'an endpoint behind a doubled leading slash is still excluded' );

// A path carrying a traversal segment is not the path the server ends up serving,
// so it must never waive authentication: `/xmlrpc.php/../wp-login.php` resolves to
// wp-login.php while reading as the excluded xmlrpc endpoint, which served the login
// form and allowed a full WordPress login with no Basic Auth at all.
foreach ( array(
	'/xmlrpc.php/../wp-login.php',
	'/xmlrpc.php/%2e%2e/wp-login.php',
	'/xmlrpc%2ephp/../wp-login.php',
	'/wp-json/wp/v2/../wp-login.php',
	'/wp-json/wp/v2/../../wp-login.php',
	'/xmlrpc.php/./../wp-login.php',
	'/xmlrpc.php/../',
) as $uri ) {
	check( false === skips_auth_for( $uri ), "a traversal segment does not waive auth: $uri" );
}

// A needle must match whole path segments, not any substring of one.
check( false === skips_auth_for( '/notwp-json/wp/v2' ), 'a path segment merely ENDING in an excluded endpoint does not waive auth' );

// The genuine exclusions still have to work, including below a subdirectory or
// multisite subsite prefix -- which is why the path is not anchored at its start.
foreach ( array(
	'/wp-json/wp/v2/posts',
	'/wp-json/wp/v2/posts?per_page=1',
	'/wp-json/jetpack/v4/whatever',
	'/wp-json/wp/v3/anything',
	'/sub1/wp-json/wp/v2/posts',
) as $uri ) {
	check( true === skips_auth_for( $uri ), "a genuine excluded endpoint still waives auth: $uri" );
}

// xmlrpc.php is matched on SCRIPT_NAME, not on the requested path, so it holds
// however the request was spelled -- including below a multisite subsite prefix,
// which the network rewrite resolves back to the root script.
foreach ( array(
	array( '/xmlrpc.php', '/xmlrpc.php' ),
	array( '/sub1/xmlrpc.php', '/xmlrpc.php' ),
	array( '/xmlrpc.php?for=jetpack', '/xmlrpc.php' ),
) as $case ) {
	check( true === skips_auth_for( $case[0], $case[1] ), "xmlrpc.php still waives auth via SCRIPT_NAME: {$case[0]}" );
}

check( false === skips_auth_for( '/' ), 'an ordinary request is still gated' );

const ONEPRESS_UA     = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36';
const ONEPRESS_SECRET = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';

/**
 * Builds an mpcp_token the way MPCP's UpdateMpcpAuthToken does: URL-safe base64,
 * unpadded, of "<wp_user_id>-<secret>-<site_id>-<md5(user agent)>".
 *
 * @param int|string $user_id WordPress user id segment.
 * @param string     $suffix  Appended to the payload, to build malformed tokens.
 * @return string
 */
function mpcp_token( $user_id = 7, $suffix = '' ) {
	$payload = $user_id . '-' . ONEPRESS_SECRET . '-1000001-' . md5( ONEPRESS_UA ) . $suffix;

	return rtrim( strtr( base64_encode( $payload ), '+/', '-_' ), '=' );
}

/**
 * Whether should_skip_auth() waives Basic Authentication for a OnePress one-click
 * login request, with every input the check reads set for the duration of the call.
 *
 * @param array $request Overrides for: token (null for absent), user_id (whose meta
 *                       is stored), meta (the stored mpcp_auth_token), user_agent,
 *                       pagenow, installing, doing_ajax, doing_cron (the wp_*()
 *                       results), request_token ($_REQUEST's mpcp_token, null for
 *                       absent; defaults to the $_GET token, as request_order GP gives).
 * @return bool
 */
function skips_auth_for_onepress( array $request = array() ) {
	static $plugin = null;

	if ( null === $plugin ) {
		$plugin = new Pressable_Basic_Auth();
	}

	$request += array(
		'token'      => mpcp_token(),
		'user_id'    => 7,
		'meta'       => array( 'value' => md5( ONEPRESS_SECRET ), 'exp' => time() + 30 ),
		'user_agent' => ONEPRESS_UA,
		'pagenow'    => 'wp-login.php',
		'installing' => false,
		'doing_ajax' => false,
		'doing_cron' => false,
	);

	if ( ! array_key_exists( 'request_token', $request ) ) {
		$request['request_token'] = $request['token'];
	}

	$GLOBALS['wp_installing'] = $request['installing'];
	$GLOBALS['wp_doing_ajax'] = $request['doing_ajax'];
	$GLOBALS['wp_doing_cron'] = $request['doing_cron'];

	$original_server  = $_SERVER;
	$original_get     = $_GET;
	$original_request = $_REQUEST;
	$original_pagenow = $GLOBALS['pagenow'] ?? null;

	$_SERVER['REQUEST_URI']     = '/wp-login.php';
	$_SERVER['SCRIPT_NAME']     = '/wp-login.php';
	$_SERVER['HTTP_USER_AGENT'] = $request['user_agent'];
	$_GET                       = null === $request['token'] ? array() : array( 'mpcp_token' => $request['token'] );
	$_REQUEST                   = null === $request['request_token'] ? array() : array( 'mpcp_token' => $request['request_token'] );
	$GLOBALS['pagenow']         = $request['pagenow'];
	$GLOBALS['user_meta']       = array( $request['user_id'] => array( 'mpcp_auth_token' => $request['meta'] ) );

	try {
		$method = new ReflectionMethod( 'Pressable_Basic_Auth', 'should_skip_auth' );
		$method->setAccessible( true );

		return (bool) $method->invoke( $plugin );
	} finally {
		$_SERVER              = $original_server;
		$_GET                 = $original_get;
		$_REQUEST             = $original_request;
		$GLOBALS['pagenow']       = $original_pagenow;
		$GLOBALS['user_meta']     = array();
		$GLOBALS['wp_installing'] = false;
		$GLOBALS['wp_doing_ajax'] = false;
		$GLOBALS['wp_doing_cron'] = false;
	}
}

// Without OnePress loaded nothing would consume the token, so waiving the challenge
// would only expose the wp-login.php password form with no Basic Auth in front of it.
// Asserted before the stand-in class below is declared, which cannot be undone.
check( false === skips_auth_for_onepress(), 'a valid one-click token does not waive auth when OnePress is not active' );

if ( ! class_exists( 'Pressable_OnePress_Login_Plugin' ) ) {
	final class Pressable_OnePress_Login_Plugin {}
}

// The MPCP WP Admin button redirects to wp-login.php?mpcp_token=…, which OnePress
// validates on `plugins_loaded` priority 10 -- after this plugin's priority-1 challenge
// has already ended the request. A valid token must therefore get through here.
check( true === skips_auth_for_onepress(), 'a valid, unexpired one-click token on wp-login.php waives auth' );

// MPCP omits base64 padding. User id 7 gives a payload needing one `=`; 77 needs none.
check(
	true === skips_auth_for_onepress( array( 'token' => mpcp_token( 77 ), 'user_id' => 77 ) ),
	'a one-click token whose encoding has no padding to omit also waives auth'
);

$GLOBALS['deleted_user_meta'] = array();
skips_auth_for_onepress();
check(
	array() === $GLOBALS['deleted_user_meta'],
	'validating the token does not consume it -- OnePress deletes it when it logs the user in'
);

foreach ( array(
	'no token'                       => array( 'token' => null ),
	'an empty token'                 => array( 'token' => '' ),
	'a token passed as an array'     => array( 'token' => array( mpcp_token() ) ),
	'a page other than wp-login.php' => array( 'pagenow' => 'index.php' ),
	'an expired token'               => array( 'meta' => array( 'value' => md5( ONEPRESS_SECRET ), 'exp' => time() - 1 ) ),
	'a wrong secret'                 => array( 'meta' => array( 'value' => md5( 'other' ), 'exp' => time() + 30 ) ),
	'a different user agent'         => array( 'user_agent' => 'curl/8.4.0' ),
	'no stored token'                => array( 'meta' => '' ),
	'a stored token missing exp'     => array( 'meta' => array( 'value' => md5( ONEPRESS_SECRET ) ) ),
	'a stored token missing value'   => array( 'meta' => array( 'exp' => time() + 30 ) ),
	'a non-array stored token'       => array( 'meta' => md5( ONEPRESS_SECRET ) ),
	'a token for another user'       => array( 'user_id' => 8 ),
	'a token that is not base64'     => array( 'token' => '!!!not*base64!!!' ),
	'a token with too few parts'     => array( 'token' => rtrim( strtr( base64_encode( '7-' . ONEPRESS_SECRET . '-1000001' ), '+/', '-_' ), '=' ) ),
	'a token with extra parts'       => array( 'token' => mpcp_token( 7, '-x' ) ),
	// (int) '7abc' is 7, so this reaches user 7's real token unless the id is rejected first.
	'a non-numeric user id'          => array( 'token' => mpcp_token( '7abc' ) ),
	// Leading zeros keep the id numeric and (int) 7, so only the length cap rejects this.
	'an overlong token'              => array( 'token' => mpcp_token( str_repeat( '0', 300 ) . '7' ) ),
	// OnePress hashes the raw header, so a value it cannot hash must not be coerced here.
	'a non-string user agent'        => array( 'user_agent' => array( ONEPRESS_UA ) ),
	// OnePress registers no login handler while WordPress is installing.
	'WordPress installing'           => array( 'installing' => true ),
	// OnePress registers on, and reads, $_REQUEST. With a request_order that leaves out
	// G it never sees a query-string token, and a body value can differ from the query one.
	'the token absent from $_REQUEST' => array( 'request_token' => null ),
	'a different $_REQUEST token'     => array( 'request_token' => mpcp_token( 8 ) ),
	// wp_doing_ajax() and wp_doing_cron() are filterable, so either can stand OnePress
	// down while the DOING_* constants skip_request() checks are still unset.
	'wp_doing_ajax() filtered true'  => array( 'doing_ajax' => true ),
	'wp_doing_cron() filtered true'  => array( 'doing_cron' => true ),
) as $description => $request ) {
	check( false === skips_auth_for_onepress( $request ), "a one-click request with $description does not waive auth" );
}

// OnePress rejects only `exp < time()`, so a token in its final second is still live.
// Run in the first half of a second so time() cannot tick between setup and check.
while ( fmod( microtime( true ), 1 ) > 0.5 ) {
	usleep( 10000 );
}
check(
	true === skips_auth_for_onepress( array( 'meta' => array( 'value' => md5( ONEPRESS_SECRET ), 'exp' => time() ) ) ),
	'a one-click token expiring this second still waives auth, as OnePress accepts it'
);

// is_ajax_request() is tested directly rather than through skip_request(): this file runs
// under the CLI SAPI, so is_cli_request() (a sibling arm of skip_request()) is always true
// here and would mask everything else.
function is_ajax_for( $x_requested_with ) {
	static $plugin = null;

	if ( null === $plugin ) {
		$plugin = new Pressable_Basic_Auth();
	}

	$original = isset( $_SERVER['HTTP_X_REQUESTED_WITH'] ) ? $_SERVER['HTTP_X_REQUESTED_WITH'] : null;
	if ( null === $x_requested_with ) {
		unset( $_SERVER['HTTP_X_REQUESTED_WITH'] );
	} else {
		$_SERVER['HTTP_X_REQUESTED_WITH'] = $x_requested_with;
	}

	try {
		$method = new ReflectionMethod( 'Pressable_Basic_Auth', 'is_ajax_request' );
		$method->setAccessible( true );

		return (bool) $method->invoke( $plugin );
	} finally {
		if ( null === $original ) {
			unset( $_SERVER['HTTP_X_REQUESTED_WITH'] );
		} else {
			$_SERVER['HTTP_X_REQUESTED_WITH'] = $original;
		}
	}
}

// The `X-Requested-With: XMLHttpRequest` request header must NOT count as AJAX. It is
// caller-controlled, so keying an auth waiver on it let any anonymous request turn Basic
// Auth off on any URL, wp-login.php included, by sending one header (caught in review by
// Mitch). is_ajax_request() is the first arm of skip_request(), so a true here is a waiver.
check( false === is_ajax_for( 'XMLHttpRequest' ), 'the X-Requested-With header does not count as AJAX' );
check( false === is_ajax_for( 'xmlhttprequest' ), 'the X-Requested-With header (lowercased) does not count as AJAX' );
check( false === is_ajax_for( null ), 'a plain request with no such header is not AJAX' );

// Real WordPress AJAX still bypasses: admin-ajax.php defines DOING_AJAX itself, which a
// caller cannot forge. Asserted last, because define() is process-global and irreversible.
define( 'DOING_AJAX', true );
check( true === is_ajax_for( null ), 'a genuine DOING_AJAX request is still AJAX (bypasses)' );

// OnePress registers no login handler under WP-CLI. Asserted last for the same reason.
define( 'WP_CLI', true );
check( false === skips_auth_for_onepress(), 'a one-click request under WP-CLI does not waive auth' );

check(
	array() === $GLOBALS['php_errors'],
	'no check raised a PHP warning or notice' . ( $GLOBALS['php_errors'] ? ': ' . implode( '; ', $GLOBALS['php_errors'] ) : '' )
);

echo "\n";

if ( $failures ) {
	echo count( $failures ) . " failure(s)\n";
	exit( 1 );
}

echo "All checks passed\n";
exit( 0 );
