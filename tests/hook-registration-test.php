<?php
/**
 * Regression test for the Basic Auth / User Switching logout conflict.
 *
 * wp_logout() fires the `wp_logout` action, whose subscribers may rely on constants
 * their own plugin defines in a `plugins_loaded` callback. Calling it from this
 * plugin's own `plugins_loaded` callback races that setup and fatals whichever way
 * the load order happens to fall. The logout must therefore stay on `init`, which
 * runs after every `plugins_loaded` callback has completed.
 *
 * Deliberately dependency-free: the repo has no composer/PHPUnit setup, and this
 * asserts hook wiring rather than request behaviour, so it needs neither WordPress
 * nor a database. Run it with: php tests/hook-registration-test.php
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

$GLOBALS['hooks'] = array();

function add_action( $hook, $callback, $priority = 10, $accepted_args = 1 ) {
	$GLOBALS['hooks'][] = array( 'hook' => $hook, 'callback' => $callback, 'priority' => $priority );
}

function add_filter( $hook, $callback, $priority = 10, $accepted_args = 1 ) {
	$GLOBALS['hooks'][] = array( 'hook' => $hook, 'callback' => $callback, 'priority' => $priority );
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
 * Invoked for real rather than inspected as source: the method touches only
 * basename() and parse_url(), so it runs without WordPress, and a behavioural
 * assertion cannot be satisfied by a rewrite that merely looks different.
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

echo "\n";

if ( $failures ) {
	echo count( $failures ) . " failure(s)\n";
	exit( 1 );
}

echo "All checks passed\n";
exit( 0 );
