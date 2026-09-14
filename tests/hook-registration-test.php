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
// answers 200 on a site where Basic Authentication returns 401 for everything else.
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

echo "\n";

if ( $failures ) {
	echo count( $failures ) . " failure(s)\n";
	exit( 1 );
}

echo "All checks passed\n";
exit( 0 );
