<?php
/**
 * Dispatch test for the OnePress one-click login waiver.
 *
 * tests/hook-registration-test.php checks the waiver's validation by calling
 * should_skip_auth() directly, because under the CLI SAPI is_cli_request() waives
 * every request and would mask it. This test covers the path those checks cannot: a
 * real HTTP request through `plugins_loaded`, init() and skip_request() to the
 * challenge, served by PHP's built-in web server (the cli-server SAPI) from
 * tests/fixtures/onepress-dispatch-router.php.
 *
 * Dependency-free like the hook test. Run it with: php tests/onepress-dispatch-test.php
 *
 * @package HostingBasicAuthentication
 */

// Same guard and reason as tests/hook-registration-test.php: never run over HTTP.
if ( 'cli' !== php_sapi_name() ) {
	exit( 1 );
}

const DISPATCH_SECRET = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
const DISPATCH_UA     = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36';

$failures = array();

function check( $passed, $description ) {
	global $failures;

	if ( $passed ) {
		echo "  PASS  $description\n";
		return;
	}

	$failures[] = $description;
	echo "  FAIL  $description\n";
}

function dispatch_token( $user_agent = DISPATCH_UA ) {
	$payload = '7-' . DISPATCH_SECRET . '-1000001-' . md5( $user_agent );

	return rtrim( strtr( base64_encode( $payload ), '+/', '-_' ), '=' );
}

// Ask the OS for a free port rather than hard-coding one a CI runner may have in use.
$probe = stream_socket_server( 'tcp://127.0.0.1:0' );
$port  = (int) substr( strrchr( stream_socket_get_name( $probe, false ), ':' ), 1 );
fclose( $probe );

$server = proc_open(
	array( PHP_BINARY, '-S', "127.0.0.1:$port", __DIR__ . '/fixtures/onepress-dispatch-router.php' ),
	array( 1 => array( 'file', '/dev/null', 'w' ), 2 => array( 'file', '/dev/null', 'w' ) ),
	$pipes
);

register_shutdown_function(
	function () use ( $server ) {
		proc_terminate( $server );
		proc_close( $server );
	}
);

$ready = false;

for ( $attempt = 0; $attempt < 50 && ! $ready; $attempt++ ) {
	$connection = @fsockopen( '127.0.0.1', $port, $errno, $errstr, 0.1 );

	if ( $connection ) {
		fclose( $connection );
		$ready = true;
	} else {
		usleep( 100000 );
	}
}

if ( ! $ready ) {
	echo "FAIL  the built-in server did not start on port $port\n";
	exit( 1 );
}

/**
 * Requests a path from the router and returns its status, challenge header and body.
 *
 * @param string $path       Request path and query.
 * @param string $user_agent User-Agent header to send.
 * @return array{status: int, challenged: bool, body: string}
 */
function dispatch( $path, $user_agent = DISPATCH_UA ) {
	global $port;

	$context = stream_context_create(
		array(
			'http' => array(
				'header'        => "User-Agent: $user_agent\r\n",
				'ignore_errors' => true,
				'timeout'       => 10,
			),
		)
	);

	$body    = (string) @file_get_contents( "http://127.0.0.1:$port$path", false, $context );
	$headers = $http_response_header ?? array();
	$status  = preg_match( '#^HTTP/\S+ (\d{3})#', $headers[0] ?? '', $match ) ? (int) $match[1] : 0;

	return array(
		'status'     => $status,
		'challenged' => (bool) preg_grep( '/^WWW-Authenticate: Basic/i', $headers ),
		'body'       => $body,
	);
}

echo "OnePress waiver dispatch (built-in server)\n";

$valid = dispatch( '/wp-login.php?mpcp_token=' . dispatch_token() );
check(
	200 === $valid['status'] && ! $valid['challenged'] && 'ONEPRESS-HANDLED' === $valid['body'],
	'a valid one-click token reaches OnePress through plugins_loaded with no challenge'
);

foreach ( array(
	'no token'               => array( '/wp-login.php', DISPATCH_UA ),
	'a different user agent' => array( '/wp-login.php?mpcp_token=' . dispatch_token(), 'curl/8.4.0' ),
	'a token for another UA' => array( '/wp-login.php?mpcp_token=' . dispatch_token( 'curl/8.4.0' ), DISPATCH_UA ),
	'a page other than wp-login.php' => array( '/?mpcp_token=' . dispatch_token(), DISPATCH_UA ),
) as $description => list( $path, $user_agent ) ) {
	$response = dispatch( $path, $user_agent );
	check(
		401 === $response['status'] && $response['challenged'] && 'ONEPRESS-HANDLED' !== $response['body'],
		"a request with $description is challenged before OnePress"
	);
}

echo "\n";

if ( $failures ) {
	echo count( $failures ) . " failure(s)\n";
	exit( 1 );
}

echo "All checks passed\n";
exit( 0 );
