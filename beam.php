<?php
/**
 * Plugin Name: Beam
 * Plugin URI: https://github.com/bobbywalters/beam
 * Description: An efficient streaming HTTP API transport.
 * Author: Bobby Walters
 * Author URI: https://github.com/bobbywalters
 * Version: 2.0.0
 * Text Domain: beam
 * Domain Path: /languages
 * License: GPLv2
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 *
 * @link https://github.com/bobbywalters/beam
 * @package beam
 * @since 1.0.0
 */

/*
Copyright (C) 2016 Bobby Walters

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; version 2
of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/**
 * The core handling of Beam plugging in to the WordPress HTTP API.
 *
 * Beam uses PHP streams (sockets) to establish a connection. Reading
 * and writing from the connection use the stream APIs while also
 * utilizing stream filters (dechunk and zlib) as appropriate.
 *
 * Beam was written as a single file so it could be used as a
 * "Must Use" plugin within WordPress.
 *
 * Notes:
 * * PHP 5.3 or greater is needed to use the PHP dechunk stream filter.
 * * The PHP zlib extension is needed to use the PHP zlib
 * stream filter.
 * * The OpenSSL extension is needed for SSL/TLS (HTTPS) support.
 * * PHP streams must be able to create socket connections.
 */
class Beam {
	/**
	 * Read a single line from the supplied PHP stream.
	 *
	 * @param resource $stream The stream resource to read an RFC
	 * compliant HTTP response line.
	 * @return string The line without the new line ("\n") or
	 * carriage return ("\r") characters.
	 */
	protected static function get_line( $stream ) {
		$line = stream_get_line( $stream, 0, "\n" );
		$i = strlen( $line ) - 1;

		return 0 <= $i && "\r" === $line[ $i ] ? substr( $line, 0, $i ) : $line;
	}

	/**
	 * A helper method to mimic the PHP `get_meta_data` function when
	 * used with fopen and the HTTP wrapper but matches
	 * `WP_Http::processHeaders` return values.
	 *
	 * @param resource $stream The stream to read RFC compliant HTTP
	 * response status line, headers, and separator from.
	 * @param string   $url    The requeust URL used to verify cookies.
	 * @return array An associative array matching `WP_Http::processHeaders`.
	 * @see WP_Http::processHeaders
	 * @uses Beam::get_line
	 */
	protected static function get_meta_data( $stream, $url ) {
		// Read status line.
		$i = explode( ' ', self::get_line( $stream ), 3 );
		if ( isset( $i[2] ) ) {
			$response = array(
				'version' => $i[0],
				'code' => intval( $i[1] ),
				'message' => $i[2],
			);
		} else {
			$response = array( 'version' => '', 'code' => 0, 'message' => '' );
		}

		$cookies = array();
		$headers = array();
		$h = null;

		// Read headers and separator.
		while ( '' !== $i = self::get_line( $stream ) ) {
			/*
			 * Check if this is a folded header value.
			 * https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.2
			 */
			if ( ' ' === $i[0] || "\t" === $i[0] ) {
				$v = trim( $i );
			} else {
				// A valid header name will be followed by a colon.
				$i = explode( ':', $i, 2 );
				if ( isset( $i[1] ) ) {
					$h = strtolower( $i[0] );
					$v = trim( $i[1] );
				} else {
					$h = null;
				}
			}

			if ( null === $h ) {
				continue;
			}

			if ( empty( $headers[ $h ] ) ) {
				$headers[ $h ] = $v;
			} elseif ( is_array( $headers[ $h ] ) ) {
				$headers[ $h ][] = $v;
			} else {
				$headers[ $h ] = array( $headers[ $h ], $v );
			}

			if ( 'set-cookie' === $h ) {
				$cookies[] = new WP_Http_Cookie( $v, $url );
			}
		}

		return array(
			'response' => $response,
			'headers' => $headers,
			'cookies' => $cookies,
		);
	}

	/**
	 * Preempt the WordPress core HTTP request handling to use Beam.
	 *
	 * @param false|array|WP_Error $preempt Whether to preempt an HTTP
	 * request's return value. Default false.
	 * @param array                $r       HTTP request arguments.
	 * @param string               $url     The request URL.
	 * @return `false` if the request will not be processed by Beam
	 * otherwise an `array` with server response data or a `WP_Error`
	 * indicating the request was handled but an issue occurred.
	 * @uses Beam::request
	 * @since 2.0.0
	 */
	static function pre_http_request( $preempt, $r, $url ) {
		if ( $r['reject_unsafe_urls'] && ! wp_http_validate_url( $url ) ) {
			return new WP_Error( 'http_request_failed', __( 'Rejected unsafe URL through HTTP.' ) );
		}

		$http = new WP_Http;
		if ( $http->block_request( $url ) ) {
			return new WP_Error( 'http_request_failed', __( 'User has blocked requests through HTTP.' ) );
		}
		unset( $http );

		if ( isset( $r['headers'] ) ) {
			if ( is_string( $r['headers'] ) ) {
				$stream = fopen( 'php://memory', 'rb+' );
				fwrite( $stream, "HTTP/1.1 200 OK\r\n" );
				fwrite( $stream, $r['headers'] );
				fwrite( $stream, "\r\n\r\n" );
				rewind( $stream );

				$r['headers'] = self::get_meta_data( $stream, $url )['headers'];

				fclose( $stream );
				unset( $stream );
			}

			// WP_Http::buildCookieHeader allowed strings and WP_Http_Cookie.
			if ( false === empty( $r['cookies'] ) ) {
				$h = '';
				foreach ( $r['cookies'] as $k => $c ) {
					if ( $c instanceof WP_Http_Cookie ) {
						$h .= '; ' . $c->getHeaderValue();
					} else {
						$h .= '; ' . $k . '=' . $c;
					}
				}

				if ( '' !== $h ) {
					if ( isset( $r['headers']['cookie']) ) {
						$r['headers']['cookie'] .= $h;
					} elseif ( isset( $r['headers']['Cookie'] ) ) {
						$r['headers']['cookie'] = $r['headers']['Cookie'] . $h;
						unset( $r['headers']['Cookie'] );
					} else {
						$r['headers']['cookie'] = substr( $h, 2 );
					}
				}

				unset( $c, $h, $k );
			}

			if ( isset( $r['headers']['user-agent'] ) ) {
				$r['user-agent'] = $r['headers']['user-agent'];
			} elseif ( isset( $r['headers']['User-Agent'] ) ) {
				$r['user-agent'] = $r['headers']['User-Agent'];
			}
			unset( $r['headers']['user-agent'], $r['headers']['User-Agent'] );

			unset( $r['headers']['connection'], $r['headers']['Connection'] );
		} else {
			$r['headers'] = array();
		}

		$r['method'] = strtoupper( $r['method'] );

		if ( 'POST' === $r['method']
			|| 'PUT' === $r['method']
			|| ( isset( $r['body'] ) && '' !== $r['body'] ) ) {

			if ( is_array( $r['body'] ) || is_object( $r['body'] ) ) {
				$r['body'] = http_build_query( $r['body'], null, '&' );
				if ( false === isset( $r['headers']['content-type'] ) && false === isset( $r['headers']['Content-Type'] ) ) {
					$r['headers']['content-type'] = 'application/x-www-form-urlencoded; charset=' . get_option( 'blog_charset' );
				}
			}

			if ( '' === $r['body'] ) {
				$r['body'] = null;
			}

			if ( false === isset( $r['headers']['content-length'] ) && false === isset( $r['headers']['Content-Length'] ) ) {
				$r['headers']['content-length'] = strlen( $r['body'] );
			}
		}

		return Beam::request( $url, $r );
	}

	/**
	 * Send an HTTP request to a URI.
	 *
	 * This method is intended to be called via
	 * `WP_Http::_dispatch_request` which provides many of the request
	 * argument values and validation by this time. Calling this method
	 * directly would require mimicing `WP_Http::request` handling
	 * first.
	 *
	 * @param string $url The request URL.
	 * @param array  $r   HTTP request arguments.
	 * @return array|WP_Error Array containing `headers`, `body`,
	 * `response`, `cookies`, and `filename` (if streaming to file).
	 * Or a WP_Error instance upon error.
	 * @see WP_Http::request
	 */
	static function request( $url, $r ) {
		$parsed_url = parse_url( $url );

		switch ( strtolower( $parsed_url['scheme'] ) ) {
			case 'https':
			case 'ssl':
			case 'tls':
				$port = 443;
				$scheme = 'tls';
				$secure = true;
				break;
			default:
				$port = 80;
				$scheme = 'tcp';
				$secure = false;
				break;
		}

		if ( isset( $r['headers']['Host'] ) ) {
			$host = $r['headers']['Host'];
		} elseif ( isset( $r['headers']['host'] ) ) {
			$host = $r['headers']['host'];
		} else {
			$host = $parsed_url['host'];
		}
		unset( $r['headers']['Host'], $r['headers']['host'] );

		switch ( strtolower( $host ) ) {
			case 'localhost':
				// Avoid issues with IPv6 vs IPv4, DNS, and PHP.
				$host = '127.0.0.1';
			case strtolower( parse_url( home_url(), PHP_URL_HOST ) ):
				$local = true;
				break;
			default:
				$local = false;
		}

		if ( isset( $parsed_url['port'] ) ) {
			$port = $parsed_url['port'];
			$std_port = $secure ? 443 === $port : 80 === $port;
		} else {
			$std_port = true;
		}

		// Path may not be empty for HTTP requests.
		if ( false === isset( $parsed_url['path'] ) ) {
			$parsed_url['path'] = '/';
			$url .= '/';
		}

		/*
		 * Apply appropriate WP HTTP API sslverify filter.
		 * The filters are documented in `wp-includes/class-wp-http-sreams.php`.
		 */
		$ssl_verify = apply_filters(
			$local ? 'https_local_ssl_verify' : 'https_ssl_verify',
			isset( $r['sslverify'] ) && $r['sslverify']
		);

		/**
		 * Filter the crypto method to use when establishing a secure connection.
		 *
		 * @since 1.0.0
		 *
		 * @param int $crypto_method The crypto method bitmask to use when
		 * calling stream_socket_enable_crypto.
		 * Default `STREAM_CRYPTO_METHOD_TLS_CLIENT`.
		 * @param string $url The requested URI information to help
		 * determine which crypto method to use.
		 */
		$crypto_method = apply_filters( 'stream_crypto_method', STREAM_CRYPTO_METHOD_TLS_CLIENT, $url );

		$context = stream_context_create( array(
			'socket' => array(
				'tcp_nodelay' => true,
			),
			'ssl' => array(
				'allow_self_signed' => ! $ssl_verify,
				'cafile' => $r['sslcertificates'],
				'capture_peer_cert' => $ssl_verify,
				'CN_match' => $host, // peer_name is preferred as of PHP 5.6.0.
				'crypto_method' => $crypto_method,
				'peer_name' => $host,
				'SNI_enabled' => true,
				'verify_peer' => $ssl_verify,
				'verify_peer_name' => $ssl_verify,
			),
		) );

		$proxy = new WP_HTTP_Proxy();
		$send_through_proxy = $proxy->is_enabled() && $proxy->send_through_proxy( $url );

		if ( $send_through_proxy ) {
			/**
			 * Filter whether to tunnel this request connection through the proxy.
			 *
			 * Tunneled connections through a proxy allow the client to speak "directly" to the
			 * requested server. Tunneled connections behave as if the proxy was not there
			 * even though all traffic sill routes through the proxy.
			 *
			 * To protect users with end-to-end encryption, a proxy may allow SSL
			 * connections to be tunneled through them. This avoids having the proxy negotiate
			 * security handshakes and decrypting any transmitted data.
			 *
			 * When this filter returns true, an HTTP CONNECT will be issued to the proxy asking
			 * to connect "directly" to the requested server. It is possible to tunnel any type
			 * of traffic through a proxy using this HTTP CONNECT mechanism, however, this is
			 * ultimately dependent on the proxy configuration and what is permitted traffic.
			 *
			 * @since 1.0.0
			 *
			 * @param bool $tunnel_through_proxy Whether to tunnel the connection through the
			 * proxy using an HTTP CONNECT. Defaults to true when a secure transport (ie HTTPS)
			 * is requested.
			 * @param string $url The requested URI information to help determine if
			 * this is a request that should be tunneled through the proxy.
			 */
			if ( $tunnel_through_proxy = apply_filters( 'proxy_tunnel', $secure, $url ) ) {
				$scheme = 'tcp';
			}

			$connect = $scheme . '://' . $proxy->host() . ':' . $proxy->port();
		} else {
			$tunnel_through_proxy = false;
			$connect = $scheme . '://' . $host . ':' . $port;
		}

		// A much cleaner and efficient way to suppress errors versus @ prefixing.
		if ( ! WP_DEBUG ) {
			$error_reporting = error_reporting( 0 );
		}

		$stream = stream_socket_client( $connect, $errno, $errstr, $r['timeout'], STREAM_CLIENT_CONNECT, $context );

		if ( false === $stream ) {
			if ( ! WP_DEBUG ) {
				 error_reporting( $error_reporting );
			}

			// SSL connection failed due to expired/invalid cert or SSL configuration is broken.
			if ( 0 === $errno || '' === $errstr ) {
				return new WP_Error( 'http_request_failed', error_get_last()['message'] );
			}

			return new WP_Error( 'http_request_failed', $errno . ': ' . $errstr );
		}

		// The same timeout is used for connecting, reading, and writing.
		stream_set_timeout( $stream, $r['timeout'] );

		if ( $tunnel_through_proxy ) {
			fwrite( $stream, 'CONNECT ' );
			fwrite( $stream, $parsed_url['host'] );
			fwrite( $stream, ':' );
			fwrite( $stream, $port );
			fwrite( $stream, ' HTTP/' );
			fwrite( $stream, $r['httpversion'] );
			fwrite( $stream, "\r\n" );

			fwrite( $stream, 'Host: ' );
			fwrite( $stream, $host );
			if ( false === $std_port ) {
				fwrite( $stream, ':' );
				fwrite( $stream, $port );
			}
			fwrite( $stream, "\r\n" );

			if ( $proxy->use_authentication() ) {
				fwrite( $stream, $proxy->authentication_header() );
				fwrite( $stream, "\r\n" );
			}

			fwrite( $stream, "\r\n" );

			$response = self::get_meta_data( $stream, $url );

			// If the CONNECT didn't return an OK (200) stop.
			if ( 200 !== $response['response']['code'] ) {
				$response['body'] = null;
			} elseif ( $secure && ! stream_socket_enable_crypto( $stream, true, $crypto_method ) ) {
				/*
				 * Secured tunneled requests may perform a crypto handshake with the
				 * remote server after the proxy has established a valid connection.
				 * Enabling crypto now allows this client to perform the handshake
				 * with the remote server establishing an end-to-end secure channel.
				 */
				$response = new WP_Error( 'http_request_failed', error_get_last()['message'] );
			} else {
				// Safe to discard the connect response now that everything is read.
				unset( $response );
			}

			if ( isset( $response ) ) {
				fclose( $stream );

				if ( ! WP_DEBUG ) {
					 error_reporting( $error_reporting );
				}

				return $response;
			}

			// Proxy is now operating transparently; use direct connection
			// behavior from this point on.
			$send_through_proxy = false;
		}

		fwrite( $stream, $r['method'] );
		fwrite( $stream, ' ' );

		if ( $send_through_proxy ) { // Some proxies require full URL in this field.
			fwrite( $stream, $url );
		} else {
			fwrite( $stream, $parsed_url['path'] );
			if ( isset( $parsed_url['query'] ) ) {
				fwrite( $stream, '?' );
				fwrite( $stream, $parsed_url['query'] );
			}
		}

		fwrite( $stream, ' HTTP/' );
		fwrite( $stream, $r['httpversion'] );
		fwrite( $stream, "\r\n" );

		fwrite( $stream, 'Host: ' );
		fwrite( $stream, $host );
		if ( false === $std_port ) {
			fwrite( $stream, ':' );
			fwrite( $stream, $port );
		}
		fwrite( $stream, "\r\n" );

		foreach ( $r['headers'] as $key => $value ) {
			fwrite( $stream, $key );
			fwrite( $stream, ': ' );
			fwrite( $stream, $value );
			fwrite( $stream, "\r\n" );
		}

		if ( isset( $r['user-agent'] ) ) {
			fwrite( $stream, 'User-Agent: ' );
			fwrite( $stream, $r['user-agent'] );
			fwrite( $stream, "\r\n" );
		}

		if ( ! isset( $r['headers']['accept-encoding'] )
			&& ! isset( $r['headers']['Accept-Encoding'] )
			&& in_array( 'zlib.*', stream_get_filters(), true ) ) {

			fwrite( $stream, "Accept-Encoding: gzip\r\n" );
			$r['decompress'] = true;
		}

		if ( $send_through_proxy && $proxy->use_authentication() ) {
			fwrite( $stream, $proxy->authentication_header() );
			fwrite( $stream, "\r\n" );
		}

		// Always close the connection.
		fwrite( $stream, "connection: close\r\n" );

		// Marks end of headers.
		fwrite( $stream, "\r\n" );

		if ( isset( $r['body'] ) && null !== $r['body'] ) {
			fwrite( $stream, $r['body'] );
		}

		$response = self::get_meta_data( $stream, $url );
		$headers = $response['headers'];

		// Handle redirects.
		if ( 0 < $r['_redirection'] ) {
			switch ( $response['response']['code'] ) {
				case 302:
				case 303:
					// 302 "Found" (for compatibility) and 303 "See Other" always use GET method.
					if ( 'GET' !== strtoupper( $r['method'] ) ) {
						$r['method'] = 'GET';

						// Remove anything that would cause a problem on a GET.
						unset( $r['body'] );
						unset( $r['headers']['content-length'], $r['headers']['Content-Length'] );
						unset( $r['headers']['content-type'], $r['headers']['Content-Type'] );
					}
				case 301:
				case 307:
				case 308:
					fclose( $stream );

					if ( ! WP_DEBUG ) {
						error_reporting( $error_reporting );
					}

					// Check redirect limit.
					if ( 0 > --$r['redirection'] ) {
						return new WP_Error( 'http_request_failed', __( 'Too many redirects.' ) );
					}

					$url = $headers['location'];
					if ( is_array( $url ) ) {
						$url = $url[0];
					}

					// Translate relative URLs to absolute.
					if ( '/' === $url[0] || '.' === $url[0] ) {
						$url = $parsed_url['scheme'] . '://' . $parsed_url['host'] . ':' . $port . $url;
					}

					// Add cookies if they're allowed at the redirect location.
					if ( false === empty( $response['cookies'] ) ) {
						foreach ( $response['cookies'] as $c ) {
							if ( $c->test( $url ) ) {
								$r['cookies'][] = $c;
							}
						}
					}

					return self::request( $url, $r );
			}
		}

		$response['body'] = '';
		$filters = null;

		// Append dechunk filter when needed.
		if ( isset( $headers['transfer-encoding'] ) && 'chunked' === $headers['transfer-encoding'] ) {
			$filters[] = stream_filter_append( $stream, 'dechunk' );
		}

		if ( true === $r['decompress'] && isset( $headers['content-encoding'] ) && 'gzip' === $headers['content-encoding'] ) {
			// The window size is: 15 (max zlib) + 16 for bare minimal gzip header.
			$filters[] = stream_filter_append( $stream, 'zlib.inflate', STREAM_FILTER_READ, array( 'window' => 31 ) );
		}

		$limit = isset( $r['limit_response_size'] ) ? $r['limit_response_size'] : null;

		if ( $r['stream'] ) {
			if ( false === isset( $r['filename'] ) ) {
				$r['filename'] = tempnam( get_temp_dir(), 'beam' );
			}

			if ( $file = fopen( $r['filename'], 'wb' ) ) {
				if ( null !== $limit ) {
					while ( 0 < $limit && ! feof( $stream ) ) {
						$block = stream_get_contents( $stream, $limit );
						$limit -= strlen( $block );
						fwrite( $file, $block );
					}
				} else {
					while ( ! feof( $stream ) ) {
						fwrite( $file, stream_get_contents( $stream ) );
					}
				}

				if ( fclose( $file ) ) {
					$response['filename'] = $r['filename'];
				} else {
					$response = new WP_Error( 'http_request_failed', __( 'Failed to write request to temporary file.' ) );
				}
			} else {
				$response = new WP_Error( 'http_request_failed', sprintf( __( 'Could not open handle for fopen() to %s' ), $r['filename'] ) );
			}
		} elseif ( null !== $limit ) {
			while ( 0 < $limit && ! feof( $stream ) ) {
				$block = stream_get_contents( $stream, $limit );
				$limit -= strlen( $block );
				$response['body'] .= $block;
			}
		} else {
			while ( ! feof( $stream ) ) {
				$response['body'] .= stream_get_contents( $stream );
			}
		}

		if ( null !== $filters ) {
			foreach ( $filters as $f ) {
				stream_filter_remove( $f );
			}
		}

		fclose( $stream );

		if ( ! WP_DEBUG ) {
			 error_reporting( $error_reporting );
		}

		return $response;
	}

	/**
	 * Provides the default HTTP version to use when making requests.
	 *
	 * Hooked to filter 'http_request_version' and only triggered when
	 * an explicit version wasn't supplied in the request arguments.
	 *
	 * HTTP/1.1 allows for chunked transfer encoded responses.
	 *
	 * @param string $version The default HTTP version.
	 * @return string Always returns `'1.1'`.
	 */
	static function request_version( $version ) {
		return '1.1';
	}
}

add_filter( 'http_request_version', 'Beam::request_version' );
add_filter( 'pre_http_request', 'Beam::pre_http_request', 99, 3 );
