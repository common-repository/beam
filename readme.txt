=== Beam ===
Contributors: bobbywalters
Tags: http, proxy, remote API, socket, stream, tunnel
Requires at least: 3.7.0
Tested up to: 4.9
Stable tag: trunk
License: GPLv2
License URI: http://www.gnu.org/licenses/gpl-2.0.html

An efficient streaming HTTP API transport.

== Description ==

Provides an efficient streaming WordPress HTTP API transport with support for tunneled proxy connections.

= Drop-in Replacement =

Leverage all the benefits of Beam without having to modify any existing `wp_remote_*` WordPress HTTP API calls.

Honors all standard WordPress HTTP API request arguments, filters, and actions. For more details around the WordPress HTTP API please see https://codex.wordpress.org/HTTP_API the codex site.

= Must Use Plugin Compatible =

May be installed as a "Must Use" plugin so the functionality is always in use. A handy option for site maintainers.

= Efficiency =

Beam was designed with efficiency and accuracy of content sent to and read from connections in mind.

* String concatenation is kept to a minimal.
* PHP streams buffered read and writes minimize network traffic.
* HTTP response is read without regular expression parsing.
* Folded and multiple value HTTP response headers are supported.
* Tolerant handling of LF only end of line markers while still supporting specification standard CRLF.

Built-in PHP stream filters remove the need for user space implementations resulting in better memory management and performance.

* `'dechunk'` Decodes HTTP 1.1 `Transfer-Encoding: chunked` responses (requires PHP 5.3+).
* `'zlib.inflate'` Inflates `Content-Encoding: gzip` responses (requires zlib extension).

Beam uses these filters by default to cut down on network traffic and alter the response on the fly without needing to read in the entire response before hand. It is highly likely that these capabilities are already available; it makes sense to use them.

= Security =

Uses TLS, by default, to establish HTTPS connections for improved security versus SSL.

Beam provides filter `'stream_crypto_method'` to change the crypto method in use based on the requested URL.

= Proxy Support =

Tunneled proxy connections may be established to connect to HTTPS sites over an HTTP proxy and avoid "503 Service Unavailable" HTTP errors. Now it's possible to update, install, and search WordPress and plugins which all use HTTPS URLs while a proxy is in use without having to install the PHP cURL extension.

Beam provides filter `'proxy_tunnel'` to change which requests require a tunneled proxy connection.

== Installation ==

1. Upload **beam.php** file to `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. All WordPress HTTP API requests will be handled by Beam.

== Changelog ==

= 2.0.0 =

2016-07-09

This release was focused on getting Beam to work on WordPress 4.6.

* FIX: WordPress 4.6 now uses the `Requests` library to handle HTTP requests and the swap prevented Beam from being used.
* NEW: Beam is now triggered via the `pre_http_request` filter to handle requests.
* NEW: `WP_HTTP_Beam` was renamed to `Beam` since Beam is no longer loaded as a WP HTTP API transport.

= 1.0.0 =

Initial release.
