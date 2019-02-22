HTTP Signature service and middleware (PHP)
===

[![Build Status](https://travis-ci.org/legalthings/http-signature-php.svg?branch=master)](https://travis-ci.org/legalthings/http-signature-php)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/legalthings/http-signature-php/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/legalthings/http-signature-php/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/legalthings/http-signature-php/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/legalthings/http-signature-php/?branch=master)
[![Packagist Stable Version](https://img.shields.io/packagist/v/legalthings/http-signature-php.svg)](https://packagist.org/packages/legalthings/http-signature-php)
[![Packagist License](https://img.shields.io/packagist/l/legalthings/http-signature-php.svg)](https://packagist.org/packages/legalthings/http-signature-php)

This library provides a service for implementing the [IETF HTTP Signatures draft RFC](https://tools.ietf.org/html/draft-cavage-http-signatures).
It includes PSR-7 compatible middleware for signing requests (by an HTTP client like Guzzle) and verifying http
signatures.

Installation
---

    composer require lto/http-signature

Usage
---

When creating the `HttpSignature` service, pass a list of supported algorithms, a callback to sign request and a
callback to verify signatures.

```php
use LTO/HttpSignature/HttpSignature;

$keys = [
  'hmac-key-1' => 'secret',
  'hmac-key-2' => 'god',
];

$service = new HttpSignature(
    'hmac-sha256',
    function (string $message, string $keyId) use ($keys): string {
        if (!isset($keys[$keyId])) {
            throw new OutOfBoundsException("Unknown sign key '$keyId'");
        }
    
        $key = $keys[$keyId];
        return hash_hmac('sha256', $message, $key, true);
    },
    function (string $message, string $signature, string $keyId) use ($keys): bool {
        if (!isset($keys[$keyId])) {
            return false;        
        }
    
        $key = $keys[$keyId];
        $expected = hash_hmac('sha256', $message, $key, true);
        
        return hash_equals($expected, $signature);
    }
);
```

### Signing request

You can use the service to sign a PSR-7 Request.

```php
$request = new Request(); // Any PSR-7 compatible Request object
$signedRequest = $service->sign($request, $keyId);
```

### Verifying requests

You can use the service to verify the signature of a signed a PSR-7 Request.

```php
$request = new Request(); // Any PSR-7 compatible Request object
$service->verify($request);
```

If the request is not signed, the signature is invalid, or the request doesn't meet the requirements, an
`HttpSignatureException` is thrown. 

### Configuring the service

#### Multiple algorithms

Rather than specifying a single algorithm, an array of supported algorithms may be specified in the constructor. The
used algorithm is passed as extra parameter to the sign and verify callbacks.

```php
use LTO/HttpSignature/HttpSignature;

$service = new HttpSignature(
    ['hmac-sha256', 'rsa', 'rsa-sha256'],
    function (string $message, string $keyId, string $algorithm): string {
        // ...
    },
    function (string $message, string $signature, string $keyId, string $algorithm): bool {
        // ...
    }
);
```

When signing, specify the algorithm;

```php
$signedRequest = $service->sign($request, $keyId, 'hmac-sha256');
```

Alternatively you can get a copy of the service with one of the algorithms selected.

```php
$signService = $service->withAlgorithm('hmac-sha256');
$signService->sign($request, $keyId);
```

#### Required headers

By default, the request target (includes the HTTP method, URL path and query parameters) and the `Date` header are
required for all types of requests.

```php
$service = $service->withRequiredHeaders('POST', ['(request-target)', 'date', 'content-type', 'digest']);
```

The required headers can be specified per request method or as `default`.

#### Date header

If a `Date` header is specified, the service will check the age of the request. If it's signed to long ago an exception
is thrown. By default a request may not be more than 300 seconds (5 minutes) old.

The time between signing a request and verifying it, may be due to latency or the system clock of client and/or server
might be off.

The time that is allowed can be configured as clock skew;

```php
$service = $service->withClockSkew(1800); // Accept requests up to 30 minutes old
```

#### X-Date header

Browsers automatically set the `Date` header for AJAX requests. This makes it impossible to use this for the signature.
As solution, an `X-Date` header may be used that supersedes the `Date` header.

### Server middleware

_TODO_

### Client middleware

Client middleware can be used to sign requests send by PSR-7 compatible HTTP clients like
[Guzzle](http://docs.guzzlephp.org) and [HTTPlug](http://docs.php-http.org).

```php
use LTO/HttpSignature/HttpSignature;
use LTO/HttpSignature/ClientMiddleware;

$service = new HttpSignature(/* ... */);
$middleware = new ClientMiddleware($service, $keyId);
```

The `$keyId` is used to the `Authorization` header and passed to the sign callback.

If the service supports multiple algorithms you need to use the `withAlgorithm` method to select one. 

```php
$middleware = new ClientMiddleware($service->withAlgorithm('hmac-sha256'));
```

#### Double pass middleware

The client middleware can be used by any client that does support double pass middleware. Such middleware are callables
with the following signature;

```php
fn(RequestInterface $request, ResponseInterface $response, callable $next): ResponseInterface
```

Most HTTP clients do not support double pass middleware, but a type of single pass instead. However more general
purpose PSR-7 middleware libraries, like [Replay](http://relayphp.com/), do support double pass.

```php
use Relay\RelayBuilder;

$relayBuilder = new RelayBuilder($resolver);
$relay = $relayBuilder->newInstance([
    $middleware->asDoublePass()
]);

$response = $relay($request, $baseResponse);
```

_The client middleware does not conform to PSR-15 (single pass) as that is intended for server requests only._

#### Guzzle

[Guzzle](http://docs.guzzlephp.org) is the most popular HTTP Client for PHP. The middleware has a `forGuzzle()` method
that creates a callback which can be used as Guzzle middleware.

```php
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Client;
use LTO/HttpSignature/HttpSignature;
use LTO/HttpSignature/ClientMiddleware;

$service = new HttpSignature(/* ... */);
$middleware = new ClientMiddleware($service, $keyId);

$stack = new HandlerStack();
$stack->push($middleware->forGuzzle());

$client = new Client(['handler' => $stack]);
```

When using the middleware for Guzzle, you may pass option `signature_key_id` which will be used instead of `$keyId`.
_Note that this feature isn't available for double pass and Httplug._

```php
$client->get('/foo', ['signature_key_id' => $keyId]);
```

#### HTTPlug

[HTTPlug](http://docs.php-http.org/en/latest/httplug/introduction.html) is the HTTP client of PHP-HTTP. It allows you
to write reusable libraries and applications that need an HTTP client without binding to a specific implementation.

The `forHttplug()` method for the middleware creates an object that can be used as HTTPlug plugin.

```php
use Http\Discovery\HttpClientDiscovery;
use Http\Client\Common\PluginClient;
use LTO/HttpSignature/HttpSignature;
use LTO/HttpSignature/ClientMiddleware;

$service = new HttpSignature(/* ... */);
$middleware = new ClientMiddleware($service, $keyId);

$pluginClient = new PluginClient(
    HttpClientDiscovery::find(),
    [
        $middleware->asHttplugPlugin()
    ]
);
```
