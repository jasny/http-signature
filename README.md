HTTP Signature service and middleware (PHP)
===

[![Build Status](https://travis-ci.org/jasny/http-signature.svg?branch=master)](https://travis-ci.org/jasny/http-signature)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/jasny/http-signature/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/jasny/http-signature/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/jasny/http-signature/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/jasny/http-signature/?branch=master)
[![Packagist Stable Version](https://img.shields.io/packagist/v/jasny/http-signature.svg)](https://packagist.org/packages/jasny/http-signature)
[![Packagist License](https://img.shields.io/packagist/l/jasny/http-signature.svg)](https://packagist.org/packages/jasny/http-signature)

This library provides a service for implementing the [IETF HTTP Signatures draft RFC](https://tools.ietf.org/html/draft-cavage-http-signatures).
It includes PSR-7 compatible middleware for signing requests (by an HTTP client like Guzzle) and verifying http
signatures.

Installation
---

    composer require jasny/http-signature

Usage
---

When creating the `HttpSignature` service, pass a list of supported algorithms, a callback to sign request and a
callback to verify signatures.

```php
use Jasny\HttpSignature\HttpSignature;

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
use Jasny\HttpSignature\HttpSignature;

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

Server middleware can be used to verify PSR-7 requests.

If the request is signed but the signature is invalid, the middleware will return a `401 Unauthorized` response and the
handler will not be called.

#### Single pass middleware (PSR-15)

The middleware implements the PSR-15 `MiddlewareInterface`. As PSR standard many new libraries support this type of
middleware, for example [Zend Stratigility](https://docs.zendframework.com/zend-stratigility/). 

You're required to supply a [PSR-17 response factory](https://www.php-fig.org/psr/psr-17/#22-responsefactoryinterface),
to create a `401 Unauthorized` response for requests with invalid signatures.

```php
use Jasny\HttpSignature\HttpSignature;
use Jasny\HttpSignature\ServerMiddleware;
use Zend\Stratigility\MiddlewarePipe;
use Zend\Diactoros\ResponseFactory;

$service = new HttpSignature(/* ... */);
$responseFactory = new ResponseFactory();
$middleware = new ServerMiddleware($service, $responseFactory);

$app = new MiddlewarePipe();
$app->pipe($middleware);
```

#### Double pass middleware

My PHP libraries support double pass middleware. These are callables with the following signature;

```php
fn(ServerRequestInterface $request, ResponseInterface $response, callable $next): ResponseInterface
```

To get a callback to be used by libraries as [Jasny Router](https://github.com/jasny/router) and
[Relay](http://relayphp.com/), use the `asDoublePass()` method.

When using as double pass middleware, the supplying a resource factory is optional. If not supplied, it will use the
response passed when invoked.

```php
use Jasny\HttpSignature\HttpSignature;
use Jasny\HttpSignature\ServerMiddleware;
use Relay\RelayBuilder;

$service = new HttpSignature(/* ... */);
$middleware = new ServerMiddleware($service);

$relayBuilder = new RelayBuilder($resolver);
$relay = $relayBuilder->newInstance([
    $middleware->asDoublePass(),
]);

$response = $relay($request, $baseResponse);
```

#### Verifying requests

If a request is signed and the signature is valid, the middle with set a `signature_key_id` request attribute.

For requests that are *not* signed, the middleware does nothing. This means that you need to always check if the request
has the `signature_key_id`. 

```php
$keyId = $request->getAttribute(`signature_key_id`);

if ($keyId === null) {
    $errorResponse = $response
        ->withStatus(401)
        ->withHeader('Content-Type', 'text/plain');
        
    $errorResponse = $service->setAuthenticateResponseHeader($errorResponse);
    $errorResponse->getBody()->write('request not signed');
}

// Request is signed and signature is valid
// ...
```


### Client middleware

Client middleware can be used to sign requests send by PSR-7 compatible HTTP clients like
[Guzzle](http://docs.guzzlephp.org) and [HTTPlug](http://docs.php-http.org).

```php
use Jasny\HttpSignature\HttpSignature;
use Jasny\HttpSignature\ClientMiddleware;

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
purpose PSR-7 middleware libraries, like [Relay](http://relayphp.com/), do support double pass.

```php
use Relay\RelayBuilder;

$relayBuilder = new RelayBuilder($resolver);
$relay = $relayBuilder->newInstance([
    $middleware->asDoublePass(),
]);

$response = $relay($request, $baseResponse);
```

_The client middleware does not conform to PSR-15 (single pass) as that is intended for server requests only._

#### Guzzle

[Guzzle](http://docs.guzzlephp.org) is the most popular HTTP Client for PHP. The middleware has a `forGuzzle()` method
that creates a callback which can be used as Guzzle middleware.

When using the middleware for Guzzle, it's not required to pass a `$keyId` to the constructor. Instead use Guzzle option
`signature_key_id`. This also allows the option use different keys per request or disable signing for requests. 

```php
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Client;
use Jasny\HttpSignature\HttpSignature;
use Jasny\HttpSignature\ClientMiddleware;

$service = new HttpSignature(/* ... */);
$middleware = new ClientMiddleware($service);

$stack = new HandlerStack();
$stack->push($middleware->forGuzzle());

$client = new Client(['handler' => $stack, 'signature_key_id' => $keyId]);

$client->get('/foo');                                    // Sign with default key
$client->get('/foo', ['signature_key_id' => $altKeyId]); // Sign with other key
$client->get('/foo', ['signature_key_id' => null]);      // Don't sign
```

Alternatively, you can disable signing by default and only sign when specified;

```php
$client = new Client(['handler' => $stack]);

$client->get('/foo');                                 // Don't sign
$client->get('/foo', ['signature_key_id' => $keyId]); // Sign
```

_Using an option is only available for Guzzle. For HTTPlug and other clients, you need to create a client per key or
sign without the use of middleware._

#### HTTPlug

[HTTPlug](http://docs.php-http.org/en/latest/httplug/introduction.html) is the HTTP client of PHP-HTTP. It allows you
to write reusable libraries and applications that need an HTTP client without binding to a specific implementation.

The `forHttplug()` method for the middleware creates an object that can be used as HTTPlug plugin.

```php
use Http\Discovery\HttpClientDiscovery;
use Http\Client\Common\PluginClient;
use Jasny\HttpSignature\HttpSignature;
use Jasny\HttpSignature\ClientMiddleware;

$service = new HttpSignature(/* ... */);
$middleware = new ClientMiddleware($service, $keyId);

$pluginClient = new PluginClient(
    HttpClientDiscovery::find(),
    [
        $middleware->forHttplug(),
    ]
);
```
