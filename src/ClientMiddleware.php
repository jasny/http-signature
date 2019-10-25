<?php declare(strict_types=1);

namespace Jasny\HttpSignature;

use Http\Client\Common\Plugin as HttpPlugin;
use Http\Promise\Promise as HttpPromise;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Middleware to sign PSR-7 HTTP requests.
 */
class ClientMiddleware
{
    /**
     * @var HttpSignature
     */
    protected $service;

    /**
     * @var string|null
     */
    protected $keyId;

    /**
     * Class constructor.
     *
     * @param HttpSignature $service
     * @param string        $keyId    Default keyId
     */
    public function __construct(HttpSignature $service, ?string $keyId = null)
    {
        $this->service = $service;
        $this->keyId = $keyId;
    }


    /**
     * Return a callback that can be used as double pass middleware.
     *
     * @return callable
     */
    public function asDoublePass(): callable
    {
        if ($this->keyId === null) {
            throw new \BadMethodCallException('Unable to use as double pass middleware, no keyId specified');
        }

        return function (RequestInterface $request, ResponseInterface $response, callable $next): ResponseInterface {
            $signedRequest = $this->service->sign($request, $this->keyId);
            return $next($signedRequest, $response);
        };
    }

    /**
     * Return a callback that can be used as Guzzle middleware.
     * @see http://docs.guzzlephp.org/en/stable/handlers-and-middleware.html
     *
     * @return callable
     */
    public function forGuzzle(): callable
    {
        return function (callable $handler) {
            return function (RequestInterface $request, array $options) use ($handler) {
                if ($request->hasHeader('Authorization')) {
                    return $handler($request, $options);                    
                }
                
                $keyId = array_key_exists('signature_key_id', $options) ? $options['signature_key_id'] : $this->keyId;
                $nextRequest = $keyId !== null ? $this->service->sign($request, $keyId) : $request;

                return $handler($nextRequest, $options);
            };
        };
    }

    /**
     * Create a version of this middleware that can be used in HTTPlug.
     * @see http://docs.php-http.org/en/latest/plugins/introduction.html
     *
     * @return self&HttpPlugin
     */
    public function forHttplug(): HttpPlugin
    {
        if ($this->keyId === null) {
            throw new \BadMethodCallException('Unable to use as httplug plugin, no keyId specified');
        }

        return new class ($this->service, $this->keyId) extends ClientMiddleware implements HttpPlugin {
            public function handleRequest(RequestInterface $request, callable $next, callable $first): HttpPromise
            {
                $signedRequest = $this->service->sign($request, $this->keyId);
                return $next($signedRequest);
            }
        };
    }
}
