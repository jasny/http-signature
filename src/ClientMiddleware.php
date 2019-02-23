<?php declare(strict_types=1);

namespace LTO\HttpSignature;

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
     * @var HTTPSignature
     */
    protected $service;

    /**
     * @var string
     */
    protected $keyId;

    /**
     * Class constructor.
     *
     * @param HTTPSignature $service
     * @param string        $keyId    Default key id
     */
    public function __construct(HTTPSignature $service, string $keyId)
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
                $keyId = $options['signature_key_id'] ?? $this->keyId;
                $signedRequest = $this->service->sign($request, $keyId);

                return $handler($signedRequest, $options);
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
        return new class ($this->service, $this->keyId) extends ClientMiddleware implements HttpPlugin {
            public function handleRequest(RequestInterface $request, callable $next, callable $first): HttpPromise
            {
                $signedRequest = $this->service->sign($request, $this->keyId);
                return $next($signedRequest);
            }
        };
    }
}
