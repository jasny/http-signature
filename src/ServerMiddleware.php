<?php declare(strict_types=1);

namespace LTO\HTTPSignature;

use Psr\Http\Message\ServerRequestInterface as ServerRequest;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ResponseFactoryInterface as ResponseFactory;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;

/**
 * Middleware to verify HTTP Signature authentication.
 * Can be used both as single pass (PSR-15) and double pass middleware.
 */
class ServerMiddleware implements MiddlewareInterface
{
    /**
     * @var HTTPSignature
     */
    protected $service;

    /**
     * @var ResponseFactory|null
     */
    protected $responseFactory;

    /**
     * Class constructor.
     *
     * @param HTTPSignature        $service
     * @param ResponseFactory|null $responseFactory
     */
    public function __construct(HTTPSignature $service, ?ResponseFactory $responseFactory = null)
    {
        $this->service = $service;
        $this->responseFactory = $responseFactory;
    }


    /**
     * Process an incoming server request (PSR-15).
     *
     * @param ServerRequest  $request
     * @param RequestHandler $handler
     * @return Response
     * @throws \RuntimeException if unauthorized response can't be created
     */
    public function process(ServerRequest $request, RequestHandler $handler): Response
    {
        if (!$this->isRequestSigned($request)) {
            return $handler->handle($request);
        }

        $next = function (ServerRequest $request) use ($handler) {
            return $handler->handle($request);
        };

        return $this->handleSignedRequest($request, null, $next);
    }

    /**
     * Get a callback that can be used as double pass middleware.
     *
     * @return callable
     */
    public function asDoublePass(): callable
    {
        return function(ServerRequest $request, Response $response, callable $next): Response {
            return $this->isRequestSigned($request)
                ? $this->handleSignedRequest($request, $response, $next)
                : $next($request, $response);
        };
    }

    /**
     * Handle signed request.
     *
     * @param ServerRequest  $request
     * @param Response|null  $response
     * @param callable       $next
     * @return Response
     * @throws \RuntimeException when the unauthorized response can't be created.
     */
    protected function handleSignedRequest(ServerRequest $request, ?Response $response, callable $next): Response
    {
        try {
            $keyId = $this->service->verify($request);
            $request = $request->withAttribute('signature_key_id', $keyId);

            $nextResponse = $next($request, $response);
        } catch (HTTPSignatureException $exception) {
            $nextResponse = $this->createUnauthorizedResponse($request, $response, $exception->getMessage());
        }

        return $nextResponse;
    }

    /**
     * Check if the request contains a signature authorization header.
     *
     * @param ServerRequest $request
     * @return bool
     */
    protected function isRequestSigned(ServerRequest $request): bool
    {
        return
            $request->hasHeader('authorization') &&
            (substr(strtolower($request->getHeaderLine('authorization')), 0 , 10) === 'signature ');
    }

    /**
     * Create a response using the response factory.
     *
     * @param int $status  Response status
     * @return Response
     */
    protected function createResponse(int $status): Response
    {
        if ($this->responseFactory === null) {
            throw new \BadMethodCallException('Response factory not set');
        }

        return $this->responseFactory->createResponse($status);
    }

    /**
     * Create a `401 Unauthorized` response.
     *
     * @param ServerRequest $request
     * @param Response|null $response
     * @param string        $message
     * @return Response
     * @throws \RuntimeException when can't write body.
     */
    protected function createUnauthorizedResponse(ServerRequest $request, ?Response $response, string $message): Response
    {
        $newResponse = $response === null
            ? $this->createResponse(401)
            : $response->withStatus(401);

        $errorResponse = $this->service->setAuthenticateResponseHeader($request->getMethod(), $newResponse)
            ->withHeader('Content-Type', 'text/plain');

        $errorResponse->getBody()->write($message);

        return $errorResponse;
    }
}
