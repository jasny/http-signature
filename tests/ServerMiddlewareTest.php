<?php

namespace Jasny\HttpSignature\Tests;

use Jasny\TestHelper;
use Jasny\HttpSignature\HttpSignature;
use Jasny\HttpSignature\HttpSignatureException;
use Jasny\HttpSignature\ServerMiddleware;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * @covers \Jasny\HttpSignature\ServerMiddleware
 */
class ServerMiddlewareTest extends TestCase
{
    use TestHelper;

    /**
     * @var HttpSignature&MockObject
     */
    protected $service;

    /**
     * @var ResponseFactoryInterface&MockObject
     */
    protected $responseFactory;

    /**
     * @var ServerMiddleware
     */
    protected $middleware;


    public function setUp()
    {
        $this->service = $this->createMock(HttpSignature::class);
        $this->responseFactory = $this->createMock(ResponseFactoryInterface::class);

        $this->middleware = new ServerMiddleware($this->service, $this->responseFactory);
    }

    public function testProcessWithValidSignature()
    {
        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $signature = "PIw+8VW129YY/6tRfThI3ZA0VygH4cYWxIayUZbdA3I9CKUdmqttvVZvOXN5BX2Z9jfO3f1vD1/R2jxwd3BHBw==";

        $authorizationHeader = join(',', [
            'keyId="' . $publicKey . '"',
            'algorithm="ed25519-sha256"',
            'headers="(request-target) date"',
            'signature="' . $signature . '"',
        ]);

        $signatureRequest = $this->createMock(ServerRequestInterface::class);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('getMethod')->willReturn('GET');
        $request->expects($this->any())->method('hasHeader')->with('authorization')->willReturn(true);
        $request->expects($this->atLeastOnce())->method('getHeaderLine')
            ->with('authorization')
            ->willReturn('Signature ' . $authorizationHeader);
        $request->expects($this->atLeastOnce())->method('withAttribute')
            ->with('signature_key_id', $publicKey)
            ->willReturn($signatureRequest);

        $response = $this->createMock(ResponseInterface::class);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')
            ->with($this->identicalTo($signatureRequest))
            ->willReturn($response);

        $this->service->expects($this->once())->method('verify')->with($request)->willReturn($publicKey);

        $this->responseFactory->expects($this->never())->method('createResponse');

        $ret = $this->middleware->process($request, $handler);

        $this->assertSame($response, $ret);
    }

    public function testProcessWithInvalidSignature()
    {
        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $signature = 'aW52YWxpZA==';

        $authorizationHeader = join(',', [
            'keyId="' . $publicKey . '"',
            'algorithm="ed25519-sha256"',
            'headers="(request-target) date"',
            'signature="' . $signature . '"',
        ]);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('getMethod')->willReturn('GET');
        $request->expects($this->any())->method('hasHeader')->with('authorization')->willReturn(true);
        $request->expects($this->atLeastOnce())->method('getHeaderLine')
            ->with('authorization')
            ->willReturn('Signature ' . $authorizationHeader);
        $request->expects($this->never())->method('withAttribute');

        $body = $this->createMock(StreamInterface::class);
        $body->expects($this->once())->method('write')->with('invalid signature');

        $unauthorizedResponse = $this->createMock(ResponseInterface::class);
        $unauthorizedResponse->expects($this->once())->method('withHeader')
            ->with('Content-Type', 'text/plain')->willReturnSelf();
        $unauthorizedResponse->expects($this->once())->method('getBody')->willReturn($body);

        $this->responseFactory->expects($this->once())->method('createResponse')
            ->with(401)->willReturn($unauthorizedResponse);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        $this->service->expects($this->once())->method('verify')->with($request)
            ->willThrowException(new HttpSignatureException('invalid signature'));
        $this->service->expects($this->atLeastOnce())->method('setAuthenticateResponseHeader')
            ->with('GET', $this->identicalTo($unauthorizedResponse))
            ->willReturn($unauthorizedResponse);

        $ret = $this->middleware->process($request, $handler);

        $this->assertSame($unauthorizedResponse, $ret);
    }

    public function testProcessWithUnsignedRequest()
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('hasHeader')
            ->with('authorization')
            ->willReturn(false);

        $response = $this->createMock(ResponseInterface::class);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')
            ->with($this->identicalTo($request))
            ->willReturn($response);

        $this->service->expects($this->never())->method('verify');

        $ret = $this->middleware->process($request, $handler);

        $this->assertSame($response, $ret);
    }

    public function testProcessWithBasicAuthRequest()
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('hasHeader')->with('authorization')->willReturn(true);
        $request->expects($this->atLeastOnce())->method('getHeaderLine')
            ->with('authorization')
            ->willReturn('Basic QWxhZGRpbjpPcGVuU2VzYW1l');

        $response = $this->createMock(ResponseInterface::class);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())->method('handle')
            ->with($this->identicalTo($request))
            ->willReturn($response);

        $this->service->expects($this->never())->method('verify');

        $ret = $this->middleware->process($request, $handler);

        $this->assertSame($response, $ret);
    }

    /**
     * @expectedException \BadMethodCallException
     * @expectedExceptionMessage Response factory not set
     */
    public function testProcessWithoutResponseFactory()
    {
        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $signature = 'aW52YWxpZA==';

        $authorizationHeader = join(',', [
            'keyId="' . $publicKey . '"',
            'algorithm="ed25519-sha256"',
            'headers="(request-target) date"',
            'signature="' . $signature . '"',
        ]);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('getMethod')->willReturn('GET');
        $request->expects($this->any())->method('hasHeader')->with('authorization')->willReturn(true);
        $request->expects($this->atLeastOnce())->method('getHeaderLine')
            ->with('authorization')
            ->willReturn('Signature ' . $authorizationHeader);
        $request->expects($this->never())->method('withAttribute');

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        $this->service->expects($this->once())->method('verify')->with($request)
            ->willThrowException(new HttpSignatureException('invalid signature'));

        $middleware = new ServerMiddleware($this->service); // No response factory

        $middleware->process($request, $handler);
    }


    public function testAsDoublePassMiddleware()
    {
        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $signature = "PIw+8VW129YY/6tRfThI3ZA0VygH4cYWxIayUZbdA3I9CKUdmqttvVZvOXN5BX2Z9jfO3f1vD1/R2jxwd3BHBw==";

        $authorizationHeader = join(',', [
            'keyId="' . $publicKey . '"',
            'algorithm="ed25519-sha256"',
            'headers="(request-target) date"',
            'signature="' . $signature . '"',
        ]);

        $signatureRequest = $this->createMock(ServerRequestInterface::class);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('getMethod')->willReturn('GET');
        $request->expects($this->any())->method('hasHeader')->with('authorization')->willReturn(true);
        $request->expects($this->atLeastOnce())->method('getHeaderLine')
            ->with('authorization')
            ->willReturn('Signature ' . $authorizationHeader);
        $request->expects($this->atLeastOnce())->method('withAttribute')
            ->with('signature_key_id', $publicKey)
            ->willReturn($signatureRequest);

        $response = $this->createMock(ResponseInterface::class);

        $next = $this->createCallbackMock(
            $this->once(),
            [$this->identicalTo($signatureRequest), $this->identicalTo($response)],
            $response
        );

        $this->service->expects($this->once())->method('verify')->with($request)->willReturn($publicKey);

        $this->responseFactory->expects($this->never())->method('createResponse');

        $doublePass = $this->middleware->asDoublePass();
        $ret = $doublePass($request, $response, $next);

        $this->assertSame($response, $ret);
    }

    public function testAsDoublePassMiddlewareWithInvalidSignatureWithoutFactory()
    {
        $this->middleware = new ServerMiddleware($this->service);

        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $signature = 'aW52YWxpZA==';

        $authorizationHeader = join(',', [
            'keyId="' . $publicKey . '"',
            'algorithm="ed25519-sha256"',
            'headers="(request-target) date"',
            'signature="' . $signature . '"',
        ]);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('getMethod')->willReturn('GET');
        $request->expects($this->any())->method('hasHeader')->with('authorization')->willReturn(true);
        $request->expects($this->atLeastOnce())->method('getHeaderLine')
            ->with('authorization')
            ->willReturn('Signature ' . $authorizationHeader);
        $request->expects($this->never())->method('withAttribute');

        $body = $this->createMock(StreamInterface::class);
        $body->expects($this->once())->method('write')->with('invalid signature');

        $unauthorizedResponse = $this->createMock(ResponseInterface::class);
        $unauthorizedResponse->expects($this->once())->method('withHeader')
            ->with('Content-Type', 'text/plain')->willReturnSelf();
        $unauthorizedResponse->expects($this->any())->method('getBody')->willReturn($body);
        $unauthorizedResponse->expects($this->any())->method('withBody')->willReturnSelf();

        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())->method('withStatus')->with(401)->willReturn($unauthorizedResponse);
        $response->expects($this->any())->method('getBody')->willReturn($body);

        $next = $this->createCallbackMock($this->never());

        $this->service->expects($this->once())->method('verify')->with($request)
            ->willThrowException(new HttpSignatureException('invalid signature'));
        $this->service->expects($this->atLeastOnce())->method('setAuthenticateResponseHeader')
            ->with('GET', $this->identicalTo($unauthorizedResponse))
            ->willReturn($unauthorizedResponse);

        $doublePass = $this->middleware->asDoublePass();
        $ret = $doublePass($request, $response, $next);

        $this->assertSame($unauthorizedResponse, $ret);
    }

    public function testAsDoublePassMiddlewareWithInvalidSignatureWithFactory()
    {
        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $signature = 'aW52YWxpZA==';

        $authorizationHeader = join(',', [
            'keyId="' . $publicKey . '"',
            'algorithm="ed25519-sha256"',
            'headers="(request-target) date"',
            'signature="' . $signature . '"',
        ]);

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('getMethod')->willReturn('GET');
        $request->expects($this->any())->method('hasHeader')->with('authorization')->willReturn(true);
        $request->expects($this->atLeastOnce())->method('getHeaderLine')
            ->with('authorization')
            ->willReturn('Signature ' . $authorizationHeader);
        $request->expects($this->never())->method('withAttribute');

        $body = $this->createMock(StreamInterface::class);
        $body->expects($this->once())->method('write')->with('invalid signature');

        $unauthorizedResponse = $this->createMock(ResponseInterface::class);
        $unauthorizedResponse->expects($this->once())->method('withHeader')
            ->with('Content-Type', 'text/plain')->willReturnSelf();
        $unauthorizedResponse->expects($this->once())->method('getBody')->willReturn($body);

        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->never())->method('withStatus');

        $this->responseFactory->expects($this->once())->method('createResponse')
            ->with(401)->willReturn($unauthorizedResponse);

        $next = $this->createCallbackMock($this->never());

        $this->service->expects($this->once())->method('verify')->with($request)
            ->willThrowException(new HttpSignatureException('invalid signature'));
        $this->service->expects($this->atLeastOnce())->method('setAuthenticateResponseHeader')
            ->with('GET', $this->identicalTo($unauthorizedResponse))
            ->willReturn($unauthorizedResponse);

        $doublePass = $this->middleware->asDoublePass();
        $ret = $doublePass($request, $response, $next);

        $this->assertSame($unauthorizedResponse, $ret);
    }

    public function testAsDoublePassMiddlewareWithUnsignedRequest()
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('hasHeader')
            ->with('authorization')
            ->willReturn(false);

        $response = $this->createMock(ResponseInterface::class);

        $next = $this->createCallbackMock(
            $this->once(),
            [$this->identicalTo($request), $this->identicalTo($response)],
            $response
        );

        $this->service->expects($this->never())->method('verify');

        $doublePass = $this->middleware->asDoublePass();
        $ret = $doublePass($request, $response, $next);

        $this->assertSame($response, $ret);
    }

    public function testAsDoublePassMiddlewareWithBasicAuthRequest()
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->any())->method('hasHeader')->with('authorization')->willReturn(true);
        $request->expects($this->atLeastOnce())->method('getHeaderLine')
            ->with('authorization')
            ->willReturn('Basic QWxhZGRpbjpPcGVuU2VzYW1l');

        $response = $this->createMock(ResponseInterface::class);

        $next = $this->createCallbackMock(
            $this->once(),
            [$this->identicalTo($request), $this->identicalTo($response)],
            $response
        );

        $this->service->expects($this->never())->method('verify');

        $doublePass = $this->middleware->asDoublePass();
        $ret = $doublePass($request, $response, $next);

        $this->assertSame($response, $ret);
    }
}
