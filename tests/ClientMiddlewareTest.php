<?php

namespace LTO\HttpSignature\Tests;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler as GuzzleMockHandler;
use GuzzleHttp\HandlerStack as GuzzleHandlerStack;
use GuzzleHttp\Middleware as GuzzleMiddleware;
use GuzzleHttp\Promise\Promise as GuzzlePromise;
use Http\Mock\Client as HttpMockClient;
use Http\Client\Common\PluginClient as HttpPluginClient;
use Jasny\TestHelper;
use LTO\HttpSignature\ClientMiddleware;
use LTO\HttpSignature\HttpSignature;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * @covers \LTO\HttpSignature\ClientMiddleware
 */
class ClientMiddlewareTest extends TestCase
{
    use TestHelper;

    /**
     * @var HttpSignature&MockObject
     */
    protected $service;

    /**
     * @var ClientMiddleware
     */
    protected $middleware;


    public function setUp()
    {
        $this->service = $this->createMock(HttpSignature::class);
        $this->middleware = new ClientMiddleware($this->service, 'key-1');
    }

    public function testAsDoublePassMiddleware()
    {
        $request = $this->createMock(RequestInterface::class);
        $signedRequest = $this->createMock(RequestInterface::class);
        $baseResponse = $this->createMock(ResponseInterface::class);
        $response = $this->createMock(ResponseInterface::class);

        $this->service->expects($this->once())->method('sign')
            ->with($this->identicalTo($request), 'key-1')
            ->willReturn($signedRequest);

        $next = $this->createCallbackMock($this->once(), [$this->identicalTo($signedRequest)], $response);

        $doublePass = $this->middleware->asDoublePass();
        $ret = $doublePass($request, $baseResponse, $next);

        $this->assertSame($response, $ret);
    }

    public function guzzleOptionsProvider()
    {
        return [
            [false],
            [true],
            [false, 'key-99'],
        ];
    }

    /**
     * @dataProvider guzzleOptionsProvider
     */
    public function testAsGuzzleMiddlewareWithSyncRequest(bool $async, ?string $keyIdOption = null)
    {
        $signedRequest = $this->createMock(RequestInterface::class);
        $response = $this->createMock(ResponseInterface::class);
        $history = [];

        $this->service->expects($this->once())->method('sign')
            ->with($this->isInstanceOf(RequestInterface::class), $keyIdOption ?? 'key-1')
            ->willReturn($signedRequest);

        $mockHandler = new GuzzleMockHandler([$response]);
        $handlerStack = GuzzleHandlerStack::create($mockHandler);

        $handlerStack->push($this->middleware->forGuzzle());
        $handlerStack->push(GuzzleMiddleware::history($history));

        $client = new GuzzleClient(['handler' => $handlerStack]);

        $options = array_merge(
            ['timeout' => 90, 'answer' => 42],
            $keyIdOption === null ? [] : ['signature_key_id' => $keyIdOption]
        );

        $method = $async ? 'getAsync' : 'get';
        $ret = $client->$method('/foo', $options);

        if (!$async) {
            $this->assertSame($response, $ret);
        } else {
            $this->assertInstanceOf(GuzzlePromise::class, $ret);
            $this->assertSame($response, $ret->wait());
        }

        $this->assertCount(1, $history);
        $this->assertSame($signedRequest, $history[0]['request']);
        $this->assertSame($response, $history[0]['response']);

        $expectedOptions = ['timeout' => 90, 'answer' => 42, 'handler' => $handlerStack];
        $actualOptions = array_intersect_key($history[0]['options'], $expectedOptions);
        $this->assertSame($expectedOptions, $actualOptions);
    }

    public function testAsHttplugMiddleware()
    {
        $request = $this->createMock(RequestInterface::class);
        $signedRequest = $this->createMock(RequestInterface::class);
        $response = $this->createMock(ResponseInterface::class);

        $this->service->expects($this->once())->method('sign')
            ->with($this->identicalTo($request), 'key-1')
            ->willReturn($signedRequest);

        $mockClient = new HttpMockClient();
        $mockClient->setDefaultResponse($response);

        $client = new HttpPluginClient($mockClient, [$this->middleware->forHttplug()]);

        $ret = $client->sendRequest($request);

        $this->assertSame($response, $ret);
    }
}
