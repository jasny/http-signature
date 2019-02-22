<?php

namespace LTO\HTTPSignature\Tests;

use LTO\HTTPSignature\HTTPSignature;
use Improved\IteratorPipeline\Pipeline;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface as Request;
use Psr\Http\Message\UriInterface as Uri;
use Carbon\CarbonImmutable;

/**
 * @covers \LTO\HTTPSignature\HTTPSignature
 */
class HTTPSignatureTest extends TestCase
{
    use \Jasny\TestHelper;

    public function setUp()
    {
        CarbonImmutable::setTestNow(CarbonImmutable::createFromTimeString('Sat, 22 Aug 1981 20:51:35 +0000'));
    }

    /**
     * Create a mock Uri object.
     *
     * @param $url
     * @return Uri&MockObject
     */
    protected function createUri(string $url): MockObject
    {
        $uri = $this->createMock(Uri::class);
        $uri->expects($this->any())->method('withScheme')->with('')->willReturnSelf();
        $uri->expects($this->any())->method('withHost')->with('')->willReturnSelf();
        $uri->expects($this->any())->method('withPort')->with('')->willReturnSelf();
        $uri->expects($this->any())->method('withUserInfo')->with('')->willReturnSelf();
        $uri->expects($this->any())->method('__toString')->willReturn($url);

        return $uri;
    }

    /**
     * Create a mock Request object.
     *
     * @param string        $method
     * @param string        $url
     * @param string[]|null $params
     * @param string[]      $headers
     * @return Request&MockObject
     */
    protected function createMockRequest(string $method, string $url, array $headers, ?array $params = null): MockObject
    {
        $request = $this->createMock(Request::class);

        $request->expects($this->any())->method('getMethod')->willReturn($method);

        $uri = $this->createUri($url);
        $request->expects($this->any())->method('getUri')->willReturn($uri);

        $headers = array_change_key_case($headers, CASE_LOWER);

        if ($params !== null) {
            $paramString = Pipeline::with($params)
                ->map(function(string $value, string $key) {
                    return sprintf('%s="%s"', $key, addcslashes($value, '"'));
                })
                ->concat(",");

            $headers['authorization'] = "Signature $paramString";
        }

        $request->expects($this->any())->method('hasHeader')
            ->willReturnCallback(function($key) use ($headers) {
                return isset($headers[strtolower($key)]);
            });

        $request->expects($this->any())->method('getHeaderLine')
            ->willReturnCallback(function($key) use ($headers) {
                if (!isset($headers[strtolower($key)])) {
                    throw new \OutOfBoundsException("Header '$key' not specified in mock request");
                }

                return $headers[strtolower($key)];
            });

        return $request;
    }

    public function algorithmProvider()
    {
        return [
            ['ed25519'],
            [['ed25519', 'ed25519-sha256']],
        ];
    }

    /**
     * @dataProvider algorithmProvider
     */
    public function testGetSupportedAlgorithms($algoritm)
    {
        $service = new HTTPSignature($algoritm, function() {}, function() {});

        $this->assertEquals((array)$algoritm, $service->getSupportedAlgorithms());
    }

    public function testWithAlgorithm()
    {
        $service = new HTTPSignature(['ed25519', 'ed25519-sha256'], function() {}, function() {});

        $newService = $service->withAlgorithm('ed25519-sha256');
        $this->assertNotSame($service, $newService);
        $this->assertEquals(['ed25519-sha256'], $newService->getSupportedAlgorithms());

        $this->assertSame($newService, $newService->withAlgorithm('ed25519-sha256'));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unsupported algorithm: hmac-sha256
     */
    public function testWithAlgorithmWithUnsupported()
    {
        $service = new HTTPSignature(['ed25519', 'ed25519-sha256'], function() {}, function() {});

        $service->withAlgorithm('hmac-sha256');
    }

    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage No supported algorithms specified
     */
    public function testWithoutAnyAlgorithmsInConstructor()
    {
        new HTTPSignature([], function() {}, function() {});
    }

    public function testGetAndSetClockSkew()
    {
        $service = new HTTPSignature('hmac-sha256', function() {}, function() {});

        $this->assertEquals(300, $service->getClockSkew());

        $this->assertSame($service, $service->withClockSkew(300)); // Unchanged

        $modifiedService = $service->withClockSkew(1000);

        $this->assertInstanceOf(HTTPSignature::class, $modifiedService);
        $this->assertNotSame($service, $modifiedService);

        $this->assertEquals(1000, $modifiedService->getClockSkew());
    }

    public function testGetAndSetRequiredHeaders()
    {
        $service = new HTTPSignature('hmac-sha256', function() {}, function() {});

        $this->assertEquals(['(request-target)', 'date'], $service->getRequiredHeaders('get'));
        $this->assertEquals(['(request-target)', 'date'], $service->getRequiredHeaders('post'));

        $this->assertSame($service, $service->withRequiredHeaders('default', ['(request-target)', 'date']));

        $modified = $service
            ->withRequiredHeaders('default', ['(request-target)', 'date', 'x-custom'])
            ->withRequiredHeaders('POST', ['(request-target)', 'date', 'digest']);

        $this->assertInstanceOf(HTTPSignature::class, $modified);
        $this->assertNotSame($service, $modified);

        $this->assertEquals(['(request-target)', 'date', 'x-custom'], $modified->getRequiredHeaders('GET'));
        $this->assertEquals(['(request-target)', 'date', 'digest'], $modified->getRequiredHeaders('POST'));
    }

    public function dateHeaderProvider()
    {
        return [
            ['Date'],
            ['X-Date'],
        ];
    }

    /**
     * @dataProvider dateHeaderProvider
     */
    public function testVerifyGetRequest(string $dateHeaderName)
    {
        $sign = $this->createCallbackMock($this->never());

        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $signature = 'PIw+8VW129YY/6tRfThI3ZA0VygH4cYWxIayUZbdA3I9CKUdmqttvVZvOXN5BX2Z9jfO3f1vD1/R2jxwd3BHBw==';

        $url = '/foos?a=1';
        $headers = [$dateHeaderName => 'Sat, 22 Aug 1981 20:52:00 +0000'];
        $params = [
            'keyId' => $publicKey,
            'algorithm' => 'ed25519-sha256',
            'headers' => '(request-target) ' . strtolower($dateHeaderName),
            'signature' => $signature,
        ];

        $expectedMessage = join("\n", [
            '(request-target): get /foos?a=1',
            strtolower($dateHeaderName) . ': Sat, 22 Aug 1981 20:52:00 +0000'
        ]);

        $request = $this->createMockRequest('GET', $url, $headers, $params);

        $expectedArgs = [
            $expectedMessage,
            base64_decode($signature),
            $publicKey,
            'ed25519-sha256',
        ];
        $verify = $this->createCallbackMock($this->once(), $expectedArgs, true);

        $service = new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify);

        $service->verify($request);
    }

    /**
     * @dataProvider dateHeaderProvider
     */
    public function testVerifyPostRequest(string $dateHeaderName)
    {
        $sign = $this->createCallbackMock($this->never());

        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $signature = 'PIw+8VW129YY/6tRfThI3ZA0VygH4cYWxIayUZbdA3I9CKUdmqttvVZvOXN5BX2Z9jfO3f1vD1/R2jxwd3BHBw==';

        $url = '/foo';
        $headers = [
            $dateHeaderName => 'Sat, 22 Aug 1981 20:52:00 +0000',
            'Digest' => 'SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=',
            'Content-Length' => 18,
        ];
        $params = [
            'keyId' => $publicKey,
            'algorithm' => 'ed25519-sha256',
            'headers' => '(request-target) ' . strtolower($dateHeaderName) . ' digest content-length',
            'signature' => $signature,
        ];

        $expectedMessage = join("\n", [
            '(request-target): post /foo',
            strtolower($dateHeaderName) . ': Sat, 22 Aug 1981 20:52:00 +0000',
            'digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=',
            'content-length: 18'
        ]);

        $request = $this->createMockRequest('POST', $url, $headers, $params);

        $expectedArgs = [
            $expectedMessage,
            base64_decode($signature),
            $publicKey,
            'ed25519-sha256',
        ];
        $verify = $this->createCallbackMock($this->once(), $expectedArgs, true);

        $service = new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify);

        $service->verify($request);
    }

    /**
     * @expectedException \LTO\HTTPSignature\HTTPSignatureException
     * @expectedExceptionMessage missing "Authorization" header
     */
    public function testVerifyWithoutAuthorizationHeader()
    {
        $sign = $this->createCallbackMock($this->never());
        $verify = $this->createCallbackMock($this->never());

        $request = $this->createMock(Request::class);
        $request->expects($this->once())->method('hasHeader')->with('authorization')->willReturn(false);

        $service = new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify);

        $service->verify($request);
    }

    /**
     * @expectedException \LTO\HTTPSignature\HTTPSignatureException
     * @expectedExceptionMessage authorization scheme should be "Signature" not "Basic"
     */
    public function testVerifyWithInvalidAuthorizationMethod()
    {
        $sign = $this->createCallbackMock($this->never());
        $verify = $this->createCallbackMock($this->never());

        $request = $this->createMock(Request::class);
        $request->expects($this->once())->method('hasHeader')->with('authorization')->willReturn(true);
        $request->expects($this->once())->method('getHeaderLine')
            ->with('authorization')
            ->willReturn('Basic YWxhZGRpbjpvcGVuc2VzYW1l');

        $service = new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify);

        $service->verify($request);
    }

    /**
     * @expectedException \LTO\HTTPSignature\HTTPSignatureException
     * @expectedExceptionMessage corrupt "Authorization" header
     */
    public function testVerifyWithCorruptAuthorizationHeader()
    {
        $sign = $this->createCallbackMock($this->never());
        $verify = $this->createCallbackMock($this->never());

        $request = $this->createMock(Request::class);
        $request->expects($this->once())->method('hasHeader')->with('authorization')->willReturn(true);
        $request->expects($this->once())->method('getHeaderLine')
            ->with('authorization')
            ->willReturn('Signature hello');

        $service = new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify);

        $service->verify($request);
    }

    public function missingKeyProvider()
    {
        return [
            ['keyId'],
            ['algorithm'],
            ['headers'],
            ['signature'],
        ];
    }

    /**
     * @dataProvider missingKeyProvider
     *
     * @expectedException \LTO\HTTPSignature\HTTPSignatureException
     */
    public function testVerifyWithMissingKey(string $missingKey)
    {
        $sign = $this->createCallbackMock($this->never());
        $verify = $this->createCallbackMock($this->never());

        $this->expectExceptionMessage($missingKey . ' not specified in Authorization header');

        $url = '/foos?a=1';
        $headers = ['date' => 'Sat, 22 Aug 1981 20:52:00 +0000'];
        $params = [
            'keyId' => 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG',
            'algorithm' => 'ed25519-sha256',
            'headers' => '(request-target) date',
            'signature' => 'PIw+8VW129YY/6tRfThI3ZA0VygH4cYWxIayUZbdA3I9CKUdmqttvVZvOXN5BX2Z9jfO3f1vD1/R2jxwd3BHBw==',
        ];

        unset($params[$missingKey]);

        $request = $this->createMockRequest('GET', $url, $headers, $params);

        $service = new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify);

        $service->verify($request);
    }

    /**
     * @expectedException \LTO\HTTPSignature\HTTPSignatureException
     * @expectedExceptionMessage signed with unsupported algorithm: hmac-sha256
     */
    public function testVerifyWithUnsupportedAlgorithm()
    {
        $sign = $this->createCallbackMock($this->never());
        $verify = $this->createCallbackMock($this->never());

        $url = '/foos?a=1';
        $headers = ['date' => 'Sat, 22 Aug 1981 20:52:00 +0000'];
        $params = [
            'keyId' => 'secret',
            'algorithm' => 'hmac-sha256',
            'headers' => '(request-target) date',
            'signature' => '+eZuF5tnR65UEI+C+K3os8Jddv0wr95sOVgixTAZYWk=',
        ];

        $request = $this->createMockRequest('GET', $url, $headers, $params);

        $service = new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify);

        $service->verify($request);
    }

    /**
     * @expectedException \LTO\HTTPSignature\HTTPSignatureException
     * @expectedException invalid signature
     */
    public function testVerifyWithInvalidSignature()
    {
        $sign = $this->createCallbackMock($this->never());

        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $signature = 'aW52YWxpZA==';

        $url = '/foos?a=1';
        $headers = ['date' => 'Sat, 22 Aug 1981 20:52:00 +0000'];
        $params = [
            'keyId' => $publicKey,
            'algorithm' => 'ed25519-sha256',
            'headers' => '(request-target) date',
            'signature' => $signature
        ];

        $expectedMessage = join("\n", [
            '(request-target): get /foos?a=1',
            'date: Sat, 22 Aug 1981 20:52:00 +0000'
        ]);

        $request = $this->createMockRequest('GET', $url, $headers, $params);

        $expectedArgs = [
            $expectedMessage,
            base64_decode($signature),
            $publicKey,
            'ed25519-sha256',
        ];
        $verify = $this->createCallbackMock($this->once(), $expectedArgs, false);

        $service = new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify);

        $service->verify($request);
    }

    public function missingHeaderProvider()
    {
        return [
            [['date', 'digest'], 'digest is not part of signature'],
            [['date', 'digest', 'content-length'], 'digest, content-length are not part of signature'],
        ];
    }

    /**
     * @dataProvider missingHeaderProvider
     * @expectedException \LTO\HTTPSignature\HTTPSignatureException
     */
    public function testVerifyWithMissingHeader(array $requiredHeaders, string $message)
    {
        $this->expectExceptionMessage($message);

        $sign = $this->createCallbackMock($this->never());
        $verify = $this->createCallbackMock($this->never());

        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $signature = 'PIw+8VW129YY/6tRfThI3ZA0VygH4cYWxIayUZbdA3I9CKUdmqttvVZvOXN5BX2Z9jfO3f1vD1/R2jxwd3BHBw==';

        $url = '/foos?a=1';
        $headers = ['Date' => 'Sat, 22 Aug 1981 20:52:00 +0000'];
        $params = [
            'keyId' => $publicKey,
            'algorithm' => 'ed25519-sha256',
            'headers' => '(request-target) date',
            'signature' => $signature,
        ];

        $request = $this->createMockRequest('GET', $url, $headers, $params);

        $service = (new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify))
            ->withRequiredHeaders('default', $requiredHeaders);

        $service->verify($request);
    }

    public function testVerifyGetRequestWithoutDateHeader()
    {
        $sign = $this->createCallbackMock($this->never());

        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $signature = 'PIw+8VW129YY/6tRfThI3ZA0VygH4cYWxIayUZbdA3I9CKUdmqttvVZvOXN5BX2Z9jfO3f1vD1/R2jxwd3BHBw==';

        $url = '/foos?a=1';
        $headers = [];
        $params = [
            'keyId' => $publicKey,
            'algorithm' => 'ed25519-sha256',
            'headers' => '(request-target)',
            'signature' => $signature,
        ];

        $expectedMessage = '(request-target): get /foos?a=1';

        $request = $this->createMockRequest('GET', $url, $headers, $params);

        $expectedArgs = [
            $expectedMessage,
            base64_decode($signature),
            $publicKey,
            'ed25519-sha256',
        ];
        $verify = $this->createCallbackMock($this->once(), $expectedArgs, true);

        $service = (new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify))
            ->withRequiredHeaders('default', []);

        $service->verify($request);
    }

    /**
     * @expectedException \LTO\HTTPSignature\HTTPSignatureException
     * @expectedExceptionMessage signature to old or system clocks out of sync
     */
    public function testVerifyGetRequestWithOldDate()
    {
        $sign = $this->createCallbackMock($this->never());
        $verify = $this->createCallbackMock($this->never());

        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $signature = 'PIw+8VW129YY/6tRfThI3ZA0VygH4cYWxIayUZbdA3I9CKUdmqttvVZvOXN5BX2Z9jfO3f1vD1/R2jxwd3BHBw==';

        $url = '/foos?a=1';
        $headers = ['Date' => 'Sat, 22 Aug 1981 01:00:00 +0000'];
        $params = [
            'keyId' => $publicKey,
            'algorithm' => 'ed25519-sha256',
            'headers' => '(request-target) date',
            'signature' => $signature,
        ];

        $request = $this->createMockRequest('GET', $url, $headers, $params);

        $service = new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify);

        $service->verify($request);
    }


    /**
     * @dataProvider dateHeaderProvider
     */
    public function testSignGetRequest(string $dateHeaderName)
    {
        $verify = $this->createCallbackMock($this->never());

        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $signature = "PIw+8VW129YY/6tRfThI3ZA0VygH4cYWxIayUZbdA3I9CKUdmqttvVZvOXN5BX2Z9jfO3f1vD1/R2jxwd3BHBw==";

        $headers = [$dateHeaderName => 'Sat, 22 Aug 1981 20:52:00 +0000'];

        $expectedAuthorizationHeader = join(',', [
            'keyId="' . $publicKey . '"',
            'algorithm="ed25519-sha256"',
            'headers="(request-target) date"',
            'signature="' . $signature . '"',
        ]);

        $request = $this->createMockRequest('GET', '/foos?a=1', $headers);
        $signedRequest = $this->createMock(Request::class);

        $request->expects($this->once())->method('withHeader')
            ->with('Authorization', 'Signature ' . $expectedAuthorizationHeader)
            ->willReturn($signedRequest);

        $expectedMessage = join("\n", [
            "(request-target): get /foos?a=1",
            strtolower($dateHeaderName) . ": Sat, 22 Aug 1981 20:52:00 +0000"
        ]);

        $args = [$expectedMessage, $publicKey, 'ed25519-sha256'];
        $sign = $this->createCallbackMock($this->once(), $args, base64_decode($signature));

        $service = new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify);

        $ret = $service->sign($request, $publicKey, 'ed25519-sha256');

        $this->assertSame($signedRequest, $ret);
    }

    /**
     * @dataProvider dateHeaderProvider
     */
    public function testSignPostRequest(string $dateHeaderName)
    {
        $verify = $this->createCallbackMock($this->never());

        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $signature = "PIw+8VW129YY/6tRfThI3ZA0VygH4cYWxIayUZbdA3I9CKUdmqttvVZvOXN5BX2Z9jfO3f1vD1/R2jxwd3BHBw==";

        $headers = [
            $dateHeaderName => 'Sat, 22 Aug 1981 20:52:00 +0000',
            'Digest' => 'SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=',
            'Content-Length' => 18,
        ];

        $expectedAuthorizationHeader = join(',', [
            'keyId="' . $publicKey . '"',
            'algorithm="ed25519-sha256"',
            'headers="(request-target) ' . strtolower($dateHeaderName) . ' digest content-length"',
            'signature="' . $signature . '"',
        ]);

        $request = $this->createMockRequest('POST', '/foo', $headers);
        $signedRequest = $this->createMock(Request::class);

        $request->expects($this->once())->method('withHeader')
            ->with('Authorization', 'Signature ' . $expectedAuthorizationHeader)
            ->willReturn($signedRequest);

        $expectedMessage = join("\n", [
            "(request-target): post /foo",
            strtolower($dateHeaderName) . ": Sat, 22 Aug 1981 20:52:00 +0000",
            "digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
            "content-length: 18"
        ]);

        $args = [$expectedMessage, $publicKey, 'ed25519-sha256'];
        $sign = $this->createCallbackMock($this->once(), $args, base64_decode($signature));

        $requiredHeaders = ['(request-target)', strtolower($dateHeaderName), 'digest', 'content-length'];

        $service = (new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify))
            ->withRequiredHeaders('POST', $requiredHeaders);

        $ret = $service->sign($request, $publicKey, 'ed25519-sha256');

        $this->assertSame($signedRequest, $ret);
    }

    public function testSignGetRequestWithoutDateHeader()
    {
        $verify = $this->createCallbackMock($this->never());

        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $signature = "PIw+8VW129YY/6tRfThI3ZA0VygH4cYWxIayUZbdA3I9CKUdmqttvVZvOXN5BX2Z9jfO3f1vD1/R2jxwd3BHBw==";

        $headers = ['Date' => 'Sat, 22 Aug 1981 20:51:35 +0000'];

        $expectedAuthorizationHeader = join(',', [
            'keyId="' . $publicKey . '"',
            'algorithm="ed25519-sha256"',
            'headers="(request-target) date"',
            'signature="' . $signature . '"',
        ]);

        $request = $this->createMockRequest('GET', '/foos?a=1', []);
        $datedRequest = $this->createMockRequest('GET', '/foos?a=1', $headers);
        $signedRequest = $this->createMock(Request::class);

        $request->expects($this->once())->method('withHeader')
            ->with('Date', 'Sat, 22 Aug 1981 20:51:35 +0000')
            ->willReturn($datedRequest);
        $datedRequest->expects($this->once())->method('withHeader')
            ->with('Authorization', 'Signature ' . $expectedAuthorizationHeader)
            ->willReturn($signedRequest);

        $expectedMessage = join("\n", [
            "(request-target): get /foos?a=1",
            "date: Sat, 22 Aug 1981 20:51:35 +0000"
        ]);

        $args = [$expectedMessage, $publicKey, 'ed25519-sha256'];
        $sign = $this->createCallbackMock($this->once(), $args, base64_decode($signature));

        $service = new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify);

        $ret = $service->sign($request, $publicKey, 'ed25519-sha256');

        $this->assertSame($signedRequest, $ret);
    }

    public function testSignGetRequestWithImplicitAlgorithm()
    {
        $verify = $this->createCallbackMock($this->never());

        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $signature = "PIw+8VW129YY/6tRfThI3ZA0VygH4cYWxIayUZbdA3I9CKUdmqttvVZvOXN5BX2Z9jfO3f1vD1/R2jxwd3BHBw==";

        $headers = ['date' => 'Sat, 22 Aug 1981 20:52:00 +0000'];

        $expectedAuthorizationHeader = join(',', [
            'keyId="' . $publicKey . '"',
            'algorithm="ed25519-sha256"',
            'headers="(request-target) date"',
            'signature="' . $signature . '"',
        ]);

        $request = $this->createMockRequest('GET', '/foos?a=1', $headers);
        $signedRequest = $this->createMock(Request::class);

        $request->expects($this->once())->method('withHeader')
            ->with('Authorization', 'Signature ' . $expectedAuthorizationHeader)
            ->willReturn($signedRequest);

        $expectedMessage = join("\n", [
            "(request-target): get /foos?a=1",
            "date: Sat, 22 Aug 1981 20:52:00 +0000"
        ]);

        $args = [$expectedMessage, $publicKey, 'ed25519-sha256'];
        $sign = $this->createCallbackMock($this->once(), $args, base64_decode($signature));

        $service = new HTTPSignature('ed25519-sha256', $sign, $verify);

        $ret = $service->sign($request, $publicKey);

        $this->assertSame($signedRequest, $ret);
    }

    /**
     * @expectedException \BadMethodCallException
     * @expectedExceptionMessage Multiple algorithms available; no algorithm specified
     */
    public function testSignGetRequestWithUnspecifiedAlgorithm()
    {
        $verify = $this->createCallbackMock($this->never());
        $sign = $this->createCallbackMock($this->never());

        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $request = $this->createMock(Request::class);

        $service = new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify);

        $service->sign($request, $publicKey);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unsupported algorithm: hmac-sha256
     */
    public function testSignGetRequestWithUnsupportedAlgorithm()
    {
        $verify = $this->createCallbackMock($this->never());
        $sign = $this->createCallbackMock($this->never());

        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $request = $this->createMock(Request::class);

        $service = new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify);

        $service->sign($request, $publicKey, 'hmac-sha256');
    }
}
