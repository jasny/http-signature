<?php

namespace LTO\HTTPSignature;

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
        CarbonImmutable::setTestNow(CarbonImmutable::createFromTimeString('Tue, 07 Jun 2014 20:51:35 GMT'));
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
     * @param string   $method
     * @param string   $url
     * @param string[] $params
     * @param string[] $headers
     * @return Request&MockObject
     */
    protected function createMockRequest(string $method, string $url, array $params, array $headers): MockObject
    {
        $request = $this->createMock(Request::class);

        $request->expects($this->any())->method('getMethod')->willReturn($method);

        $uri = $this->createUri($url);
        $request->expects($this->any())->method('getUri')->willReturn($uri);

        $paramString = Pipeline::with($params)
            ->map(function(string $value, string $key) {
                return sprintf('%s="%s"', $key, addcslashes($value, '"'));
            })
            ->concat(",");

        $headers = array_change_key_case($headers, CASE_LOWER);
        $headers['authorization'] = "Signature $paramString";

        $request->expects($this->any())->method('hasHeader')
            ->willReturnCallback(function($key) use ($headers) {
                return isset($headers[$key]);
            });

        $request->expects($this->any())->method('getHeaderLine')
            ->willReturnCallback(function($key) use ($headers) {
                if (!isset($headers[$key])) {
                    throw new \OutOfBoundsException("Header '$key' not specified in mock request");
                }

                return $headers[$key];
            });

        return $request;
    }

    public function testGetSupportedAlgorithms()
    {
        $service = new HTTPSignature(['ed25519', 'ed25519-sha256'], function() {}, function() {});

        $this->assertEquals(['ed25519', 'ed25519-sha256'], $service->getSupportedAlgorithms());
    }

    public function testGetAndSetClockSkew()
    {
        $service = new HTTPSignature([], function() {}, function() {});

        $this->assertEquals(300, $service->getClockSkew());

        $this->assertSame($service, $service->withClockSkew(300)); // Unchanged

        $modifiedService = $service->withClockSkew(1000);

        $this->assertInstanceOf(HTTPSignature::class, $modifiedService);
        $this->assertNotSame($service, $modifiedService);

        $this->assertEquals(1000, $modifiedService->getClockSkew());
    }

    public function testGetAndSetRequiredHeaders()
    {
        $service = new HTTPSignature([], function() {}, function() {});

        $this->assertEquals(['date'], $service->getRequiredHeaders());

        $this->assertSame($service, $service->withRequiredHeaders(['date'])); // Unchanged

        $modifiedService = $service->withRequiredHeaders(['(request-target)', 'date', 'digest', 'content-length']);

        $this->assertInstanceOf(HTTPSignature::class, $modifiedService);
        $this->assertNotSame($service, $modifiedService);

        $expected = ['(request-target)', 'date', 'digest', 'content-length'];
        $this->assertEquals($expected, $modifiedService->getRequiredHeaders());
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
        $headers = [$dateHeaderName => 'Tue, 07 Jun 2014 20:52:00 GMT'];
        $params = [
            'keyId' => $publicKey,
            'algorithm' => 'ed25519-sha256',
            'headers' => '(request-target) ' . strtolower($dateHeaderName),
            'signature' => $signature,
        ];

        $expectedMessage = join("\n", [
            '(request-target): get /foos?a=1',
            strtolower($dateHeaderName) . ': Tue, 07 Jun 2014 20:52:00 GMT'
        ]);

        $request = $this->createMockRequest('GET', $url, $params, $headers);

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
            $dateHeaderName => 'Tue, 07 Jun 2014 20:52:00 GMT',
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
            strtolower($dateHeaderName) . ': Tue, 07 Jun 2014 20:52:00 GMT',
            'digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=',
            'content-length: 18'
        ]);

        $request = $this->createMockRequest('POST', $url, $params, $headers);

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
    public function testVerifyWithMissingKey($missingKey)
    {
        $sign = $this->createCallbackMock($this->never());
        $verify = $this->createCallbackMock($this->never());

        $this->expectExceptionMessage($missingKey . ' not specified in Authorization header');

        $url = '/foos?a=1';
        $headers = ['date' => 'Tue, 07 Jun 2014 20:52:00 GMT'];
        $params = [
            'keyId' => 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG',
            'algorithm' => 'ed25519-sha256',
            'headers' => '(request-target) date',
            'signature' => 'PIw+8VW129YY/6tRfThI3ZA0VygH4cYWxIayUZbdA3I9CKUdmqttvVZvOXN5BX2Z9jfO3f1vD1/R2jxwd3BHBw==',
        ];

        unset($params[$missingKey]);

        $request = $this->createMockRequest('GET', $url, $params, $headers);

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
        $headers = ['date' => 'Tue, 07 Jun 2014 20:52:00 GMT'];
        $params = [
            'keyId' => 'secret',
            'algorithm' => 'hmac-sha256',
            'headers' => '(request-target) date',
            'signature' => '+eZuF5tnR65UEI+C+K3os8Jddv0wr95sOVgixTAZYWk=',
        ];

        $request = $this->createMockRequest('GET', $url, $params, $headers);

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
        $headers = ['date' => 'Tue, 07 Jun 2014 20:52:00 GMT'];
        $params = [
            'keyId' => $publicKey,
            'algorithm' => 'ed25519-sha256',
            'headers' => '(request-target) date',
            'signature' => $signature
        ];

        $expectedMessage = join("\n", [
            '(request-target): get /foos?a=1',
            'date: Tue, 07 Jun 2014 20:52:00 GMT'
        ]);

        $request = $this->createMockRequest('GET', $url, $params, $headers);

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
        $headers = ['Date' => 'Tue, 07 Jun 2014 20:52:00 GMT'];
        $params = [
            'keyId' => $publicKey,
            'algorithm' => 'ed25519-sha256',
            'headers' => '(request-target) date',
            'signature' => $signature,
        ];

        $request = $this->createMockRequest('GET', $url, $params, $headers);

        $service = (new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify))
            ->withRequiredHeaders($requiredHeaders);

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

        $request = $this->createMockRequest('GET', $url, $params, $headers);

        $expectedArgs = [
            $expectedMessage,
            base64_decode($signature),
            $publicKey,
            'ed25519-sha256',
        ];
        $verify = $this->createCallbackMock($this->once(), $expectedArgs, true);

        $service = (new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify))
            ->withRequiredHeaders([]);

        $service->verify($request);
    }

    /**
     * @expectedException \LTO\HTTPSignature\HTTPSignatureException
     * @expectedException signature to old or system clocks out of sync
     */
    public function testVerifyGetRequestWithOldDate()
    {
        $sign = $this->createCallbackMock($this->never());
        $verify = $this->createCallbackMock($this->never());

        $publicKey = 'AVXUh6yvPG8XYqjbUgvKeEJQDQM7DggboFjtGKS8ETRG';
        $signature = 'PIw+8VW129YY/6tRfThI3ZA0VygH4cYWxIayUZbdA3I9CKUdmqttvVZvOXN5BX2Z9jfO3f1vD1/R2jxwd3BHBw==';

        $url = '/foos?a=1';
        $headers = ['Date' => 'Tue, 07 Jun 2014 01:00:00 GMT'];
        $params = [
            'keyId' => $publicKey,
            'algorithm' => 'ed25519-sha256',
            'headers' => '(request-target) date',
            'signature' => $signature,
        ];

        $request = $this->createMockRequest('GET', $url, $params, $headers);

        $service = (new HTTPSignature(['ed25519', 'ed25519-sha256'], $sign, $verify));

        $service->verify($request);
    }

    /**
     */
    public function testSignGETRequest()
    {
        $this->markTestSkipped();

        $msg = join("\n", [
            "(request-target): post /foo",
            "date: Tue, 07 Jun 2014 20:51:35 GMT",
            "digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
            "content-length: 18"
        ]);
        $hash = "0b50f70b241111e3233c84279697f7d80efae4303b54a8959c1ac68a54fe7736";
        $signature = "PIw+8VW129YY/6tRfThI3ZA0VygH4cYWxIayUZbdA3I9CKUdmqttvVZvOXN5BX2Z9jfO3f1vD1/R2jxwd3BHBw==";

        $account = $this->createMock(Account::class);
        $account->expects($this->once())->method('getPublicSignKey')->with('base64')
            ->willReturn("2yYhlEGdosg7QZC//hibHiZ1MHk2m7jp/EbUeFdzDis=");
        $account->expects($this->once())->method('sign')
            ->with($algorithm === 'ed25519-sha256' ? pack('H*', $hash) : $msg, 'base64')
            ->willReturn($signature);

        $request = $this->createMock(Request::class);
        $request->expects($this->any())->method('hasHeader')->with('date')->willReturn(true);
        $request->expects($this->any())->method('getHeaderLine')->with('date')
            ->willReturn("Tue, 07 Jun 2014 20:51:35 GMT");
        $request->expects($this->once())->method('withHeader')
            ->with('authorization', 'Signature keyId="2yYhlEGdosg7QZC//hibHiZ1MHk2m7jp/EbUeFdzDis=",algorithm="' . $algorithm . '",headers="(request-target) date digest content-length",signature="PIw+8VW129YY/6tRfThI3ZA0VygH4cYWxIayUZbdA3I9CKUdmqttvVZvOXN5BX2Z9jfO3f1vD1/R2jxwd3BHBw=="')
            ->willReturnSelf();

        $httpSign = $this->createHTTPSignature($request, ['getHeaders', 'getMessage']);

        $httpSign->expects($this->once())->method('getHeaders')
            ->willReturn(["(request-target)", "date", "digest", "content-length"]);
        $httpSign->expects($this->once())->method('getMessage')->willReturn($msg);

        $ret = $httpSign->signWith($account, $algorithm);
        $this->assertSame($request, $ret);

        $this->assertSame($account, $httpSign->getAccount());
        $this->assertEquals([
            'keyId' => "2yYhlEGdosg7QZC//hibHiZ1MHk2m7jp/EbUeFdzDis=",
            'algorithm' => $algorithm,
            'headers' => "(request-target) date digest content-length"
        ], $httpSign->getParams());
    }
}
