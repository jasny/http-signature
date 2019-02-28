<?php declare(strict_types=1);

namespace Jasny\HttpSignature;

use Improved as i;
use const Improved\FUNCTION_ARGUMENT_PLACEHOLDER as __;

use Carbon\CarbonImmutable;
use Improved\IteratorPipeline\Pipeline;
use Psr\Http\Message\RequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;

/**
 * Create and verify HTTP Signatures.
 * Only support signatures using the ED25519 algorithm.
 */
class HttpSignature
{
    /**
     * @var int
     */
    protected $clockSkew = 300;

    /**
     * Headers required / used in message per request method.
     * @var array
     */
    protected $requiredHeaders = [
        'default' => ['(request-target)', 'date'],
    ];

    /**
     * Supported algorithms
     * @var string[]
     */
    protected $supportedAlgorithms;

    /**
     * Function to sign a request.
     * @var callable
     */
    protected $sign;

    /**
     * Function to verify a signed request.
     * @var callable
     */
    protected $verify;


    /**
     * Class construction.
     *
     * @param string|string[] $algorithm  Supported algorithm(s).
     * @param callable        $sign       Function to sign a request.
     * @param callable        $verify     Function to verify a signed request.
     */
    public function __construct($algorithm, callable $sign, callable $verify)
    {
        if (is_array($algorithm) && count($algorithm) === 0) {
            throw new \InvalidArgumentException('No supported algorithms specified');
        }

        $this->supportedAlgorithms = is_array($algorithm) ? array_values($algorithm) : [$algorithm];

        $this->sign = $sign;
        $this->verify = $verify;
    }

    /**
     * Create a clone of the service where one of the algorithms is supported.
     *
     * @param string $algorithm
     * @return self
     * @throw \InvalidArgumentException
     */
    public function withAlgorithm(string $algorithm)
    {
        if ($this->supportedAlgorithms === [$algorithm]) {
            return $this;
        }

        if (!in_array($algorithm, $this->supportedAlgorithms, true)) {
            throw new \InvalidArgumentException('Unsupported algorithm: ' . $algorithm);
        }

        $clone = clone $this;
        $clone->supportedAlgorithms = [$algorithm];

        return $clone;
    }

    /**
     * Get supported cryptography algorithms.
     *
     * @return string[]
     */
    public function getSupportedAlgorithms(): array
    {
        return $this->supportedAlgorithms;
    }

    /**
     * Get service with modified max clock offset.
     *
     * @param int $clockSkew
     * @return static
     */
    public function withClockSkew(int $clockSkew = 300)
    {
        if ($this->clockSkew === $clockSkew) {
            return $this;
        }

        $clone = clone $this;
        $clone->clockSkew = $clockSkew;
        
        return $clone;
    }
    
    /**
     * Get the max clock offset.
     *
     * @return int
     */
    public function getClockSkew(): int
    {
        return $this->clockSkew;
    }

    /**
     * Set the required headers for the signature message.
     *
     * @param string $method   HTTP Request method or 'default'
     * @param array  $headers
     * @return static
     */
    public function withRequiredHeaders(string $method, array $headers)
    {
        $method = strtolower($method);

        $headers = Pipeline::with($headers)
            ->map(i\function_partial('strtolower', __))
            ->values()
            ->toArray();

        if (isset($this->requiredHeaders[$method]) && $this->requiredHeaders[$method] === $headers) {
            return $this;
        }

        $clone = clone $this;
        $clone->requiredHeaders[$method] = $headers;

        return $clone;
    }

    /**
     * Get the required headers for the signature message.
     *
     * @param string $method
     * @return string[]
     */
    public function getRequiredHeaders(string $method): array
    {
        $method = strtolower($method);

        return $this->requiredHeaders[$method] ?? $this->requiredHeaders['default'];
    }


    /**
     * Verify the signature
     *
     * @param Request $request
     * @return string `keyId` parameter
     * @throws HttpSignatureException
     */
    public function verify(Request $request): string
    {
        $params = $this->getParams($request);
        $this->assertParams($params);

        $method = $request->getMethod();
        $headers = isset($params['headers']) ? explode(' ', $params['headers']) : [];
        $this->assertRequiredHeaders($method, $headers);

        $this->assertSignatureAge($request);

        $message = $this->getMessage($request, $headers);
        $keyId = $params['keyId'] ?? '';
        $signature = base64_decode($params['signature'] ?? '', true);

        $verified = ($this->verify)($message, $signature, $keyId, $params['algorithm'] ?? 'unknown');

        if (!$verified) {
            throw new HttpSignatureException("invalid signature");
        }

        return $params['keyId'];
    }

    /**
     * Sign a request.
     *
     * @param Request     $request
     * @param string      $keyId      Public key or key reference
     * @param string|null $algorithm  Signing algorithm, must be specified if more than one is supported.
     * @return Request
     * @throws \RuntimeException for an unsupported or unspecified algorithm
     */
    public function sign(Request $request, string $keyId, ?string $algorithm = null): Request
    {
        $method = $request->getMethod();

        $params = [
            'keyId' => $keyId,
            'algorithm' => $this->getSignAlgorithm($algorithm),
            'headers' => join(' ', $this->getRequiredHeaders($method))
        ];

        if (!$request->hasHeader('Date') && !$request->hasHeader('X-Date')) {
            $date = CarbonImmutable::now()->format(DATE_RFC1123);
            $request = $request->withHeader('Date', $date);
        }

        $headers = $this->getSignHeaders($request);
        $message = $this->getMessage($request, $headers);

        $rawSignature = ($this->sign)($message, $keyId, $params['algorithm']);
        i\type_check($rawSignature, 'string', new \UnexpectedValueException('Expected %2$s, %1$s given'));

        $signature = base64_encode($rawSignature);

        $args = [$params['keyId'], $params['algorithm'], $params['headers'], $signature];
        $header = sprintf('Signature keyId="%s",algorithm="%s",headers="%s",signature="%s"', ...$args);

        return $request->withHeader('Authorization', $header);
    }

    /**
     * Set the `WWW-Authenticate` header for each algorithm (on a 401 response).
     *
     * @param string   $method
     * @param Response $response
     * @return Response
     */
    public function setAuthenticateResponseHeader(string $method, Response $response): Response
    {
        $algorithms = $this->getSupportedAlgorithms();
        $requiredHeaders = $this->getRequiredHeaders($method);

        $header = sprintf('Signature algorithm="%%s",headers="%s"', join(' ', $requiredHeaders));

        foreach ($algorithms as $algorithm) {
            $response = $response->withHeader('WWW-Authenticate', sprintf($header, $algorithm));
        }

        return $response;
    }

    /**
     * Extract the authorization Signature parameters
     *
     * @param Request $request
     * @return string[]
     * @throws HttpSignatureException
     */
    protected function getParams(Request $request): array
    {
        if (!$request->hasHeader('authorization')) {
            throw new HttpSignatureException('missing "Authorization" header');
        }
        
        $auth = $request->getHeaderLine('authorization');
        
        list($method, $paramString) = explode(' ', $auth, 2) + [null, null];
        
        if (strtolower($method) !== 'signature') {
            throw new HttpSignatureException(sprintf('authorization scheme should be "Signature" not "%s"', $method));
        }
        
        if (!preg_match_all('/(\w+)\s*=\s*"([^"]++)"\s*(,|$)/', $paramString, $matches, PREG_PATTERN_ORDER)) {
            throw new HttpSignatureException('corrupt "Authorization" header');
        }
        
        return array_combine($matches[1], $matches[2]);
    }

    /**
     * Assert that required headers are present
     *
     * @param string   $method
     * @param string[] $headers
     * @throws HttpSignatureException
     */
    protected function assertRequiredHeaders(string $method, array $headers): void
    {
        if (in_array('x-date', $headers, true)) {
            $key = array_search('x-date', $headers, true);
            $headers[$key] = 'date';
        }

        $missing = array_diff($this->getRequiredHeaders($method), $headers);

        if ($missing !== []) {
            $err = sprintf("%s %s not part of signature", join(', ', $missing), count($missing) === 1 ? 'is' : 'are');
            throw new HttpSignatureException($err);
        }
    }

    /**
     * Get message that should be signed.
     *
     * @param Request  $request
     * @param string[] $headers
     * @return string
     */
    protected function getMessage(Request $request, array $headers): string
    {
        $headers = Pipeline::with($headers)
            ->map(i\function_partial('strtolower', __))
            ->toArray();

        $message = [];
        
        foreach ($headers as $header) {
            $message[] = $header === '(request-target)'
                ? sprintf("%s: %s", '(request-target)', $this->getRequestTarget($request))
                : sprintf("%s: %s", $header, $request->getHeaderLine($header));
        }
        
        return join("\n", $message);
    }

    /**
     * Build a request line.
     *
     * @param Request $request
     * @return string
     */
    protected function getRequestTarget(Request $request): string
    {
        $method = strtolower($request->getMethod());
        $uri = (string)$request->getUri()->withScheme('')->withHost('')->withPort(null)->withUserInfo('');

        return $method . ' ' . $uri;
    }

    /**
     * Assert all required parameters are available.
     *
     * @param string[] $params
     * @throws HttpSignatureException
     */
    protected function assertParams(array $params): void
    {
        $required = ['keyId', 'algorithm', 'headers', 'signature'];

        foreach ($required as $param) {
            if (!isset($params[$param])) {
                throw new HttpSignatureException("{$param} not specified in Authorization header");
            }
        }

        if (!in_array($params['algorithm'], $this->supportedAlgorithms, true)) {
            throw new HttpSignatureException(sprintf(
                'signed with unsupported algorithm: %s',
                $params['algorithm']
            ));
        }
    }

    /**
     * Asset that the signature is not to old
     *
     * @param Request $request
     * @throws HttpSignatureException
     */
    protected function assertSignatureAge(Request $request): void
    {
        $dateString =
            ($request->hasHeader('x-date') ? $request->getHeaderLine('x-date') : null) ??
            ($request->hasHeader('date') ? $request->getHeaderLine('date') : null);

        if ($dateString === null) {
            return; // Normally 'Date' should be a required header, so we shouldn't event get to this point.
        }

        $date = CarbonImmutable::createFromTimeString($dateString);

        if (abs(CarbonImmutable::now()->diffInSeconds($date)) > $this->clockSkew) {
            throw new HttpSignatureException("signature to old or system clocks out of sync");
        }
    }

    /**
     * Get the headers that should be part of the message used to create the signature.
     *
     * @param Request $request
     * @return string[]
     */
    protected function getSignHeaders(Request $request): array
    {
        $headers = $this->getRequiredHeaders($request->getMethod());

        if (in_array('date', $headers, true) && $request->hasHeader('X-Date')) {
            $index = array_search('date', $headers, true);
            $headers[$index] = 'x-date';
        }

        return $headers;
    }

    /**
     * Get the algorithm to sign the request.
     * Assert that the algorithm is supported.
     *
     * @param string|null $algorithm
     * @return string
     * @throws \RuntimeException
     */
    protected function getSignAlgorithm(?string $algorithm): string
    {
        if ($algorithm === null && count($this->supportedAlgorithms) > 1) {
            throw new \BadMethodCallException(sprintf('Multiple algorithms available; no algorithm specified'));
        }

        if ($algorithm !== null && !in_array($algorithm, $this->supportedAlgorithms, true)) {
            throw new \InvalidArgumentException('Unsupported algorithm: ' . $algorithm);
        }

        return $algorithm ?? $this->supportedAlgorithms[0];
    }
}
