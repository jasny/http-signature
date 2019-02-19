HTTP Signature service and middleware (PHP)
===

[![Build Status](https://travis-ci.org/legalthings/http-signature.php.svg?branch=master)](https://travis-ci.org/legalthings/http-signature.php)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/legalthings/http-signature.php/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/legalthings/http-signature.php/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/legalthings/http-signature.php/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/legalthings/http-signature.php/?branch=master)
[![Packagist Stable Version](https://img.shields.io/packagist/v/legalthings/http-signature.php.svg)](https://packagist.org/packages/legalthings/http-signature.php)
[![Packagist License](https://img.shields.io/packagist/l/legalthings/http-signature.php.svg)](https://packagist.org/packages/legalthings/http-signature.php)

This library provides a service for implementing the [IETF HTTP Signatures draft RFC](https://tools.ietf.org/html/draft-cavage-http-signatures).
It includes PSR-7 compatible middleware for signing requests (by an HTTP client like Guzzle) and verifying http
signatures.

Installation
---

    composer require lto/http-signature

Usage
---


