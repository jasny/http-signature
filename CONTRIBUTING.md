# How to contribute

Thanks for taking the time to contribute.

Please read this guide to better understand the project.

## Project structure

| directory    |                                               |
|--------------|-----------------------------------------------|
| bin          | Commandline scripts and tools                 |
| config       | Application configuration                     |
| controller   | Controller classes to handle (HTTP) requests  |
| declarations | Service declarations for dependency injection |
| lib          | Non-app specific services and other classes   |
| models       | Objects that are represented in the database  |
| services     | App specific services                         |
| tests        | Automated tests                               |
| www          | Webserver document root                       |

## Code quality

This project is written in PHP, a language that is known for it's _spooky behaviour at runtime_. To combat this, we
enforce much stricter rules than you typically find in PHP projects. 

### PSR

The project follows [PSR-1: Basic Coding Standard](https://www.php-fig.org/psr/psr-1/),
[PSR-2: Coding Style Guide](https://www.php-fig.org/psr/psr-2/) and
[PSR-4: Improved Autoloading](https://www.php-fig.org/psr/psr-4/).

### Static code analysis 

[PHPStan](https://github.com/phpstan/phpstan) is a static code analysis tool, that is able to find errors without
running the code.

PHPStan moves PHP closer to compiled languages in the sense that the correctness of each line of the code can be checked
before you run the actual line.

### Strict dynamic typing

PHP has loose dynamic typing and type coercion. This is a reminisce from the past, and should be avoided.

The project also uses PHPStan to deduct variable types and verify correct use. For a overview of the rules, please see
[PHPStan strict rules](https://github.com/phpstan/phpstan-strict-rules).

#### Operator restrictions

Arithmetic and loose comparison operators, may only be be used on numeric values (`int`, `float`). This rule applies to
`-`, `*`, `/`, `**`, `%`, `==`, `!=`, `<`, `>`, `<=`, `>=` and `<=>`.

In general use `===` and `!==` for comparing two values. To order strings using `strcmp`.

### Global state

Using the global state static is strictly prohibited. This includes global I/O functions (`echo`, `print`, `header`),
superglobals (`$_GET`, `$_POST`, `$_SESSION`, etc), and static properties.

Input / output is handled by a [PSR-7 compatible HTTP request handler](https://www.php-fig.org/psr/psr-15/).

The project uses dependency injection with a [PSR-11 compatible container](https://www.php-fig.org/psr/psr-11/) to
manage services.

### External libraries

PHP extensions are typically a very thin layer over a C library. While this is great for performance, they don't provide
the level of abstraction you may expect from a high level language.

Rather than using these functions directly, use an abstraction library that provides a consistent interface, does type
checking and throws exceptions.

The project uses the [Improved PHP library](https://github.com/improved-php-library) for rudimentary functions as
manipulating strings and arrays.

### Immutable services

Services are constructed as immutable objects. This means there are not `setter` methods or other methods that somehow
changes the state of a service. Services may implement `with` methods, which creates a new copy of the service.

Mutable services can cause issues that are difficult to reproduce.

## Tests

Test use the [Codeception test framework](https://codeception.com/). The project contains unit and api tests. Code in
the controllers is only covered by the api tests.

    bin/codecept run

To run only a single test use

    bin/codecept run api Default/100-InfoCept

For more options see the [Codeception docs on 'run'](https://codeception.com/docs/reference/Commands#run).

Services should have 100% test coverage.

### HTTP Mock

External services MUST be mocked. For api tests use `$I->expectHttpRequest()` to mock and assert external http calls
done by Guzzle.

```php
$I->expectHttpRequest(function (Request $request) use ($I) {
    $I->assertEquals('http://example.com', (string)$request->getUri());
    $I->assertEquals('application/json', $request->getHeaderLine('Content-Type'));

    $I->assertJsonStringEqualsJsonString('{"foo": "bar"}', (string)$request->getBody());
    
    return new Response(200);
});
```

## Pull request

Create a new branch for your feature and add a pull request. It's not possible to commit and push to the `master`
branch.

Each pull request is automatically checked by [Scrutinizer](https://scrutinizer-ci.com/), which does static code
analysis and style checks, and [Travis](https://travis-ci.com/), which runs automated tests.

While running QA on your local machine might succeed, Scrutinizer might still fail if it detects a reduction in code
quality. This may be caused with trying to commit code that isn't properly tested or low in quality. 

Each pull request is manually checked by a project member. As such, make sure the PR is small enough to be checked.
Break a big change up in smaller chunks if needed.
