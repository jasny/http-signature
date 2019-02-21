# How to contribute

Thanks for taking the time to contribute. Please read this guide to better understand the project.

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

#### Improved PHP library

The project uses the [Improved PHP library](https://github.com/improved-php-library) for rudimentary functions as
manipulating strings and arrays.

#### Carbon

For dates and timestamps, using [`CarbonImmutable`](https://carbon.nesbot.com/) rather than the native `DateTime`
objects. Carbon makes it easier to test time related functions. Immutable value objects prevent unexpected side-effects.  

## Tests

Test use the [PHPUnit test framework](https://phpunit.de/). Source code should have 100% test coverage.

In rare cases, code may be excluded from test coverage using `@codeCoverageIgnore`. Please include a comment explaining
why the code is excluded.
