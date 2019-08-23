# Contributing to SuperTokens

Contributions are always welcome. Before contributing please read the [code of conduct](https://github.com/supertokens/supertokens-laravel-ref-jwt/blob/master/CODE_OF_CONDUCT.md) & search [the issue tracker](https://github.com/supertokens/supertokens-laravel-ref-jwt/issues); your issue may have already been discussed or fixed in master. To contribute, fork SuperTokens, commit your changes, & send a pull request.

# Questions
We are most accessible via team@supertokens.io, via the GitHub issues feature and our [Discord server](https://supertokens.io/discord). 

## Pull Requests
Before issuing a pull request, please make sure:
- Code is formatted properly according to PSR1 and PSR2 specifications - we have a pre-commit hook to enforce this
- All tests are passing. We will also be running tests when you issue a pull request.

Please only issue pull requests to the dev branch.


## Prerequisites

1) You will need PHP and composer on your local system to run and test the repo.

2) Install package dependencies
    ```bash
    composer install --dev
    ```

3) Set-up hooks
    ```bash
    make set-up-hooks
    ```

## Coding standards
In addition to the following guidelines, please follow the conventions already established in the code.

- **Comments**
    - Please refrain from commenting very obvious code. But for anything else, please do add comments.
    - For every function, please write what it returns, if it throws an error (and what type), as well as what the params mean (if they are not obvious).

- **Error handling**
    - All Exceptions must be extended from SuperTokensException.

All other issues like quote styles, spacing etc.. will be taken care of by the formatter.


## Pre committing checks

1) Run the make lint script
    ```bash
    make lint
    make check-lint
    ```

## Pre push

Run unit tests and make sure all tests are passing.
```bash
make test
```
