# JWT authenticator for Integreat

Signs a JWT token.

[![npm Version](https://img.shields.io/npm/v/integreat-authenticator-jwt.svg)](https://www.npmjs.com/package/integreat-authenticator-jwt)
![Coverage Status](https://coveralls.io/repos/github/integreat-io/integreat-authenticator-jwt/badge.svg?branch=master)](https://coveralls.io/github/integreat-io/integreat-authenticator-jwt?branch=master)
[![Maintainability](https://api.codeclimate.com/v1/badges/6331723a6ff61de5f232/maintainability)](https://codeclimate.com/github/integreat-io/integreat-authenticator-jwt/maintainability)

## Getting started

### Prerequisits

Requires node v18 and Integreat v0.8.

### Installing and using

Install from npm:

```
npm install integreat-authenticator-jwt
```

The authenticator supports the following options:

- `key`: The key to sign the JWT with. Required
- `algorithm`: The algorithm to sign with. Default `HS256`
- `subPath`: A dot notation path into the request object, to get the JWT sub
  claim
- `audience`: The JWT audience claim. Required
- `expiresIn`: The expiration time for the JWT, as a ms string. When not set,
  the token will never expire
- `payload`: An object whose properties will be set on the JWT payload

### Running the tests

The tests can be run with `npm test`.

## Contributing

Please read
[CONTRIBUTING](https://github.com/integreat-io/integreat-authenticator-jwt/blob/master/CONTRIBUTING.md)
for details on our code of conduct, and the process for submitting pull
requests.

## License

This project is licensed under the ISC License - see the
[LICENSE](https://github.com/integreat-io/integreat-authenticator-jwt/blob/master/LICENSE)
file for details.
