import test from 'node:test'
import assert from 'node:assert/strict'
import googleWithEmailJWT from './tests/helpers/jwts/googleWithEmail.js'
import googleWithEmailNotVerifiedJWT from './tests/helpers/jwts/googleWithEmailNotVerified.js'
import googleWithKidJWT from './tests/helpers/jwts/googleWithKid.js'
import integreatJWT from './tests/helpers/jwts/validIntegreat.js'
import invalidJohnfJWT from './tests/helpers/jwts/invalidJohnfRaw.js'
import noSubJWT from './tests/helpers/jwts/noSub.js'
import validJohnfJWT from './tests/helpers/jwts/validJohnfRaw.js'
import validJohnfWithHttpsJWT from './tests/helpers/jwts/validJohnfRawWithHttps.js'
import unknownIssJWT from './tests/helpers/jwts/unknownIssuer.js'

import validate from './validate.js'

/*
 Note: The public keys and jwts in the tests are borrowed from another project,
 but they have never been used in any real capacity and are generated for
 testing only.
*/

// Setup

const addonPublicKey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoL4L168z16xjA0YvRhGD
wTMT1YTz6ItPP9j+pkMOSdg4B9OW+Gvc37yyqMNjuAMJG2PPo1i+XC4iYuHJ3YkJ
XfQIytolRAojaRgdcqY2exzK25VKhqlsd7prKWPdXLjTEFHMSqSfklJJsYl4frcM
cEV5glZGjunGLN4jnUEZ7MoBFTNswuSaD9kLIBwj/HaM+dEGVGY1ZVM3OaQDyj23
Vq7iA8TTUaq7cDoaLg+O/2kCmq9Vtpw5FU9hLdll0AZCCYgG/D2nxDKqxKF2KunT
h94GGJZdEYBQJ0Xt3PW6HuI9HJGO9fQJ/K+WpddRx6MGonM6LJHiLpJqbNUOEKej
Eg4Amoda7aZCyXAKXWtHqwqxRQ29FsI2+7vdvvPTilZyjA8NuGETE5AJtFNXCz37
vNuwURXCBlKCt4tv93VRGatK9IjUhgY5i3Xaz9y2FMaZxTaLqkHcTfFl/LQM75T8
tSpQjvRV8zhO+TrYqcV9pMMsN+0DSqxkLWNE6Jq6zAzvPG6cDMJm6G9ZD9asBNLX
icXZO/oR2ansB42RRKuqoeav7fmURXIzXgtWjQ6Wq7NlldwTiYb7GbVrsk3DQR4l
dN4yA7vDKsmJB6jV3AuobSjEcKE/cGXriGMREMLKS9lbiNkf2NfxhYLFnYbPpaV3
dsINY2oYCtTVrzZKoknLS7sCAwEAAQ==
-----END PUBLIC KEY-----`

const integreatPublicKey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxcH/rvEDOcrqobgu5sPY
+v3CSUyI39Y6IbEm22KaeJLbGkr/gdCPzA1POT73ZUyX77e7F7hF29uYhGCSAmi+
5blKcDNJ3VE9RdTSdkplpniAq8Agj9HhtqNatg90Q0s58khW3C15gNu9g71mEA5l
IsuTVi7oQkA7OYBptZke5tI26/KTubH9m0seQJHSUhvV6EAlTTY5iCYPhmTyOaYH
GH9LEHduWKa0K/8LNqM1q4W5mc7XX0EEgZ9vH4iQIsM9T1xjfQQa1BeBmipfkEZ8
yE1QUXgvWwxeCDSKaGg9VW3QS/deiwE8CgzAa53BrQMjsA1JqVfrvK1tDvYUjOWj
VlQkcBi4DPUGBINSVrfKIbKlkQ9muu1mIxtEYx86k87O1jJHgW+vEWEBdM8yHjrl
stOrFvcw83b3z8cQaaBFmouuaqvkGPkiyAdvIclU8WtxRFSNGt8TUAAkU/G8rPYk
B0LaPAe76CIqPlf4jA8z01CFYdMyhaMvxDwGxtkBbF+YFv3kh3HPvV7nCWoY+HpV
K1d/qEOPtT0LXztS+jOuonhDBxdLmdLrKKYXq79zpcE5TQ955YAJsIGHjCVuD9xR
l6Xl4Iq8QIw5jt4l2uAL5gSLiyVVGq8Sqz/7FWgmbBega8hRnNlfuyZoYeKEv+ak
ndm9HTKx4W06zvarwtqV7scCAwEAAQ==
-----END PUBLIC KEY-----`

const trustedKeys = new Map<string, string>() // issuer -> trusted key
trustedKeys.set('rawreporting.io/googleaddon', addonPublicKey)
trustedKeys.set('integreat.io', integreatPublicKey)
trustedKeys.set(
  'google.com|rawdata.no|58b429662db0786f2efefe13c1eb12a28dc442d0',
  integreatPublicKey,
)

const authentication = { status: 'granted' } // Doesn't matter what we pass here
const options = { trustedKeys }

// Tests

test('should return response with token from valid and verified jwt', async () => {
  const action = {
    type: 'GET',
    payload: {
      type: 'table',
      source: '24so',
      id: 'order',
      client: 'client1',
      pageSize: 2,
      path: '/',
      method: 'GET',
      headers: {
        authorization: `Bearer ${validJohnfJWT}`,
      },
    },
  }
  const expected = {
    status: 'ok',
    access: {
      ident: { withToken: 'rawreporting.io/googleaddon|johnf@gmail.com' },
    },
  }

  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const ret = await validate!(authentication, options, action)

  assert.deepEqual(ret, expected)
})

test('should set ident from valid and verified jwt from other known issuer', async () => {
  const action = {
    type: 'GET',
    payload: {
      type: 'table',
      source: '24so',
      id: 'order',
      client: 'client1',
      pageSize: 2,
      path: '/',
      method: 'GET',
      headers: {
        authorization: `Bearer ${integreatJWT}`,
      },
    },
  }
  const expected = {
    status: 'ok',
    access: {
      ident: { withToken: 'integreat.io|7617840F-1827-4FAB-83D8-4607A770E5B1' },
    },
  }

  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const ret = await validate!(authentication, options, action)

  assert.deepEqual(ret, expected)
})

test('should set ident from valid and verified jwt from other known issuer with key id (in header) and aud', async () => {
  const action = {
    type: 'GET',
    payload: {
      type: 'table',
      source: '24so',
      id: 'order',
      client: 'client1',
      pageSize: 2,
      path: '/',
      method: 'GET',
      headers: {
        authorization: `Bearer ${googleWithKidJWT}`,
      },
    },
  }
  const expected = {
    status: 'ok',
    access: {
      ident: { withToken: 'google.com|C074B1BB-92DB-4E0C-9445-3B8292395F3C' },
    },
  }

  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const ret = await validate!(authentication, options, action)

  assert.deepEqual(ret, expected)
})

test('should set ident with tokens from valid and verified jwt with email', async () => {
  const action = {
    type: 'GET',
    payload: {
      type: 'table',
      source: '24so',
      id: 'order',
      client: 'client1',
      pageSize: 2,
      path: '/',
      method: 'GET',
      headers: {
        authorization: `Bearer ${googleWithEmailJWT}`,
      },
    },
  }
  const expected = {
    status: 'ok',
    access: {
      ident: {
        withToken: [
          'google.com|C074B1BB-92DB-4E0C-9445-3B8292395F3C',
          'google.com|johnf@gmail.com',
        ],
      },
    },
  }

  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const ret = await validate!(authentication, options, action)

  assert.deepEqual(ret, expected)
})

test('should not set email token when email in jwt is not verified', async () => {
  const action = {
    type: 'GET',
    payload: {
      type: 'table',
      source: '24so',
      id: 'order',
      client: 'client1',
      pageSize: 2,
      path: '/',
      method: 'GET',
      headers: {
        authorization: `Bearer ${googleWithEmailNotVerifiedJWT}`,
      },
    },
  }
  const expected = {
    status: 'ok',
    access: {
      ident: {
        withToken: 'google.com|C074B1BB-92DB-4E0C-9445-3B8292395F3C',
      },
    },
  }

  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const ret = await validate!(authentication, options, action)

  assert.deepEqual(ret, expected)
})

test('should set email token when email in jwt is not verified and requireEmailVerified is false', async () => {
  const optionsAllowNonverified = { ...options, requireEmailVerified: false }
  const action = {
    type: 'GET',
    payload: {
      type: 'table',
      source: '24so',
      id: 'order',
      client: 'client1',
      pageSize: 2,
      path: '/',
      method: 'GET',
      headers: {
        authorization: `Bearer ${googleWithEmailNotVerifiedJWT}`,
      },
    },
  }
  const expected = {
    status: 'ok',
    access: {
      ident: {
        withToken: [
          'google.com|C074B1BB-92DB-4E0C-9445-3B8292395F3C',
          'google.com|johnf@gmail.com',
        ],
      },
    },
  }

  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const ret = await validate!(authentication, optionsAllowNonverified, action)

  assert.deepEqual(ret, expected)
})

test('should remove https in issuer', async () => {
  const action = {
    type: 'GET',
    payload: {
      type: 'table',
      source: '24so',
      id: 'order',
      client: 'client1',
      pageSize: 2,
      path: '/',
      method: 'GET',
      headers: {
        authorization: `Bearer ${validJohnfWithHttpsJWT}`,
      },
    },
  }
  const expected = {
    status: 'ok',
    access: {
      ident: { withToken: 'rawreporting.io/googleaddon|johnf@gmail.com' },
    },
  }

  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const ret = await validate!(authentication, options, action)

  assert.deepEqual(ret, expected)
})

test('should return noaccess response for unknown issuer', async () => {
  const action = {
    type: 'GET',
    payload: {
      type: 'table',
      source: '24so',
      id: 'order',
      client: 'client1',
      pageSize: 2,
      path: '/',
      method: 'GET',
      headers: {
        authorization: `Bearer ${unknownIssJWT}`,
      },
    },
  }
  const expected = {
    status: 'noaccess',
    error: 'No access. Unknown issuer or audience',
    reason: 'invalidauth',
  }

  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const ret = await validate!(authentication, options, action)

  assert.deepEqual(ret, expected)
})

test('should return autherror response when jwt is not valid', async () => {
  const action = {
    type: 'GET',
    payload: {
      type: 'table',
      source: '24so',
      id: 'order',
      client: 'client1',
      pageSize: 2,
      path: '/',
      method: 'GET',
      headers: {
        authorization: `Bearer ${invalidJohnfJWT}`,
      },
    },
  }
  const expected = {
    status: 'autherror',
    error: 'Unauthorized. JWT is not valid',
    reason: 'invalidauth',
  }

  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const ret = await validate!(authentication, options, action)

  assert.deepEqual(ret, expected)
})

test('should return autherror response when jwt is missing sub', async () => {
  const action = {
    type: 'GET',
    payload: {
      type: 'table',
      source: '24so',
      id: 'order',
      client: 'client1',
      pageSize: 2,
      path: '/',
      method: 'GET',
      headers: {
        authorization: `Bearer ${noSubJWT}`,
      },
    },
  }
  const expected = {
    status: 'autherror',
    error: 'Unauthorized. Credentials are not valid',
    reason: 'invalidauth',
  }

  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const ret = await validate!(authentication, options, action)

  assert.deepEqual(ret, expected)
})

test('should return noaccess when no action', async () => {
  const action = null
  const expected = {
    status: 'noaccess',
    error: 'Authentication required',
    reason: 'noauth',
  }

  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const ret = await validate!(authentication, options, action)

  assert.deepEqual(ret, expected)
})

test('should return noaccess when action has no auth header', async () => {
  const action = {
    type: 'GET',
    payload: {
      type: 'table',
      source: '24so',
      id: 'order',
      client: 'client1',
      pageSize: 2,
      path: '/',
      method: 'GET',
      // No auth header
    },
  }
  const expected = {
    status: 'noaccess',
    error: 'Authentication required',
    reason: 'noauth',
  }

  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const ret = await validate!(authentication, options, action)

  assert.deepEqual(ret, expected)
})
