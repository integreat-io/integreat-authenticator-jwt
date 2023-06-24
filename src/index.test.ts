/* eslint-disable @typescript-eslint/no-non-null-assertion */
import test from 'ava'
import jwt from 'jsonwebtoken'

import authenticator from './index.js'

// Setup

type Dictionary = { [key: string]: unknown }

const parseJwt = (token: string | null) =>
  token ? jwt.decode(token) : { token: null }

const verifyJwt = (
  token: string | null,
  key: string,
  algorithm: jwt.Algorithm = 'HS256'
) => {
  if (token) {
    return jwt.verify(token, key, { algorithms: [algorithm] })
  } else {
    throw new Error('No token')
  }
}

const action = {
  type: 'GET',
  payload: { data: null },
  meta: { ident: { id: 'johnf' } },
}

// Tests -- extractAuthKey

test('should use action ident (sub) as auth key', (t) => {
  const action = {
    type: 'GET',
    payload: { data: null, params: { userid: 'bettyk' } },
    meta: { ident: { id: 'johnf' } },
  }
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }

  const ret = authenticator.extractAuthKey!(options, action)

  t.is(ret, 'johnf')
})

test('should use property given by subPath as auth key', (t) => {
  const action = {
    type: 'GET',
    payload: { data: null, params: { userid: 'bettyk' } },
    meta: { ident: { id: 'johnf' } },
  }
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
    subPath: 'payload.params.userid',
  }

  const ret = authenticator.extractAuthKey!(options, action)

  t.is(ret, 'bettyk')
})

// Tests -- authenticate

test('authenticate should generate jwt token', async (t) => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }
  const now = Math.round(Date.now() / 1000)

  const ret = await authenticator.authenticate(options, action)

  t.truthy(ret)
  t.is(ret.status, 'granted')
  t.is(ret.expire, null)
  t.is(ret.authKey, 'johnf')
  t.is(typeof ret.token, 'string')
  const payload = parseJwt(ret.token as string) as Dictionary
  t.is(payload.sub, 'johnf')
  t.true((payload.iat as number) >= now - 1)
  t.true((payload.iat as number) < now + 1)
  t.is(payload.aud, 'waste-iq')
  t.is(typeof payload.exp, 'undefined')
})

test('authenticate should use other prop as sub', async (t) => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
    subPath: 'payload.params.userid',
  }
  const action = {
    type: 'GET',
    payload: { data: null, params: { userid: 'bettyk' } },
    meta: { ident: { id: 'johnf' } },
  }

  const ret = await authenticator.authenticate(options, action)

  const payload = parseJwt(ret.token as string) as Dictionary
  t.is(payload.sub, 'bettyk')
  t.is(ret.authKey, 'bettyk')
})

test('authenticate should add payload to JWT payload', async (t) => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
    payload: { permissions: ['editor'] },
  }
  const action = {
    type: 'GET',
    payload: { data: null, params: { userid: 'bettyk' } },
    meta: { ident: { id: 'johnf' } },
  }

  const ret = await authenticator.authenticate(options, action)

  const payload = parseJwt(ret.token as string) as Dictionary
  t.deepEqual(payload.permissions, ['editor'])
})

test('authenticate should set expire time', async (t) => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
    expiresIn: '5m',
  }
  const exp = Math.round(Date.now() / 1000) + 5 * 60

  const ret = await authenticator.authenticate(options, action)

  t.is(ret.status, 'granted', ret?.error)
  const payload = parseJwt(ret.token as string) as Dictionary
  t.is(typeof payload.exp, 'number')
  t.true((payload.exp as number) >= exp - 1)
  t.true((payload.exp as number) < exp + 1)
  t.true((ret.expire as number) >= exp * 1000 - 1000)
  t.true((ret.expire as number) < exp * 1000 + 1000)
})

test('authenticate should sign payload', async (t) => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }

  const ret = await authenticator.authenticate(options, action)

  t.notThrows(
    () => verifyJwt(ret.token as string, 's3cr3t'),
    'Token is not signed correctly'
  )
})

test('authenticate should sign with given algorithm', async (t) => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
    algorithm: 'HS384' as const,
  }

  const ret = await authenticator.authenticate(options, action)

  t.notThrows(
    () => verifyJwt(ret.token as string, 's3cr3t', 'HS384'),
    'Token is not signed correctly'
  )
})

test('authenticate should refuse when no sub', async (t) => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
    subPath: 'payload.params.unknown',
  }

  const ret = await authenticator.authenticate(options, action)

  t.is(ret.status, 'refused')
  t.is(ret.error, 'Auth refused due to missing subject')
  t.is(ret.token, null)
})

test('authenticate should refuse when signing fails', async (t) => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
    algorithm: 'INVALID',
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ret = await authenticator.authenticate(options as any, action)

  t.is(ret.status, 'refused')
  t.is(
    ret.error,
    'Auth refused. Error: "algorithm" must be a valid string enum value'
  )
  t.is(ret.token, null)
})

test('authenticate should refuse when no options', async (t) => {
  const options = null

  const ret = await authenticator.authenticate(options, action)

  t.is(ret.status, 'refused')
  t.is(ret.error, 'Auth refused due to missing key or audience')
  t.is(ret.token, null)
})

test('authenticate should refuse when no action', async (t) => {
  const action = null
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }

  const ret = await authenticator.authenticate(options, action)

  t.is(ret.status, 'refused')
  t.is(ret.error, 'Auth refused due to missing action')
  t.is(ret.token, null)
})

// Tests -- isAuthenticated

test('isAuthenticated should return true for valid authentication', (t) => {
  const authentication = {
    status: 'granted',
    token: 's0m3t0k3n',
    expire: null,
    authKey: 'johnf',
  }
  const action = {
    type: 'GET',
    payload: { data: null },
    meta: { ident: { id: 'johnf' } },
  }
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }

  const ret = authenticator.isAuthenticated(authentication, options, action)

  t.true(ret)
})

test('isAuthenticated should return false for status refused', (t) => {
  const authentication = {
    status: 'refused',
    token: 's0m3t0k3n',
    expire: null,
    authKey: 'johnf',
  }
  const action = {
    type: 'GET',
    payload: { data: null },
    meta: { ident: { id: 'johnf' } },
  }
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }

  const ret = authenticator.isAuthenticated(authentication, options, action)

  t.false(ret)
})

test('isAuthenticated should return false when no token', (t) => {
  const authentication = {
    status: 'granted',
    token: undefined,
    expire: null,
    authKey: 'johnf',
  }
  const action = {
    type: 'GET',
    payload: { data: null },
    meta: { ident: { id: 'johnf' } },
  }
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }

  const ret = authenticator.isAuthenticated(authentication, options, action)

  t.false(ret)
})

test('isAuthenticated should return false when expire is in the past', (t) => {
  const authentication = {
    status: 'granted',
    token: 's0m3t0k3n',
    expire: 1687632749,
    authKey: 'johnf',
  }
  const action = {
    type: 'GET',
    payload: { data: null },
    meta: { ident: { id: 'johnf' } },
  }
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }

  const ret = authenticator.isAuthenticated(authentication, options, action)

  t.false(ret)
})

test('isAuthenticated should return true when expire is in the future', (t) => {
  const authentication = {
    status: 'granted',
    token: 's0m3t0k3n',
    expire: Math.round(Date.now() / 1000) + 5 * 60,
    authKey: 'johnf',
  }
  const action = {
    type: 'GET',
    payload: { data: null },
    meta: { ident: { id: 'johnf' } },
  }
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }

  const ret = authenticator.isAuthenticated(authentication, options, action)

  t.true(ret)
})

test('isAuthenticated should return false for wrong authKey', (t) => {
  const authentication = {
    status: 'granted',
    token: 's0m3t0k3n',
    expire: null,
    authKey: 'wrong',
  }
  const action = {
    type: 'GET',
    payload: { data: null },
    meta: { ident: { id: 'johnf' } },
  }
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }

  const ret = authenticator.isAuthenticated(authentication, options, action)

  t.false(ret)
})

test('isAuthenticated should return true for authKey with other subPath', (t) => {
  const authentication = {
    status: 'granted',
    token: 's0m3t0k3n',
    expire: null,
    authKey: 'bettyk',
  }
  const action = {
    type: 'GET',
    payload: { data: null, params: { userid: 'bettyk' } },
    meta: { ident: { id: 'johnf' } },
  }
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
    subPath: 'payload.params.userid',
  }

  const ret = authenticator.isAuthenticated(authentication, options, action)

  t.true(ret)
})

test('isAuthenticated should return false for no authentication', (t) => {
  const authentication = null
  const action = {
    type: 'GET',
    payload: { data: null },
    meta: { ident: { id: 'johnf' } },
  }
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }

  const ret = authenticator.isAuthenticated(authentication, options, action)

  t.false(ret)
})

// Tests -- asObject

test('asObject should return token', (t) => {
  const authentication = { status: 'granted', token: 't0k3n', expire: null }
  const expected = { token: 't0k3n' }

  const ret = authenticator.authentication.asObject(authentication)

  t.deepEqual(ret, expected)
})

test('asObject should return empty object when not granted', (t) => {
  const authentication = { status: 'refused', token: null, expire: null }
  const expected = {}

  const ret = authenticator.authentication.asObject(authentication)

  t.deepEqual(ret, expected)
})

test('asObject should return empty object when no token', (t) => {
  const authentication = { status: 'granted', token: null, expire: null }
  const expected = {}

  const ret = authenticator.authentication.asObject(authentication)

  t.deepEqual(ret, expected)
})

test('asObject should return empty object when no authentication', (t) => {
  const authentication = null
  const expected = {}

  const ret = authenticator.authentication.asObject(authentication)

  t.deepEqual(ret, expected)
})

// Tests -- asHttpHeaders

test('asHttpHeaders should return auth header with token', (t) => {
  const authentication = { status: 'granted', token: 't0k3n', expire: null }
  const expected = { Authorization: 'Bearer t0k3n' }

  const ret = authenticator.authentication.asHttpHeaders(authentication)

  t.deepEqual(ret, expected)
})

test('asHttpHeaders should return empty object when not granted', (t) => {
  const authentication = { status: 'refused', token: null, expire: null }
  const expected = {}

  const ret = authenticator.authentication.asHttpHeaders(authentication)

  t.deepEqual(ret, expected)
})

test('asHttpHeaders should return empty object when no token', (t) => {
  const authentication = { status: 'granted', token: null, expire: null }
  const expected = {}

  const ret = authenticator.authentication.asHttpHeaders(authentication)

  t.deepEqual(ret, expected)
})

test('asHttpHeaders should return empty object when no authentication', (t) => {
  const authentication = null
  const expected = {}

  const ret = authenticator.authentication.asHttpHeaders(authentication)

  t.deepEqual(ret, expected)
})
