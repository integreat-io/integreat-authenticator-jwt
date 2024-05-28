import test from 'ava'
import jwt from 'jsonwebtoken'

import authenticator from './index.js'

// Setup

type Dictionary = { [key: string]: unknown }

const parseJwt = (token: string | null) =>
  token ? jwt.decode(token) : { token: null }

const action = {
  type: 'GET',
  payload: { data: null },
  meta: { ident: { id: 'johnf' } },
}

// Tests

test('should be an authenticator', (t) => {
  t.is(typeof authenticator, 'object')
  t.is(typeof authenticator.extractAuthKey, 'function')
  t.is(typeof authenticator.authenticate, 'function')
  t.is(typeof authenticator.isAuthenticated, 'function')
  t.is(typeof authenticator.validate, 'function')
  t.is(typeof authenticator.authentication, 'object')
  t.is(typeof authenticator.authentication.asObject, 'function')
  t.is(typeof authenticator.authentication.asHttpHeaders, 'function')
})

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
  t.is(ret.expire, undefined)
  t.is(ret.authKey, 'johnf')
  t.is(typeof ret.token, 'string')
  const payload = parseJwt(ret.token as string) as Dictionary
  t.is(payload.sub, 'johnf')
  t.true((payload.iat as number) >= now - 1)
  t.true((payload.iat as number) < now + 1)
  t.is(payload.aud, 'waste-iq')
  t.is(typeof payload.exp, 'undefined')
})

// Tests -- isAuthenticated

test('isAuthenticated should return true for valid authentication', (t) => {
  const authentication = {
    status: 'granted',
    token: 's0m3t0k3n',
    expire: undefined,
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

// Tests -- asObject

test('asObject should return token', (t) => {
  const authentication = {
    status: 'granted',
    token: 't0k3n',
    expire: undefined,
  }
  const expected = { token: 't0k3n' }

  const ret = authenticator.authentication.asObject(authentication)

  t.deepEqual(ret, expected)
})

test('asObject should return empty object when not granted', (t) => {
  const authentication = { status: 'refused', token: null, expire: undefined }
  const expected = {}

  const ret = authenticator.authentication.asObject(authentication)

  t.deepEqual(ret, expected)
})

test('asObject should return empty object when no token', (t) => {
  const authentication = { status: 'granted', token: null, expire: undefined }
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
  const authentication = {
    status: 'granted',
    token: 't0k3n',
    expire: undefined,
  }
  const expected = { Authorization: 'Bearer t0k3n' }

  const ret = authenticator.authentication.asHttpHeaders(authentication)

  t.deepEqual(ret, expected)
})

test('asHttpHeaders should return empty object when not granted', (t) => {
  const authentication = { status: 'refused', token: null, expire: undefined }
  const expected = {}

  const ret = authenticator.authentication.asHttpHeaders(authentication)

  t.deepEqual(ret, expected)
})

test('asHttpHeaders should return empty object when no token', (t) => {
  const authentication = { status: 'granted', token: null, expire: undefined }
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
