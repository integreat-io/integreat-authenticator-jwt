import test from 'ava'
import jwt = require('jsonwebtoken')
import sinon = require('sinon')

import authFn from '.'

// Setup

const authenticator = authFn()

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

// Tests

test('should always return false from isAuthenticated', (t) => {
  const authentication = { status: 'granted', token: 's0m3t0k3n', expire: null }

  const ret = authenticator.isAuthenticated(authentication, action)

  t.false(ret)
})

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
  t.is(typeof ret.token, 'string')
  const payload = parseJwt(ret.token) as Dictionary
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

  const payload = parseJwt(ret.token) as Dictionary
  t.is(payload.sub, 'bettyk')
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

  const payload = parseJwt(ret.token) as Dictionary
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

  const payload = parseJwt(ret.token) as Dictionary
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
    () => verifyJwt(ret.token, 's3cr3t'),
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
    () => verifyJwt(ret.token, 's3cr3t', 'HS384'),
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
  t.is(ret.token, null)
})

test('authenticate should log when no sub', async (t) => {
  const logger = { error: sinon.stub(), info: sinon.stub() }
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
    subPath: 'payload.params.unknown',
  }
  await authFn(logger).authenticate(options, action)

  t.is(logger.error.callCount, 1)
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
  t.is(ret.token, null)
})

test('authenticate should log when signing fails', async (t) => {
  const logger = { error: sinon.stub(), info: sinon.stub() }
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
    algorithm: 'INVALID',
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await authFn(logger).authenticate(options as any, action)

  t.is(logger.error.callCount, 1)
})

test('authenticate should refuse when no options', async (t) => {
  const options = null

  const ret = await authenticator.authenticate(options, action)

  t.is(ret.status, 'refused')
  t.is(ret.token, null)
})

test('authenticate should log when no options', async (t) => {
  const logger = { error: sinon.stub(), info: sinon.stub() }
  const options = null

  await authFn(logger).authenticate(options, action)

  t.is(logger.error.callCount, 1)
})

test('authenticate should refuse when no action', async (t) => {
  const action = null
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }

  const ret = await authenticator.authenticate(options, action)

  t.is(ret.status, 'refused')
  t.is(ret.token, null)
})

test('authenticate should log when no action', async (t) => {
  const logger = { error: sinon.stub(), info: sinon.stub() }
  const action = null
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }

  await authFn(logger).authenticate(options, action)

  t.is(logger.error.callCount, 1)
})

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
