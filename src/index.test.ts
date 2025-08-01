import test from 'node:test'
import assert from 'node:assert/strict'
import jwt from 'jsonwebtoken'
import type { Action, Response } from 'integreat'

import authenticator from './index.js'

// Setup

type Dictionary = Record<string, unknown>

const parseJwt = (token: string | null) =>
  token ? jwt.decode(token) : { token: null }

const action = {
  type: 'GET',
  payload: { data: null },
  meta: { ident: { id: 'johnf' } },
}

const dispatch = async (_action: Action): Promise<Response> => ({
  status: 'ok',
})

// Tests

test('should be an authenticator', () => {
  assert.equal(typeof authenticator, 'object')
  assert.equal(typeof authenticator.extractAuthKey, 'function')
  assert.equal(typeof authenticator.authenticate, 'function')
  assert.equal(typeof authenticator.isAuthenticated, 'function')
  assert.equal(typeof authenticator.validate, 'function')
  assert.equal(typeof authenticator.authentication, 'object')
  assert.equal(typeof authenticator.authentication.asObject, 'function')
  assert.equal(typeof authenticator.authentication.asHttpHeaders, 'function')
})

// Tests -- extractAuthKey

test('should use action ident (sub) as auth key', () => {
  const action = {
    type: 'GET',
    payload: { data: null, params: { userid: 'bettyk' } },
    meta: { ident: { id: 'johnf' } },
  }
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }

  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const ret = authenticator.extractAuthKey!(options, action)

  assert.equal(ret, 'johnf')
})

test('should use property given by subPath as auth key', () => {
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

  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const ret = authenticator.extractAuthKey!(options, action)

  assert.equal(ret, 'bettyk')
})

// Tests -- authenticate

test('authenticate should generate jwt token', async () => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }
  const now = Math.round(Date.now() / 1000)

  const ret = await authenticator.authenticate(options, action, dispatch, null)

  assert.ok(ret)
  assert.equal(ret.status, 'granted')
  assert.equal(ret.expire, undefined)
  assert.equal(ret.authKey, 'johnf')
  assert.equal(typeof ret.token, 'string')
  const payload = parseJwt(ret.token as string) as Dictionary
  assert.equal(payload.sub, 'johnf')
  assert.ok((payload.iat as number) >= now - 1)
  assert.ok((payload.iat as number) < now + 1)
  assert.equal(payload.aud, 'waste-iq')
  assert.equal(typeof payload.exp, 'undefined')
})

// Tests -- isAuthenticated

test('isAuthenticated should return true for valid authentication', () => {
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

  assert.ok(ret)
})

// Tests -- asObject

test('asObject should return token', () => {
  const authentication = {
    status: 'granted',
    token: 't0k3n',
    expire: undefined,
  }
  const expected = { token: 't0k3n' }

  const ret = authenticator.authentication.asObject(authentication)

  assert.deepEqual(ret, expected)
})

test('asObject should return empty object when not granted', () => {
  const authentication = { status: 'refused', token: null, expire: undefined }
  const expected = {}

  const ret = authenticator.authentication.asObject(authentication)

  assert.deepEqual(ret, expected)
})

test('asObject should return empty object when no token', () => {
  const authentication = { status: 'granted', token: null, expire: undefined }
  const expected = {}

  const ret = authenticator.authentication.asObject(authentication)

  assert.deepEqual(ret, expected)
})

test('asObject should return empty object when no authentication', () => {
  const authentication = null
  const expected = {}

  const ret = authenticator.authentication.asObject(authentication)

  assert.deepEqual(ret, expected)
})

// Tests -- asHttpHeaders

test('asHttpHeaders should return auth header with token', () => {
  const authentication = {
    status: 'granted',
    token: 't0k3n',
    expire: undefined,
  }
  const expected = { Authorization: 'Bearer t0k3n' }

  const ret = authenticator.authentication.asHttpHeaders(authentication)

  assert.deepEqual(ret, expected)
})

test('asHttpHeaders should return empty object when not granted', () => {
  const authentication = { status: 'refused', token: null, expire: undefined }
  const expected = {}

  const ret = authenticator.authentication.asHttpHeaders(authentication)

  assert.deepEqual(ret, expected)
})

test('asHttpHeaders should return empty object when no token', () => {
  const authentication = { status: 'granted', token: null, expire: undefined }
  const expected = {}

  const ret = authenticator.authentication.asHttpHeaders(authentication)

  assert.deepEqual(ret, expected)
})

test('asHttpHeaders should return empty object when no authentication', () => {
  const authentication = null
  const expected = {}

  const ret = authenticator.authentication.asHttpHeaders(authentication)

  assert.deepEqual(ret, expected)
})
