import test from 'node:test'
import assert from 'node:assert/strict'
import jwt from 'jsonwebtoken'

import authenticate from './authenticate.js'

// Setup

type Dictionary = Record<string, unknown>

const parseJwt = (token: string | null) =>
  token ? jwt.decode(token) : { token: null }

const verifyJwt = (
  token: string | null,
  key: string,
  algorithm: jwt.Algorithm = 'HS256',
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

test('authenticate should generate jwt token', async () => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }
  const now = Math.round(Date.now() / 1000)

  const ret = await authenticate(options, action)

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

test('authenticate should use other prop as sub', async () => {
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

  const ret = await authenticate(options, action)

  const payload = parseJwt(ret.token as string) as Dictionary
  assert.equal(payload.sub, 'bettyk')
  assert.equal(ret.authKey, 'bettyk')
})

test('authenticate should add payload to JWT payload', async () => {
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

  const ret = await authenticate(options, action)

  const payload = parseJwt(ret.token as string) as Dictionary
  assert.deepEqual(payload.permissions, ['editor'])
})

test('authenticate should set expire time', async () => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
    expiresIn: '5m',
  }
  const exp = Math.round(Date.now() / 1000) + 5 * 60

  const ret = await authenticate(options, action)

  assert.equal(ret.status, 'granted', ret?.error)
  const payload = parseJwt(ret.token as string) as Dictionary
  assert.equal(typeof payload.exp, 'number')
  assert.ok((payload.exp as number) >= exp - 1)
  assert.ok((payload.exp as number) < exp + 1)
  assert.ok((ret.expire as number) >= exp * 1000 - 2000) // Should set expire 1s before, to avoid being off by a few milliseconds
  assert.ok((ret.expire as number) < exp * 1000)
})

test('authenticate should sign payload', async () => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }

  const ret = await authenticate(options, action)

  assert.doesNotThrow(
    () => verifyJwt(ret.token as string, 's3cr3t'),
    'Token is not signed correctly',
  )
})

test('authenticate should sign with given algorithm', async () => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
    algorithm: 'HS384' as const,
  }

  const ret = await authenticate(options, action)

  assert.doesNotThrow(
    () => verifyJwt(ret.token as string, 's3cr3t', 'HS384'),
    'Token is not signed correctly',
  )
})

test('authenticate should refuse when no sub', async () => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
    subPath: 'payload.params.unknown',
  }

  const ret = await authenticate(options, action)

  assert.equal(ret.status, 'refused')
  assert.equal(ret.error, 'Auth refused due to missing subject')
  assert.equal(ret.token, null)
})

test('authenticate should refuse when signing fails', async () => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
    algorithm: 'INVALID',
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ret = await authenticate(options as any, action)

  assert.equal(ret.status, 'refused')
  assert.equal(
    ret.error,
    'Auth refused. Error: "algorithm" must be a valid string enum value',
  )
  assert.equal(ret.token, null)
})

test('authenticate should refuse when no options', async () => {
  const options = null

  const ret = await authenticate(options, action)

  assert.equal(ret.status, 'refused')
  assert.equal(ret.error, 'Auth refused due to missing key or audience')
  assert.equal(ret.token, null)
})

test('authenticate should refuse when no action', async () => {
  const action = null
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }

  const ret = await authenticate(options, action)

  assert.equal(ret.status, 'refused')
  assert.equal(ret.error, 'Auth refused due to missing action')
  assert.equal(ret.token, null)
})
