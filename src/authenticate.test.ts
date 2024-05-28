import test from 'ava'
import jwt from 'jsonwebtoken'

import authenticate from './authenticate.js'

// Setup

type Dictionary = { [key: string]: unknown }

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

test('authenticate should generate jwt token', async (t) => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }
  const now = Math.round(Date.now() / 1000)

  const ret = await authenticate(options, action)

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

  const ret = await authenticate(options, action)

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

  const ret = await authenticate(options, action)

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

  const ret = await authenticate(options, action)

  t.is(ret.status, 'granted', ret?.error)
  const payload = parseJwt(ret.token as string) as Dictionary
  t.is(typeof payload.exp, 'number')
  t.true((payload.exp as number) >= exp - 1)
  t.true((payload.exp as number) < exp + 1)
  t.true((ret.expire as number) >= exp * 1000 - 2000) // Should set expire 1s before, to avoid being off by a few milliseconds
  t.true((ret.expire as number) < exp * 1000)
})

test('authenticate should sign payload', async (t) => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
  }

  const ret = await authenticate(options, action)

  t.notThrows(
    () => verifyJwt(ret.token as string, 's3cr3t'),
    'Token is not signed correctly',
  )
})

test('authenticate should sign with given algorithm', async (t) => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
    algorithm: 'HS384' as const,
  }

  const ret = await authenticate(options, action)

  t.notThrows(
    () => verifyJwt(ret.token as string, 's3cr3t', 'HS384'),
    'Token is not signed correctly',
  )
})

test('authenticate should refuse when no sub', async (t) => {
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
    subPath: 'payload.params.unknown',
  }

  const ret = await authenticate(options, action)

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
  const ret = await authenticate(options as any, action)

  t.is(ret.status, 'refused')
  t.is(
    ret.error,
    'Auth refused. Error: "algorithm" must be a valid string enum value',
  )
  t.is(ret.token, null)
})

test('authenticate should refuse when no options', async (t) => {
  const options = null

  const ret = await authenticate(options, action)

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

  const ret = await authenticate(options, action)

  t.is(ret.status, 'refused')
  t.is(ret.error, 'Auth refused due to missing action')
  t.is(ret.token, null)
})
