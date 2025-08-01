import test from 'node:test'
import assert from 'node:assert/strict'

import isAuthenticated from './isAuthenticated.js'

// Tests

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

  const ret = isAuthenticated(authentication, options, action)

  assert.equal(ret, true)
})

test('isAuthenticated should return false for status refused', () => {
  const authentication = {
    status: 'refused',
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

  const ret = isAuthenticated(authentication, options, action)

  assert.equal(ret, false)
})

test('isAuthenticated should return false when no token', () => {
  const authentication = {
    status: 'granted',
    token: undefined,
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

  const ret = isAuthenticated(authentication, options, action)

  assert.equal(ret, false)
})

test('isAuthenticated should return false when expire is in the past', () => {
  const authentication = {
    status: 'granted',
    token: 's0m3t0k3n',
    expire: 1687632749000,
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

  const ret = isAuthenticated(authentication, options, action)

  assert.equal(ret, false)
})

test('isAuthenticated should return true when expire is in the future', () => {
  const authentication = {
    status: 'granted',
    token: 's0m3t0k3n',
    expire: Math.round(Date.now()) + 5 * 60,
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

  const ret = isAuthenticated(authentication, options, action)

  assert.equal(ret, true)
})

test('isAuthenticated should return false for wrong authKey', () => {
  const authentication = {
    status: 'granted',
    token: 's0m3t0k3n',
    expire: undefined,
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

  const ret = isAuthenticated(authentication, options, action)

  assert.equal(ret, false)
})

test('isAuthenticated should return true for authKey with other subPath', () => {
  const authentication = {
    status: 'granted',
    token: 's0m3t0k3n',
    expire: undefined,
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

  const ret = isAuthenticated(authentication, options, action)

  assert.equal(ret, true)
})

test('isAuthenticated should return false for no authentication', () => {
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

  const ret = isAuthenticated(authentication, options, action)

  assert.equal(ret, false)
})
