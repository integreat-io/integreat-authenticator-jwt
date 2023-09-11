import test from 'ava'

import isAuthenticated from './isAuthenticated.js'

// Tests

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

  const ret = isAuthenticated(authentication, options, action)

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

  const ret = isAuthenticated(authentication, options, action)

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

  const ret = isAuthenticated(authentication, options, action)

  t.false(ret)
})

test('isAuthenticated should return false when expire is in the past', (t) => {
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

  t.false(ret)
})

test('isAuthenticated should return true when expire is in the future', (t) => {
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

  const ret = isAuthenticated(authentication, options, action)

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

  const ret = isAuthenticated(authentication, options, action)

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

  const ret = isAuthenticated(authentication, options, action)

  t.false(ret)
})
