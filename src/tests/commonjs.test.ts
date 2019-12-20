import test from 'ava'
import sinon = require('sinon')

import resourcesFn = require('..')

test('should have resources', t => {
  const resources = resourcesFn()
  t.truthy(resources)
  t.truthy(resources.authenticators)
  t.truthy(resources.authenticators.jwt)
})

test('should log error', async t => {
  const logger = {
    info: sinon.stub(),
    error: sinon.stub()
  }
  const resources = resourcesFn(logger)
  const options = {
    audience: 'waste-iq',
    key: 's3cr3t',
    subPath: 'params.userid'
  }
  const request = {
    action: 'GET',
    params: {},
    data: null,
    access: { ident: { id: 'johnf' } }
  }

  const ret = await resources.authenticators.jwt.authenticate(options, request)

  t.is(ret.status, 'refused')
  t.is(logger.error.callCount, 1)
})
