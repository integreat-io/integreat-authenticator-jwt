import test from 'ava'

import resources = require('..')

test('should have resources', t => {
  t.truthy(resources)
  t.truthy(resources.authenticators)
  t.truthy(resources.authenticators.jwt)
})
