import test from 'ava'

import resourcesFn from '..'

const resources = resourcesFn()

test('should have resources', t => {
  t.truthy(resources)
  t.truthy(resources.authenticators)
  t.truthy(resources.authenticators.jwt)
})
