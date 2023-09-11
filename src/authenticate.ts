import jwt from 'jsonwebtoken'
import { getProperty } from 'dot-prop'
import ms from 'ms'
import type { Action } from 'integreat'
import type { JwtAuthentication, JwtOptions } from './types.js'

const refusedAuth = (error?: string) => ({
  status: 'refused',
  error,
  token: null,
  expire: null,
})

function createAuthenticationWithSignedJwt(
  payload: Record<string, unknown>,
  key: string,
  algorithm: jwt.Algorithm,
  audience: string,
  expiresIn?: string,
  authKey?: string,
) {
  const expire = expiresIn ? Date.now() + ms(expiresIn) - 1000 : null // Set expire to 1 second before actual expiration, to avoid being off by some milliseconds
  const options =
    typeof expiresIn === 'string'
      ? { algorithm, audience, expiresIn }
      : { algorithm, audience }

  try {
    const token = jwt.sign(payload, key, options)
    return { status: 'granted', token, expire, authKey }
  } catch (err) {
    return refusedAuth(`Auth refused. ${err}`)
  }
}

/**
 * Authenticate and return authentication object if authentication was
 * successful.
 */
export default async function authenticate(
  options: JwtOptions | null,
  action: Action | null,
): Promise<JwtAuthentication> {
  if (!action) {
    return refusedAuth('Auth refused due to missing action')
  }

  const {
    key,
    audience,
    algorithm = 'HS256',
    subPath = 'meta.ident.id',
    expiresIn,
    payload: optionsPayload = {},
  } = options || {}

  const sub = getProperty(action, subPath)
  const payload = { ...optionsPayload, sub }
  if (!payload.sub) {
    return refusedAuth('Auth refused due to missing subject')
  } else if (!key || !audience) {
    return refusedAuth('Auth refused due to missing key or audience')
  }

  return createAuthenticationWithSignedJwt(
    payload,
    key,
    algorithm,
    audience,
    expiresIn,
    sub,
  )
}
