import jwt from 'jsonwebtoken'
import { isObject } from './utils/is.js'
import { createError } from './utils/error.js'
import type { Action } from 'integreat'
import type { JwtAuthentication, JwtOptions } from './types.js'

const isNonEmptyString = (sub?: string): sub is string =>
  typeof sub === 'string' && sub !== ''
const isVerifiedEmail = (email?: string, verified?: boolean) =>
  typeof email === 'string' && verified === true
const isToken = (token?: string): token is string => typeof token === 'string'

function tokenFromAction(action: Action) {
  const authHeader = action.payload.headers?.authorization
  if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7)
  }
  return undefined
}

const removeHttps = (url?: string) =>
  typeof url === 'string' && url.startsWith('https://') ? url.slice(8) : url

function keyIdFromJwt(token: string) {
  const { header, payload } = jwt.decode(token, { complete: true }) || {}
  if (isObject(payload) && isNonEmptyString(payload.iss)) {
    const { iss, aud } = payload
    const kid = isObject(header) ? header.kid : undefined
    return [removeHttps(iss), aud, kid].filter(Boolean).join('|') || undefined
  } else {
    return undefined
  }
}

function keyFromJwt(token: string, trustedKeys: Map<string, string>) {
  const keyId = keyIdFromJwt(token)
  return keyId ? trustedKeys.get(keyId) : undefined
}

function generateTokens(payload: jwt.JwtPayload) {
  const { iss, sub, email, email_verified } = payload
  const issuer = removeHttps(iss)

  const subToken = isNonEmptyString(sub) ? `${issuer}|${sub}` : undefined
  const emailToken = isVerifiedEmail(email, email_verified)
    ? `${issuer}|${email}`
    : undefined
  return [subToken, emailToken].filter(isToken)
}

/**
 * Will fetch the `authorization` header from the action and verify it as a JWT
 * token. Keys of trusted issuers are provided in the `trustedKeys` Map set in
 * options. When the JWT is verified against the relevant key, an `ok` response
 * will be returned with an ident in `access`.
 *
 * The ident will have one or more `tokens` set to a concatinated string of
 * issuer and subject, separated by a pipe character. If the JWT contains a
 * verified email, the ident will have an extra token with issuer and email. Any
 * `https://` prefix in the issuer will be removed.
 *
 * Note that the `trustedKeys` Map is allowed to be updated at runtime, so that
 * new keys can be added and removed. The authenticator will never cache or
 * prepare the keys, so any changes will be reflected immediately.
 */
export default async function validate(
  _authentication: JwtAuthentication | null,
  options: JwtOptions | null,
  action: Action | null,
) {
  const { trustedKeys = new Map() } = options || {}

  // Fetch token from header given in action
  const token = action && tokenFromAction(action)
  if (!token) {
    return createError('Authentication required', 'noaccess', 'noauth')
  }

  // Fetch the correct public key, given the issuer in the JWT token
  const key = keyFromJwt(token, trustedKeys)
  if (!key) {
    return createError(
      'No access. Unknown issuer or audience',
      'noaccess',
      'invalidauth',
    )
  }

  let payload: string | jwt.JwtPayload | null
  try {
    payload = jwt.verify(token, key)
  } catch (error) {
    payload = null
  }

  if (isObject(payload)) {
    const tokens = generateTokens(payload)
    if (tokens.length > 0) {
      // JWT is valid, return response with ident with generated tokens
      return { status: 'ok', access: { ident: { tokens } } }
    }
  }

  // JWT is not valid, return autherror response
  return createError(
    'Unauthorized. Credentials are not valid',
    'autherror',
    'invalidauth',
  )
}
