import jwt = require('jsonwebtoken')
import dotProp = require('dot-prop')
import ms = require('ms')
import { Request } from 'integreat'

export interface JwtAuthentication {
  status: string
  token: string | null
  expire: null
}

export interface JwtOptions {
  audience: string
  key: string
  algorithm?: string
  subPath?: string
  expiresIn?: string
}

const shouldReturnToken = (
  authentication: JwtAuthentication | null
): authentication is JwtAuthentication =>
  !!(
    authentication &&
    authentication.status === 'granted' &&
    authentication.token
  )

const refusedAuth = { status: 'refused', token: null, expire: null }

/**
 * The jwt strategy. The jwt is signed on each authentication
 */
export default {
  /**
   * Authenticate and return authentication object if authentication was
   * successful.
   */
  async authenticate(options: JwtOptions, request: Request) {
    const {
      key,
      audience,
      algorithm = 'HS256',
      subPath = 'access.ident.id',
      expiresIn
    } = options

    const payload = {
      sub: dotProp.get(request, subPath)
    }
    if (!payload.sub) {
      return refusedAuth
    }

    const signOptions = expiresIn
      ? { algorithm, audience, expiresIn }
      : { algorithm, audience }
    const expire = expiresIn ? Date.now() + ms(expiresIn) : null
    try {
      const token = jwt.sign(payload, key, signOptions)
      return { status: 'granted', token, expire }
    } catch (err) {
      return refusedAuth
    }
  },

  /**
   * Check whether we've already ran authentication.
   * In the jwt auth, this will alway be false, to trigger authentiation on
   * every request, with a request prop as subject.
   */
  isAuthenticated(_authentication: JwtAuthentication | null) {
    return false
  },

  /**
   * Return an object with the information needed for authenticated requests
   * with this authenticator. The object will include `token` and nothing else.
   */
  asObject(authentication: JwtAuthentication | null) {
    return shouldReturnToken(authentication)
      ? { token: authentication.token }
      : {}
  },

  /**
   * Return a headers object with the headers needed for authenticated requests
   * with this authenticator. There will be only one property - `Authorization`.
   */
  asHttpHeaders(authentication: JwtAuthentication | null) {
    return shouldReturnToken(authentication)
      ? { Authorization: `Bearer ${authentication.token}` }
      : {}
  }
}
