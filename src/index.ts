import jwt = require('jsonwebtoken')
import dotProp = require('dot-prop')
import ms = require('ms')

interface Response {
  status: string | null
}

export interface Ident {
  id?: string
  root?: boolean
  withToken?: string
  roles?: string[]
  tokens?: string[]
}

export interface Meta extends Record<string, unknown> {
  ident?: Ident
}

export interface Action {
  type: string
  payload: Record<string, unknown>
  response?: Response
  meta?: Meta
}

export interface JwtAuthentication {
  status: string
  token?: string | null
  expire?: null
}

export interface JwtOptions {
  audience?: string
  key?: string
  algorithm?: jwt.Algorithm
  subPath?: string
  expiresIn?: string
  payload?: Record<string, unknown>
}

export interface Logger {
  info: (...args: string[]) => void
  error: (...args: string[]) => void
}

const shouldReturnToken = (
  authentication: JwtAuthentication | null
): authentication is JwtAuthentication =>
  authentication?.status === 'granted' && !!authentication.token

const refusedAuth = () => ({ status: 'refused', token: null, expire: null })

// authentication: {
//   [asFunction: string]: (
//     authentication: Authentication | null
//   ) => Record<string, unknown>
// }

/**
 * The jwt strategy. The jwt is signed on each authentication
 */
export default (logger?: Logger) => ({
  /**
   * Authenticate and return authentication object if authentication was
   * successful.
   */
  async authenticate(options: JwtOptions | null, action: Action | null) {
    if (!action) {
      if (logger) {
        logger.error('Auth refused due to missing action', 'autherror')
      }
      return refusedAuth()
    }

    const {
      key,
      audience,
      algorithm = 'HS256',
      subPath = 'meta.ident.id',
      expiresIn,
      payload: optionsPayload = {},
    } = options || {}

    const payload = {
      ...optionsPayload,
      sub: dotProp.get(action, subPath),
    }
    if (!payload.sub) {
      if (logger) {
        logger.error('Auth refused due to missing subject', 'autherror')
      }
      return refusedAuth()
    } else if (!key || !audience) {
      if (logger) {
        logger.error('Auth refused due to missing key or audience', 'autherror')
      }
      return refusedAuth()
    }

    const signOptions = expiresIn
      ? { algorithm, audience, expiresIn }
      : { algorithm, audience }
    const expire = expiresIn ? Date.now() + ms(expiresIn) : null
    try {
      const token = jwt.sign(payload, key, signOptions)
      return { status: 'granted', token, expire }
    } catch (err) {
      if (logger) {
        logger.error(`Auth refused. Error: ${err}`)
      }
      return refusedAuth()
    }
  },

  /**
   * Check whether we've already ran authentication.
   * In the jwt auth, this will alway be false, to trigger authentiation on
   * every request, with a request prop as subject.
   */
  isAuthenticated(
    _authentication: JwtAuthentication | null,
    _action: Action | null
  ) {
    return false
  },

  authentication: {
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
    },
  },
})
