import jwt from 'jsonwebtoken'
import { getProperty } from 'dot-prop'
import ms from 'ms'
import type { Authenticator, Authentication } from 'integreat'

export interface JwtAuthentication extends Authentication {
  token?: string | null
  expire?: number | null
}

export interface JwtOptions extends Record<string, unknown> {
  audience?: string
  key?: string
  algorithm?: jwt.Algorithm
  subPath?: string
  expiresIn?: string
  payload?: Record<string, unknown>
}

const shouldReturnToken = (
  authentication: JwtAuthentication | null
): authentication is JwtAuthentication =>
  authentication?.status === 'granted' && !!authentication.token

const refusedAuth = (error?: string) => ({
  status: 'refused',
  error,
  token: null,
  expire: null,
})

function signAuth(
  payload: Record<string, unknown>,
  key: string,
  algorithm: jwt.Algorithm,
  audience: string,
  expiresIn?: string
) {
  const expire = expiresIn ? Date.now() + ms(expiresIn) : null
  const options =
    typeof expiresIn === 'string'
      ? { algorithm, audience, expiresIn }
      : { algorithm, audience }

  try {
    const token = jwt.sign(payload, key, options)
    return { status: 'granted', token, expire }
  } catch (err) {
    return refusedAuth(`Auth refused. ${err}`)
  }
}

/**
 * The jwt strategy. The jwt is signed on each authentication
 */
const authenticator: Authenticator<JwtAuthentication> = {
  /**
   * Authenticate and return authentication object if authentication was
   * successful.
   */
  async authenticate(
    options: JwtOptions | null,
    action
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

    const payload = { ...optionsPayload, sub: getProperty(action, subPath) }
    if (!payload.sub) {
      return refusedAuth('Auth refused due to missing subject')
    } else if (!key || !audience) {
      return refusedAuth('Auth refused due to missing key or audience')
    }

    return signAuth(payload, key, algorithm, audience, expiresIn)
  },

  /**
   * Check whether we've already ran authentication.
   * In the jwt auth, this will alway be false, to trigger authentiation on
   * every request, with a request prop as subject.
   */
  isAuthenticated(_authentication, _action) {
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
}

export default authenticator
