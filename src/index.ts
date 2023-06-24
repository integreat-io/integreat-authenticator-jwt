import jwt from 'jsonwebtoken'
import { getProperty } from 'dot-prop'
import ms from 'ms'
import type { Authenticator, Authentication, Action } from 'integreat'

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
  expiresIn?: string,
  authKey?: string
) {
  const expire = expiresIn ? Date.now() + ms(expiresIn) : null
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

function extractAuthKey(options: JwtOptions | null, action: Action | null) {
  const subPath = options?.subPath ?? 'meta.ident.id'
  const key = getProperty(action, subPath)
  return typeof key === 'string' ? key : undefined
}

/**
 * The jwt strategy. The jwt is signed on each authentication
 */
const authenticator: Authenticator<JwtAuthentication, JwtOptions> = {
  /**
   * Returns a key for separating different authentications. In the jwt auth,
   * the key will be the subject of the jwt, as we will issue a unique key for
   * every subject (user).
   */
  extractAuthKey(options, action) {
    return extractAuthKey(options, action)
  },

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

    const sub = getProperty(action, subPath)
    const payload = { ...optionsPayload, sub }
    if (!payload.sub) {
      return refusedAuth('Auth refused due to missing subject')
    } else if (!key || !audience) {
      return refusedAuth('Auth refused due to missing key or audience')
    }

    return signAuth(payload, key, algorithm, audience, expiresIn, sub)
  },

  /**
   * Check whether this authentication is valid and not expired.
   * For the jwt auth, a valid authentication has `status: 'granted'`, a
   * `token`, no `expire` or an `expire` timestamp in the future, and an
   * `authKey` matching the auth key of the given action.
   */
  isAuthenticated(authentication, options, action) {
    if (
      authentication &&
      authentication.status === 'granted' &&
      !!authentication.token &&
      (!authentication.expire || authentication.expire * 1000 >= Date.now())
    ) {
      const authKey = extractAuthKey(options, action)
      return authentication.authKey === authKey
    }
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
