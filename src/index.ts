import { getProperty } from 'dot-prop'
import authenticate from './authenticate.js'
import isAuthenticated from './isAuthenticated.js'
import validate from './validate.js'
import type { Authenticator, Action } from 'integreat'
import type { JwtAuthentication, JwtOptions } from './types.js'

const shouldReturnToken = (
  authentication: JwtAuthentication | null,
): authentication is JwtAuthentication =>
  authentication?.status === 'granted' && !!authentication.token

export function extractAuthKey(
  options: JwtOptions | null,
  action: Action | null,
) {
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
    action,
  ): Promise<JwtAuthentication> {
    return authenticate(options, action)
  },

  /**
   * Check whether this authentication is valid and not expired.
   * For the jwt auth, a valid authentication has `status: 'granted'`, a
   * `token`, no `expire` or an `expire` timestamp in the future, and an
   * `authKey` matching the auth key of the given action.
   */
  isAuthenticated(authentication, options, action) {
    return isAuthenticated(authentication, options, action)
  },

  /**
   * Validate authentication object.
   *
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
  async validate(authentication, options, action) {
    return validate(authentication, options, action)
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
