import { extractAuthKey } from './index.js'
import type { Action } from 'integreat'
import type { JwtAuthentication, JwtOptions } from './types.js'

/**
 * Check whether this authentication is valid and not expired.
 * For the jwt auth, a valid authentication has `status: 'granted'`, a
 * `token`, no `expire` or an `expire` timestamp in the future, and an
 * `authKey` matching the auth key of the given action.
 */
export default function isAuthenticated(
  authentication: JwtAuthentication | null,
  options: JwtOptions | null,
  action: Action | null,
) {
  if (
    authentication &&
    authentication.status === 'granted' &&
    !!authentication.token &&
    (!authentication.expire || authentication.expire >= Date.now())
  ) {
    const authKey = extractAuthKey(options, action)
    return authentication.authKey === authKey
  }
  return false
}
