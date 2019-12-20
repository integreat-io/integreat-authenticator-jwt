import jwt, { Logger } from './authenticator'

export = Object.assign(
  (logger: Logger = console) => ({
    authenticators: {
      jwt: jwt(logger)
    }
  }),
  {
    default: (logger: Logger = console) => ({
      authenticators: {
        jwt: jwt(logger)
      }
    })
  }
)
