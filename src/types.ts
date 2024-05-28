import type { Algorithm } from 'jsonwebtoken'
import type { Authentication } from 'integreat'

export interface JwtAuthentication extends Authentication {
  token?: string | null
  expire?: number
}

export interface JwtOptions extends Record<string, unknown> {
  audience?: string
  key?: string
  algorithm?: Algorithm
  subPath?: string
  expiresIn?: string
  payload?: Record<string, unknown>
  trustedKeys?: Map<string, string>
}
