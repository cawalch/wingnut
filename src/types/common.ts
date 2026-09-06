import { RequestHandler } from 'express'
import type { ParamType } from './open-api-3'

export type Route = (path: string, ...handler: RequestHandler[]) => void

export type AjvErrorLikeObject = {
  propertyName?: string
  message?: string
  data?: unknown
}

export interface AjvLikeValidateFunction<T = unknown> {
  (this: AjvLike | any, schema: any): schema is T
  errors?: null | AjvErrorLikeObject[]
}

export type AjvLike = {
  compile: (schema: Record<string, unknown>) => AjvLikeValidateFunction
}

export interface AjvLikeSchemaObject extends Record<string, unknown> {
  $id?: string
  /** 3.0: a single type. 3.1 / 2020-12: an array of types, e.g. `['string', 'null']`. */
  type?: ParamType | readonly ParamType[]
  properties?: Record<string, unknown>
  required?: readonly string[]
}
