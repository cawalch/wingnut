/* eslint-disable @typescript-eslint/no-explicit-any */
import { RequestHandler } from 'express'

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

export type AjvLikeSchemaObject = any
