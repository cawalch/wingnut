import { describe, it, expect } from "vitest"
import { Parameter } from "../types/open-api-3"
import { groupByParamIn, validateParams, validateBuilder, validateHandler } from "../lib/index"
import { AjvLike, AjvLikeValidateFunction } from "../types/common"

describe('groupByParamIn', () => {

  it('should group by a parameter', () => {
    const param: Parameter = {
      in: 'path',
      name: 'id',
      schema: {
        type: 'string',
      },
    }
    const result = groupByParamIn([param])
    expect(result).toStrictEqual({
      params: [param],
    })
  })
  it('should group by multiple params', () => {
    const params: Parameter[] = [
      {
        in: 'path',
        name: 'id',
        schema: {
          type: 'string',
        },
      },
      {
        in: 'query',
        name: 'name',
        schema: {
          type: 'string',
        },
      },
    ]
    const result = groupByParamIn(params)
    expect(result).toEqual({
      params: [params[0]],
      query: [params[1]],
    })
  })
})

describe('validateParams', () => {
  it('should validate params', () => {
    const params: (Partial<Parameter> & { name: string })[] = [{
      in: 'path',
      name: 'id',
      schema: {
        type: 'string',
      }
    }]
    const result = validateParams(params)
    expect(result).toStrictEqual({
      type: 'object',
      properties: {
        id: {
          type: 'string',
        }
      },
      required: [],
    })
  })
  it('should handle required', () => {
    const params: (Partial<Parameter> & { name: string })[] = [{
      in: 'path',
      name: 'id',
      required: true,
      schema: {
        type: 'string',
      }
    }]
    const result = validateParams(params)
    expect(result).toStrictEqual({
      type: 'object',
      properties: {
        id: {
          type: 'string',
        }
      },
      required: ['id'],
    })
  })
})

describe('validateBuilder', () => {
  it('should build a validator', () => {

    const mockAjvLike = {
      compile: () => () => true,
    };

    const validator = validateBuilder(mockAjvLike as unknown as AjvLike);
    const param: Parameter = {
      in: 'path',
      name: 'id',
      schema: {
        type: 'string',
      },
    }
    const result = validator([param])
    expect(result.schema).toEqual({
      params: {
        properties: {
          id: {
            type: 'string',
          }
        },
        required: [],
        type: 'object',
      }
    })
  })
})
