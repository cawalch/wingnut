import {
  Express,
  RequestHandler,
  Request,
  Response,
  NextFunction,
  Router,
} from "express";
import {
  AjvLike,
  AjvLikeSchemaObject,
  AjvLikeValidateFunction,
} from "../types/common";
import {
  AppObject,
  MediaSchemaItem,
  NamedHandler,
  ParamIn,
  ParamSchema,
  Parameter,
  PathItem,
  PathObject,
  PathOperation,
  ScopeHandler,
  ScopeObject,
  inMap,
} from "../types/open-api-3";
import { ValidationError } from "./errors";

export type AppRoute = { paths: PathItem[]; router: Router };

type ValidateByParam = Record<ParamIn, AjvLikeValidateFunction | undefined>;

export interface Security<S = string> {
  name: string;
  before?: RequestHandler;
  handler: RequestHandler;
  scopes: NamedHandler<S>;
  responses?: MediaSchemaItem;
}

export const app = (a: AppObject): AppObject => a;

export const groupByParamIn = (params: Parameter[]) =>
  params.reduce(
    (group, p) => {
      const m = inMap[p.in];
      if (!group[m]) {
        group[m] = [];
      }
      group[m].push(p);
      return group;
    },
    {} as { [key in string]: Parameter[] },
  );

export const validateParams = (
  p: (Partial<Parameter> & { name: string })[],
): AjvLikeSchemaObject =>
  p.reduce<AjvLikeSchemaObject>(
    (acc, s) => {
      acc.properties[s.name] = { ...s.schema };
      if (s.required === true) {
        acc.required.push(s.name);
      }
      return acc;
    },
    {
      type: "object",
      properties: {},
      required: [],
    } as ParamSchema,
  );

export const validateBuilder =
  (v: AjvLike) =>
  (
    s: Parameter[],
  ): {
    handlers: RequestHandler[];
    schema: { [p: string]: AjvLikeSchemaObject };
  } => {
    const pIns = groupByParamIn(s);
    const ret: { [p: string]: AjvLikeSchemaObject } = {};
    const handlers: RequestHandler[] = [];
    const validators: ValidateByParam = {
      path: undefined,
      query: undefined,
      body: undefined,
    };

    for (const k of Object.keys(pIns)) {
      const schema = validateParams(pIns[k]);
      const validator = v.compile(schema);
      validators[k as ParamIn] = validator;
      ret[k] = schema;
      handlers.push(validateHandler(validator, k as ParamIn));
    }
    return { handlers, schema: ret };
  };

export const validateHandler =
  (valid: AjvLikeValidateFunction, whereIn: ParamIn) =>
  (req: Request, _res: Response, next: NextFunction) => {
    if (!valid(req[whereIn])) {
      throw new ValidationError("WingnutValidationError", valid.errors);
    }
    next();
  };

export const wingnut = (ajv: AjvLike, appRtr: Router) => {
  const validate = validateBuilder(ajv);

  const mapRouter = (
    urtr: Router,
    {
      pathOp,
      path,
      method,
    }: { pathOp: PathOperation; path: string; method: string },
  ) => {
    let wrapper: (cb: RequestHandler) => RequestHandler = (cb) => cb;
    if (pathOp.wrapper) {
      wrapper = pathOp.wrapper;
    }

    const middle: RequestHandler[] = [];

    // security handler
    if (pathOp.scope) {
      for (const s of pathOp.scope) {
        for (const m of s.middleware) {
          middle.push(wrapper(m));
        }
      }
    }

    if (pathOp.requestBody?.content !== undefined) {
      const content = pathOp.requestBody.content["application/json"];
      if (content) {
        const handler = validateHandler(ajv.compile(content.schema), "body");
        middle.push(wrapper(handler));
      }
    }

    if (pathOp.parameters) {
      const { handlers } = validate(pathOp.parameters);
      for (const h of handlers) {
        middle.push(wrapper(h));
      }
    }

    for (const m of pathOp.middleware) {
      middle.push(wrapper(m));
    }
    urtr[method](path, ...middle);
  };

  const route = (rtr: Router, ...pitems: PathItem[]): AppRoute => ({
    paths: pitems,
    router: pitems.reduce((urtr, pitem) => {
      Object.keys(pitem).forEach((path: string) => {
        Object.keys(pitem[path]).forEach((method: keyof PathObject) =>
          mapRouter(urtr, {
            pathOp: pitem[path][method],
            path,
            method,
          }),
        );
      });
      return urtr;
    }, rtr),
  });

  const controller =
    (ctrl: { prefix: string; route: typeof route }) =>
    (app: Express): PathItem[] => {
      const paths = ctrl.route(appRtr);
      app.use(ctrl.prefix, paths.router);
      if (!Array.isArray(paths.paths)) {
        throw new Error('WingnutError: "paths" must be an array');
      }
      paths.paths.forEach((p) => {
        Object.keys(p).forEach((k) => {
          const pathKey = `${ctrl.prefix}${k}`
            .replace(/\(.*?\)/g, "")
            .replace(/:(\w+)/g, "{$1}");
          p[pathKey] = p[k];
          delete p[k];
        });
      });
      return paths.paths;
    };

  const paths = (
    app: Express,
    ...ctrls: ReturnType<typeof controller>[]
  ): PathItem => {
    const paths = ctrls.reduce(
      (acc, c) => {
        const paths = c(app);
        paths.forEach((p) => {
          const [path] = Object.keys(p);
          const [method] = Object.keys(p[path]);
          const full = `${method} ${path}`;
          if (acc.track.has(full)) {
            console.warn(`WingnutWarning: ${full} already exists`);
          } else {
            acc.track.add(full);
          }
          Object.assign(acc.out, p);
        });
        return acc;
      },
      { out: {}, track: new Set<string>() },
    );
    return paths.out;
  };

  return {
    validate,
    route,
    paths,
    controller,
  };
};

export const path = (path: string, ...po: PathObject[]): PathItem => ({
  [path]: po.reduce((acc, p) => ({ ...acc, ...p }), {}),
});

export const asyncMethod =
  (m: string, wrapper: (cb: AsyncRequestHandler) => RequestHandler) =>
  (pop: PathOperation): PathObject => ({
    [m]: { wrapper, ...pop },
  });

type AsyncRequestHandler = (
  req: Request,
  res: Response,
  next: NextFunction,
) => Promise<void>;

export const asyncWrapper =
  (cb: AsyncRequestHandler) =>
  async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      await cb(req, res, next);
    } catch (e) {
      next(e);
    }
  };

export const method =
  (m: string) =>
  (pop: PathOperation): PathObject => ({
    [m]: pop,
  });

export const scopeWrapper =
  (cb: RequestHandler, scopes: ScopeHandler[]) =>
  (req: Request, res: Response, next: NextFunction) => {
    if (scopes.some((v) => v(req, res, next))) {
      next();
      return;
    } else {
      cb(req, res, next);
    }
  };

export const scope = <T = string>(
  security: Security<T>,
  ...scopes: (keyof NamedHandler<T>)[]
): ScopeObject => ({
  auth: security.name,
  scopes,
  middleware: [
    ...(security.before ? [security.before] : []),
    scopeWrapper(
      security.handler,
      scopes.map((s) => security.scopes[s]),
    ),
  ],
  responses: security.responses,
});

export const authPathOp =
  (scope: ScopeObject) =>
  (pop: PathObject): PathObject => {
    const [m] = Object.keys(pop);
    const ret: PathOperation = pop[m as keyof PathObject];

    ret.security = [{ [scope.auth]: scope.scopes }];
    ret.scope = [scope];
    ret.responses = { ...ret.responses, ...scope.responses };
    return { [m]: ret };
  };

export const param =
  (pin: ParamIn) =>
  (param: Omit<Parameter, "in">): Parameter => ({
    in: pin,
    ...param,
  });

export const integer = (sch: Partial<ParamSchema>): ParamSchema => ({
  type: "integer",
  ...sch,
});

export const queryParam = param("query");
export const pathParam = param("path");
export const getMethod = method("get");
export const postMethod = method("post");
export const putMethod = method("put");
export const deleteMethod = method("delete");
export const asyncGetMethod = asyncMethod("get", asyncWrapper);

export const asyncPostMethod = asyncMethod("post", asyncWrapper);
export const asyncPutMethod = asyncMethod("put", asyncWrapper);
export const asyncDeleteMethod = asyncMethod("delete", asyncWrapper);

type WnNumberType = "integer" | "int32" | "int8" | "number";

type WnTDataDef<S, D extends Record<string, unknown>> = S extends {
  type: WnNumberType;
}
  ? number
  : S extends { type: "boolean" }
  ? boolean
  : S extends { type: "timestamp" }
  ? string | Date
  : S extends { type: "array"; items: { type: string } }
  ? WnTDataDef<S["items"], D>[]
  : S extends { type: "string"; enum: readonly (infer E)[] }
  ? string extends E
    ? never
    : [E] extends [string]
    ? E
    : never
  : S extends { elements: infer E }
  ? WnTDataDef<E, D>[]
  : S extends { type: "string" }
  ? string
  : S extends {
      properties: Record<string, unknown>;
      required?: readonly string[];
      additionalProperties?: boolean;
    }
  ? {
      -readonly [K in keyof S["properties"]]?: WnTDataDef<
        S["properties"][K],
        D
      >;
    } & {
      -readonly [K in S["required"][number]]: WnTDataDef<S["properties"][K], D>;
    } & ([S["additionalProperties"]] extends [true]
        ? Record<string, unknown>
        : unknown)
  : S extends { name: string; schema: Record<string, unknown> }
  ? {
      -readonly [K in S["name"]]: WnTDataDef<S["schema"], D>;
    }
  : S extends { description: string; schema: Record<string, unknown> }
  ? WnDataType<S["schema"]>
  : S extends { type: "object" }
  ? Record<string, unknown>
  : null;

export type WnDataType<S> = WnTDataDef<S, Record<string, never>>;

export type WnParamDef = Record<
  string,
  Record<string, Omit<Parameter, "in" | "name">>
>;
