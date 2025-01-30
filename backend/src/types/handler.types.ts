import type { NextFunction, Request, Response } from "express";

export type CustomSchemaExpressHandler<
    Schema extends {
        body?: Object;
        params?: Object;
        query?: Object;
    } = {},
> = (
    req: Request<Schema["params"], {}, Schema["body"], Schema["query"]>,
    res: Response<{}>,
    next: NextFunction,
) =>
        | Promise<Response<any, Record<string, any>> | undefined>
        | Response<any, Record<string, any>>
        | undefined;