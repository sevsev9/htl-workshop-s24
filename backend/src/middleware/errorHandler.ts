import { Request, Response, NextFunction } from 'express';
import logger from '../util/logger.util';

export function errorHandler(
    err: Error,
    req: Request,
    res: Response,
    next: NextFunction
): void {
    logger.error(`An unexpected error occurred: ${err.name} => ${err.message} | ${err.stack}`);

    res.status(res.statusCode !== 200 ? res.statusCode : 500);

    res.json({
        message: err.message
    });
}