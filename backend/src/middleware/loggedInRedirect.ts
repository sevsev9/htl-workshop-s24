import { NextFunction, Request, Response } from "express";
import logger from "../util/logger.util";

export function loggedInRedirect(req: Request, res: Response, next: NextFunction) {
    if (res.locals.user) {
        logger.debug(`Logged in user tried to go to login/signup page | sid:${res.locals.user.sessionId}`);
        return res.redirect('/');
    }

    next();
}

export default loggedInRedirect;