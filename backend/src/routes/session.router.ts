import { Request, Response, NextFunction, Router } from "express";
import loggerUtil from "../util/logger.util";
import validate from "../middleware/validateResource";
import { loginUserSchema, refreshAccessTokenSchema, registerUserSchema } from "../schema/auth.schema";
import requireUser from "../middleware/requireUser";
import { loginHandler, logoutHandler, refreshAccessTokenHandler, registerHandler } from "../controller/session.controller";
import loggedInRedirect from "../middleware/loggedInRedirect";

const router = Router();

// log in with email and password
router.post('/login', [loggedInRedirect, validate(loginUserSchema)], loginHandler)

// route for getting a new access token from the refresh token
router.post('/refresh', [validate(refreshAccessTokenSchema)], refreshAccessTokenHandler);

// logout route
router.post('/logout', requireUser, logoutHandler);

export default router;