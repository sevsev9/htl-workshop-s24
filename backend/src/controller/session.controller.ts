import { NextFunction, Request, Response } from "express";

import logger from "../util/logger.util";

import {
  CreateSessionInput,
  RefreshAccessTokenInput,
} from "../schema/session.schema";

import {
  invalidateAllSessionsForUser,
  reIssueAccessToken,
  issueTokens,
} from "../service/session.service";

import { ApplicationError } from "../types/errors";
import { CustomSchemaExpressHandler } from "../types/handler.types";
import { validateUserCredentials } from "../service/user.service";

/**
 * Login Handler
 */
export const loginHandler: CustomSchemaExpressHandler<
  CreateSessionInput
> = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await validateUserCredentials(email, password);

    const invalidated = await invalidateAllSessionsForUser(user.id);

    logger.debug(`Invalidated ${invalidated} sessions for user ${user.id}`);

    const { accessToken, refreshToken } = await issueTokens(
      user,
      req.get("user-agent") || ""
    );

    return res.json({ accessToken, refreshToken });
  } catch (err) {
    if (err instanceof ApplicationError) {
      const error = err as ApplicationError;

      return res.status(error.getHttpCode()).json({ message: error.message });
    }

    logger.error(
      `{Session Controller | Login Handler} - Error logging in user: ${err}`
    );

    return res.status(500).json({ message: "Internal Server Error" });
  }
};

export const refreshAccessTokenHandler: CustomSchemaExpressHandler<
  RefreshAccessTokenInput
> = async (req, res) => {
  try {
    const refreshToken = req.body.refreshToken;

    const jwt = await reIssueAccessToken(refreshToken);

    return res.status(200).json({
      accessToken: jwt,
    });
  } catch (err) {
    if (err instanceof ApplicationError) {
      const error = err as ApplicationError;

      return res.status(error.getHttpCode()).json({ message: error.message });
    }

    logger.error(
      `{Session Controller | Login Handler} - Error logging in user: ${err}`
    );

    return res.status(500).json({ message: "Internal Server Error" });
  }
};

/**
 * Logout Handler
 */
export const logoutHandler = async (req: Request, res: Response, next: NextFunction) => {
  const user = res.locals.user;

  try {
    const invalidated = await invalidateAllSessionsForUser(user.id);

    logger.debug(`Invalidated ${invalidated} sessions for user ${user.id}`);

    return res.status(200).json({
      message: "Successfully logged out.",
    });
  } catch (err) {
    if (err instanceof ApplicationError) {
      logger.warn("{Session Controller | Logout Handler} - Error logging out user: ", err.message);
    }
    
    next(err);
  }
}