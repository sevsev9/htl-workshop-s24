import { Request, Response } from "express";
import { Error as MongooseError } from "mongoose";
import type { MongoServerError } from "mongodb";
import { pick } from "lodash";

import logger from "../util/logger.util";

import {
  CreateSessionInput,
  RefreshAccessTokenInput,
} from "../schema/session.schema";

import {
  createSession,
  invalidateAllSessionsForUser,
  reIssueAccessToken,
  issueTokens,
} from "../service/session.service";

import { UserJwtPayload } from "../types/jwt.types";
import { ApplicationError, ErrorCode } from "../types/errors";
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


