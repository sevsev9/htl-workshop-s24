// controller/session.controller.ts
import { Request, Response } from "express";
import { Error as MongooseError } from "mongoose";
import type { MongoServerError } from "mongodb";
import { pick } from "lodash";

import logger from "../util/logger.util";

import { LoginUserInput, RegisterUserInput, RefreshAccessTokenInput } from "../schema/session.schema";
import type {  } from "../schema/session.schema";

import { signJwt } from "../util/jwt.util";

import { createSession, invalidateAllSessionsForUser, reIssueAccessToken } from "../service/session.service";
import { createUser, validateUserCredentials } from "../service/user.service";

import { UserJwtPayload } from "../types/jwt.types";
import { ApplicationError, ErrorCode } from "../types/errors";
import { CustomSchemaExpressHandler } from "../types/handler.types";