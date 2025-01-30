import { Types } from "mongoose";
import Session, { SessionDocument } from "../model/session.model";
import { signJwt, verifyJwt } from "../util/jwt.util";
import { getUser } from "./user.service";
import SessionModel from "../model/session.model";
import logger from "../util/logger.util";
import { UserDocument } from "../model/user.model";
import env from "../util/env.util";
import { UserJwtPayload } from "../types/jwt.types";

/**
 * Creates a new session for a given user
 * @param userId The userId the session is for
 * @param userAgent The userAgent the user is requesting a new session from
 * @returns a new session
 */
export async function createSession(userId: string, userAgent: string) {
  const session = await Session.create({ userId: userId, userAgent });
  return session;
}

/**
 * Creates a pair of access and refresh tokens for a given user.
 *
 * @param user The user to create the tokens for.
 *
 * @returns An object containing the access and refresh tokens.
 */
export async function issueTokens(
    user: UserDocument,
    userAgent: string
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const session = await createSession(user._id.toString(), userAgent);
  
    const userInfo = {
      _id: user._id.toString(),
      email: user.email,
      sessionId: session._id,
    };
  
    // create new access JWT
    const accessToken = signJwt(userInfo as UserJwtPayload, {
      expiresIn: env.ACCESS_TOKEN_TTL,
    });
  
    // create new refresh JWT
    const refreshToken = signJwt(userInfo as UserJwtPayload, {
      expiresIn: env.REFRESH_TOKEN_TTL,
    });
  
    return { accessToken, refreshToken };
  }
  

/**
 * Validates a session for a given session id.
 *
 * @param id the session id
 * @returns true if the session is valid
 */
export async function validateSessionWithId(id: Types.ObjectId) {
  try {
    const session = await SessionModel.findById(id);
    return session !== null && session.valid;
  } catch (e) {
    throw new Error(`Failed to validate session: ${(e as Error).message}`);
  }
}

/**
 * Reissues an access token if the refresh token and session are valid.
 *
 * @param refreshToken The refresh token to verify.
 * @returns A new access token or an error message.
 */
export async function reIssueAccessToken(
  refreshToken: string
): Promise<{ error: string; jwt: string | false }> {
  const { decoded, valid, error } = verifyJwt(refreshToken);

  if (!valid || !decoded) {
    logger.warn(
      `{Session Service | Re-Issue Access Token} - Refresh token verification failed: ${error}`
    );
    return { jwt: false, error: "Invalid refresh token" };
  }

  try {
    const session = await Session.findById(decoded.sessionId);
    if (!session || !session.valid) {
      logger.warn(
        `{Session Service | Re-Issue Access Token} - Session ${decoded.sessionId} invalid or not found`
      );
      return { jwt: false, error: "Invalid session" };
    }

    const user = await getUser(session.userId);
    if (!user) {
      logger.warn(
        `{Session Service | Re-Issue Access Token} - User ${session.userId} not found for session ${decoded.sessionId}`
      );
      return { jwt: false, error: "User not found" };
    }

    const accessToken = signJwt(
      {
        _id: user._id.toString(),
        email: user.email,
        sessionId: session._id,
      },
      { expiresIn: env.ACCESS_TOKEN_TTL }
    );

    return { jwt: accessToken, error: "" };
  } catch (err) {
    logger.error(
      `{Session Service | Re-Issue Access Token} - Error in re-issuing access token: ${err}`
    );
    return { jwt: false, error: "Error processing refresh token" };
  }
}

/**
 * Invalidates a session by setting its valid flag to false.
 * @param sessionId The ID of the session to invalidate.
 */
export async function invalidateSession(sessionId: SessionDocument["_id"]): Promise<void> {
    try {
        await SessionModel.findByIdAndUpdate(sessionId, { valid: false });
        logger.info(`{Session Service | Invalidate Session} - Session ${sessionId} invalidated successfully.`);
    } catch (error) {
        logger.error(`{Session Service | Invalidate Session} - Failed to invalidate session ${sessionId}: ${(error as Error).message}`);
        throw new Error(`Failed to invalidate session: ${(error as Error).message}`);
    }
}

/**
 * This function invalidates all sessions for a given user
 * @param userId the ObjectId from the user to invalidate all sessions for
 */
export async function invalidateAllSessionsForUser(userId: UserDocument["_id"]): Promise<number> {
    const sessions = await SessionModel.updateMany({ userId, valid: true }, { valid: false });

    logger.info(`{Session Service | Invalidate All Sessions For User} - Invalidated ${sessions.modifiedCount} session${sessions.modifiedCount > 1 ? 's': ''} for user ${userId}.`);

    return sessions.modifiedCount;
}
