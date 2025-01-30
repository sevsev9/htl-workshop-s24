import { Types } from "mongoose";
import SessionModel, { SessionDocument } from "../model/session.model";
import { signJwt, verifyJwt } from "../util/jwt.util";
import { getUser } from "./user.service";
import logger from "../util/logger.util";
import env from "../util/env.util";
import { UserDocument } from "../model/user.model";
import { UserJwtPayload } from "../types/jwt.types";
import { ApplicationError, ErrorCode } from "../types/errors";


/**
 * Creates a new session for a given user
 * @param userId The userId the session is for
 * @param userAgent The userAgent the user is requesting a new session from
 * @returns a new session
 */
export async function createSession(userId: string, userAgent: string) {
    const session = await SessionModel.create({ userId, userAgent});7

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
): Promise<{ accessToken: string, refreshToken: string }> {
    const session = await createSession(user.id, userAgent);

    const userInfo = {
        id: user.id,
        email: user.email,
        sessionId: session.id
    };

    const accessToken = signJwt(userInfo as UserJwtPayload, {
        expiresIn: env.ACCESS_TOKEN_TTL
    });

    const refreshToken = signJwt(userInfo as UserJwtPayload, {
        expiresIn: env.REFRESH_TOKEN_TTL
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
        throw new ApplicationError('Invalid session id', ErrorCode.UNAUTHORIZED);
    }
}

/**
 * Reissues an access token if the refresh token and session are valid.
 * 
 * @param refreshToken The refresh token to verify.
 * @returns A new access token or an error message.
 */
export async function reIssueAccessToken(refresToken: string): Promise<string> {
    const { decoded, valid, error } = verifyJwt(refresToken);

    if (!valid || !decoded) {
        logger.warn(`{Session Service | Re-Issue Access Token} - Refresh token verification failed: ${error}`);
        throw new ApplicationError("Invalid refresh token", ErrorCode.UNAUTHORIZED);
    }

    try {
        const session = await SessionModel.findById(decoded.sessionId);

        if (!session || !session.valid) {
            logger.warn(`{Session Service | Re-Issue Access Token} - Session ${decoded.sessionId} invalid or not found`);
            throw new ApplicationError("Invalid Session", ErrorCode.UNAUTHORIZED);
        }

        const user = await getUser(session.userId.toString());

        if (!user) {
            logger.warn(`{Session Service | Re-Issue Access Token} - User ${session.userId} not found`);
            throw new ApplicationError("User not found!", ErrorCode.USER_NOT_FOUND);
        }

        const accessToken = signJwt({
            id: user.id,
            email: user.email,
            sessionId: session.id
        }, { expiresIn: env.ACCESS_TOKEN_TTL });

        return accessToken;
    } catch (err) {
        if (err instanceof ApplicationError) {
            throw err;
        }

        logger.error(`{Session Service | Re-Issue Access Token} - Error: ${err}`);
        throw new ApplicationError("Error re-issuing access token!", ErrorCode.INTERNAL_SERVER_ERROR);
    }
}

export async function invalidateSession(sessionId: string): Promise<void> {
    try {
        await SessionModel.findByIdAndUpdate(sessionId, { valid: false});
        logger.debug(`{Session Service | Invalidate Session} - Session ${sessionId} invalidated`);
    } catch (err) {
        logger.error(`{Session Service | Invalidate Session} - Error: ${err}`);
        throw new ApplicationError('Error invalidating session', ErrorCode.DATABASE_ERROR);
    }
}

export async function invalidateAllSessionsForUser(userId: string): Promise<number> {
    const sessions = await SessionModel.updateMany({userId, valid: true}, { valid: false });

    logger.debug(`{Session Service | Invalidate All Sessions For User} - Invalidated ${sessions.modifiedCount} sessions for user ${userId}`);

    return sessions.modifiedCount;
}