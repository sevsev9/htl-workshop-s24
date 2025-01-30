import { Types } from "mongoose";
import SessionModel, { SessionDocument } from "../model/session.model";
import { signJwt, verifyJwt } from "../util/jwt.util";
import { getUser } from "./user.service";
import logger from "../util/logger.util";
import env from "../util/env.util";
import { UserDocument } from "../model/user.model";
import { UserJwtPayload } from "../types/jwt.types";


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

