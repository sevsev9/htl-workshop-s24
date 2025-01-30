import jwt from 'jsonwebtoken';
import { UserJwtPayload, VerifyJwtResult } from '../types/jwt.types';

export function signJwt(object: UserJwtPayload, options?: jwt.SignOptions): string {
    return jwt.sign(object, process.env.PRIVATE_KEY!, {
        algorithm: 'RS256',
        ...(options || {})
    });
}

/**
 * Verifies a JWT using the public key.
 * @param {string} token - The JWT to verify.
 * @returns {object} An object containing the verification result.
 * @property {boolean} valid - Indicates if the JWT is valid.
 * @property {boolean} expired - Indicates if the JWT is expired.
 * @property {object|null} decoded - The decoded JWT payload, or null if the JWT is not valid.
 * @property {string|null} error - The error message, or null if the JWT is valid.
 */
export function verifyJwt(token: string): VerifyJwtResult {
    try {
        const decoded = jwt.verify(token, process.env.PUBLIC_KEY!) as UserJwtPayload;

        return {
            valid: true,
            expired: false,
            decoded,
            error: null
        }
    } catch (e: any) {
        let error = 'Invalid token';
        let decoded;

        if (e instanceof jwt.TokenExpiredError) {
            error = 'Token expired';

            // try to decode the token to get the user information
            decoded = jwt.decode(token) as UserJwtPayload;
        } else if (e instanceof jwt.NotBeforeError) {
            error = 'Token not active';
        } else if (e instanceof jwt.JsonWebTokenError) {
            error = e.message;
        }

        return {
            valid: false,
            expired: e instanceof jwt.TokenExpiredError,
            decoded,
            error
        };
    }
}