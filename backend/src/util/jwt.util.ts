import jwt from "jsonwebtoken";
import { UserJwtPayload, VerifyJwtResult } from "../types/jwt.types";

export function signJwt(object: UserJwtPayload, options?: jwt.SignOptions): string {
    return jwt.sign(object, process.env.PRIVATE_KEY!, {
        algorithm: "RS256",
        ...(options || {})
    });
}