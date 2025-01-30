export type UserJwtPayload = {
    _id: string;
    email: string;
    sessionId: string;
    exp?: number; // expiration date
    iat?: number; // issued at
}

export type VerifyJwtResult = {
    valid: boolean;
    expired?: boolean;
    decoded?: UserJwtPayload;
    error?: string | null;
}