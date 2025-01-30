export type UserJwtPayload = {
    id: string;
    email: string;
    sessionId: string;
    exp?: number; // expiration unix timestamp
    iat?: number; // issued at
}

export type VerifyJwtResult = {
    valid: boolean;
    expired?: boolean;
    decoded?: UserJwtPayload;
    error?: string | null;
}