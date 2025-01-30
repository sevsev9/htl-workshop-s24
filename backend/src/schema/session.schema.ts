import { object, string, TypeOf } from "zod";

// login
export const createSessionSchema = object({
    body: object({
        email: string({ message: "email is required" }).email("please give me a valid email"),
        password: string({ message: "password required" }).min(8).max(255)
    })
});

// refresh token schema
export const refreshAccessTokenSchema = object({
    body: object({
        refreshToken: string({ message: "refreshToken is required" }).min(1)
    })
});

export type CreateSessionInput = TypeOf<typeof createSessionSchema>;
export type RefreshAccessTokenInput = TypeOf<typeof refreshAccessTokenSchema>;