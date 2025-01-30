import { object, coerce, string, enum as enum_z, nativeEnum } from "zod";
import { config } from 'dotenv';

config();

enum LogLevel {
    TRACE = "trace",
    DEBUG = "debug",
    INFO = "info",
    WARN = "warn",
    ERROR = "error"
}

const envSchema = object({
    PORT: coerce.number({
        message: "Port must be a number"
    }).min(0).max(65536),
    MONGO_URL: string({
        message: "MongoDB URL is required!"
    }),
    LOG_LEVEL: nativeEnum(LogLevel).default(LogLevel.INFO),
    SALT_WORK_FACTOR: coerce
        .number({
            message: "Salt work factor must be a number"
        })
        .min(4)
        .max(31),

    ACCESS_TOKEN_TTL: coerce
        .number({
            message: "ACCESS_TOKEN_TTL must be a number"
        })
        .min(60)
        .default(900),
    
    REFRESH_TOKEN_TTL: coerce
        .number({
            message: "REFRESH_TOKEN_TTL must be a number"
        })
        .min(3600)
        .default(604800),

    PRIVATE_KEY_FILE: string({
        message: "Private key file path is required!"
    }),

    PUBLIC_KEY_FILE: string({
        message: "Public key file path is required!"
    }),
});

export default envSchema.parse(process.env);