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
    LOG_LEVEL: nativeEnum(LogLevel).default(LogLevel.INFO)
});

export default envSchema.parse(process.env);