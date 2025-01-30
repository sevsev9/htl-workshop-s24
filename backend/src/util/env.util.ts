import { object, coerce, string } from "zod";
import { config } from "dotenv";

config();

const envSchema = object({
  PORT: coerce
    .number({
      message: "Port must be a number",
    })
    .min(0)
    .max(65536),
  MONGO_URL: string({
    message: "MongoDB URL is required!",
  }),
  SALT_WORK_FACTOR: coerce
    .number({
      message: "SALT_WORK_FACTOR must be a number",
    })
    .min(4)
    .max(31),

  // the number of seconds the access token is valid for
  ACCESS_TOKEN_TTL: coerce
    .number({
      message: "ACCESS_TOKEN_TTL must be a number",
    })
    .min(60) // 1m minimum
    .default(900), // 15m default

  // the number of seconds the refresh token is valid for
  REFRESH_TOKEN_TTL: coerce
    .number({
        message: "REFRESH_TOKEN_TTL must be a number",
    })
    .min(3600) // 1h minimum
    .default(604800), // 7d default
  PRIVATE_KEY_FILE: string({
    required_error: "PRIVATE_KEY_FILE is required.",
  }),
  PUBLIC_KEY_FILE: string({
    required_error: "PUBLIC_KEY_FILE is required.",
  }),
  LOG_LEVEL: string()
    .default("info")
    .refine(
      (e) => ["trace", "debug", "info", "warn", "error", "fatal"].includes(e),
      "LOG_LEVEL must be one of trace, debug, info, warn, error, fatal"
    ),
});

export default envSchema.parse(process.env);
