import { object, coerce } from "zod";
import { config } from 'dotenv';

config();

const envSchema = object({
    PORT: coerce.number({
        message: "Port must be a number"
    }).min(0).max(65536)
});

export default envSchema.parse(process.env);