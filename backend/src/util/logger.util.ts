import logger from "pino";
import dayjs from "dayjs";
import env from "./env.util";

export default logger({
    level: env.LOG_LEVEL,
    transport: {
        target: "pino-pretty"
    },
    base: {
        pid: false
    },
    timestamp: () => `,"time":"${dayjs().format()}"`
});