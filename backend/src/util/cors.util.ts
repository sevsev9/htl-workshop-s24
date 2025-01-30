import cors from "cors";
import env from "./env.util";

export default cors({
    credentials: true,
    origin: [
        `http://localhost:${env.PORT}`, // backend
        "http://localhost:3000",        // frontend
    ]
});