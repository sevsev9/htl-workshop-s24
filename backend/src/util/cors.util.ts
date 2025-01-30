import cors from "cors";

export default cors({
    credentials: true,
    origin: [`http://localhost:${process.env.PORT}`, "http://localhost:3000"],
});
