import express from "express";
import userRouter from "./user.router";
import sessionRouter from "./session.router";
 
const router = express.Router();

// localhost:PORT/user/*
router.use("/user", userRouter);

router.use("/auth", sessionRouter);

export default router;