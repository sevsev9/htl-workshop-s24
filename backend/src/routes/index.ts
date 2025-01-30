import express from "express";
import userRouter from "./user.router";
 
const router = express.Router();

// localhost:PORT/user/*
router.use("/user", userRouter);

export default router;