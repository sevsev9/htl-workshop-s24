import express from "express";

import { createUserHandler, getUserHandler } from "../controller/user.controller";
import { validate } from "../middleware/validation";
import { createUserSchema, getUserSchema } from "../schema/user.schema";
import authRequiredMiddleware from "../middleware/authRequired";

// @path /user
const router = express.Router();

router.get('/', authRequiredMiddleware, getUserHandler);

router.post('/', validate(createUserSchema), createUserHandler);

export default router;