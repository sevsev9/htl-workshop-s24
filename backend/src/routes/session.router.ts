import express from "express";
import { validate } from "../middleware/validation";
import { createSessionSchema, refreshAccessTokenSchema } from "../schema/session.schema";
import { loginHandler, logoutHandler, refreshAccessTokenHandler } from "../controller/session.controller";
import authRequiredMiddleware from "../middleware/authRequired";

const router = express.Router();

// login
router.post('/login', validate(createSessionSchema), loginHandler);

// refresh
router.post('/refresh', validate(refreshAccessTokenSchema), refreshAccessTokenHandler);

// logout
router.delete('/logout', authRequiredMiddleware, logoutHandler);

export default router;