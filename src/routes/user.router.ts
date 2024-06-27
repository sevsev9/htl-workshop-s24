import express from "express";

import { createUserHandler } from "../controller/user.controller";

// @path /user
const router = express.Router();

router.get('/', (request, response) => {
    response.status(200).send("Hello, World!");
});

router.post('/', createUserHandler);

export default router;