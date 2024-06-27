import express from "express";

// @path /user
const router = express.Router();

router.get('/', (request, response) => {
    response.status(200).send("Hello, World!");
});

export default router;