import type { Request, Response } from "express";

import { createUser, getUser } from "../service/user.service";
import { CreateUserInput } from "../schema/user.schema";
import logger from "../util/logger.util";
import { ApplicationError, ErrorCode } from "../types/errors";


export async function createUserHandler(
    req: Request<{}, {}, CreateUserInput["body"]>,
    res: Response
) {    
    try {
        const user = await createUser(req.body);

        return res.status(200).json(user);
    } catch (e) {
        logger.error(e);
        return res.status(400).send(e);
    }
}

export async function getUserHandler(
    req: Request,
    res: Response
) {
    try {
        const id = res.locals.user.id;

        const user = await getUser(id);

        return res.status(200).json(user);
    } catch (e) {
        return res.status(404).json({
            message: "User not found",
            error: e
        });
    }
}