import type { Request, Response } from "express";

import { createUser, getUser } from "../service/user.service";
import { CreateUserInput, GetUserInput } from "../schema/user.schema";


export async function createUserHandler(
    req: Request<{}, {}, CreateUserInput["body"]>,
    res: Response
) {
    try {
        const user = await createUser(req.body);

        return res.status(200).json(user);
    } catch (e) {
        console.log(e);
        return res.status(400).send(e);
    }
}

export async function getUserHandler(
    req: Request<GetUserInput["params"]>,
    res: Response
) {
    try {
        const user = await getUser(req.params.id);

        return res.status(200).json(user);
    } catch (e) {
        return res.status(404).json({
            message: "User not found",
            error: e
        });
    }
}