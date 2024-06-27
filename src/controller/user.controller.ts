import type { Request, Response } from "express";
import { pick } from "lodash";

import { createUserSchema } from "../schema/user.schema";
import { createUser } from "../service/user.service";


export async function createUserHandler(
    req: Request,
    res: Response
) {
    const validated = createUserSchema.safeParse(req.body);

    console.log(validated);

    if (validated.success) {
        try {
            const user = await createUser(validated.data);

            return res.status(200).json(
                pick(user, "username", "email", "_id")
            );
        } catch(e) {
            console.log(e);
            return res.status(400).send(e);
        }
    } else {
        res.status(400).json({
            error: "Malformed request body"
        })
    }
}