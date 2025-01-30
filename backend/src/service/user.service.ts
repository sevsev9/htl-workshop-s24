import { User, UserModel } from "../model/user.model";
import logger from "../util/logger.util";


export async function createUser(
    user: User
) {
    try {
        const userDocument = await UserModel.create(user);

        logger.info("{User Service | Create User} - Successfully created user with id: " + userDocument._id);

        return userDocument;
    } catch(e) {
        logger.error(e);
        throw e;
    }
}

export async function getUser(
    id: string
) {
    try {
        const user = await UserModel.findById(id);

        if (!user) {
            throw new Error(`Could not find user with ${id}`);
        }

        return user;
    } catch(e) {
        logger.error(`{User Service | Get User} - Error getting user: ${e}`);
        throw e;
    }
}