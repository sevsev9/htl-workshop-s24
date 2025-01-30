import bcrypt from "bcrypt";
import { User, UserModel } from "../model/user.model";
import { ApplicationError, ErrorCode } from "../types/errors";
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

/**
 * Check if the user exists in the database and the password matches
 * @param email User's email
 * @param password User's password
 * 
 * @returns the user if the email is registered and the provided password matches
 * 
 * @throws If the user is not found
 * @throws If the user has no password stored
 * @throws If the user has an invalid password
 */
export async function validateUserCredentials(email: string, password: string) {
    logger.debug(`{Session Service | Validate User Credentials} - Validating user ${email}`);

    const user = await UserModel.findOne({ email }, { password: true });

    if (!user) {
        logger.warn(`{Session Service | Validate User Credentials} - User ${email} not found`);
        throw new ApplicationError('User not found', ErrorCode.USER_NOT_FOUND);
    }

    logger.debug(`{Session Service | Validate User Credentials} - User ${email} found`);

    if (!user.password) {
        logger.warn(`{Session Service | Validate User Credentials} - User ${email} has no password`);
        throw new ApplicationError('Invalid password', ErrorCode.INVALID_PASSWORD);
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
        logger.warn(`{Session Service | Validate User Credentials} - User ${email} has invalid password`);
        throw new ApplicationError('Invalid password', ErrorCode.INVALID_PASSWORD);
    }

    return user;
}