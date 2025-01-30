import { Request, Response, NextFunction } from "express";
import logger from "../util/logger.util";
import { verifyJwt } from "../util/jwt.util";

export default function authRequiredMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.header("Authorization");

  const token = authHeader?.split(" ")[1];

  if (!token) {
    logger.debug("No token provided");

    return next();
  }

  const { valid, expired, decoded, error } = verifyJwt(token);

  if (decoded) {
    res.locals.user = decoded;

    if (!expired) {
      logger.debug(
        `{Deserialize User} - User ${decoded.id} deserialized from JWT.`
      );

      return next();
    } else {
        logger.debug(
            `{Deserialize User} - User ${decoded.id} jwt expired.`
        );

        return res.status(401).json({ message: "JWT Expired.", expired: true });
    }
  }

  return res.status(401).json({ message: "Unauthorized", error });
}
