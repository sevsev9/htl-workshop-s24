import { NextFunction, Response, Request } from "express";

const requireUser = (req: Request, res: Response, next: NextFunction) => {
  const user = res.locals.user;

  if (!user) {
    return res
      .status(401)
      .json({ message: res.locals.error ?? "Unauthorized" });
  }
  
  return next();
};

export default requireUser;