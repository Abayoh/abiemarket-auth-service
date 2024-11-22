import { Request, Response, NextFunction } from "express";
import { authErrorCodes } from "../error/errorCodes";
import { decodeUserClaimsFromBase64String } from "../lib/auth";
import { AppError } from "../error/AppError";

const auth = async (req: Request, _: Response, next: NextFunction) => {
  const user = req.headers["x-user"] as string;

  try {
    const userClaims = decodeUserClaimsFromBase64String(user);
    req.user = userClaims;
    next();
  } catch (e) {
    const err = e as Error;

    return next(
      new AppError(authErrorCodes.AUTH_UNAUTHORIZE, undefined, {
        logLevel: "error",
        errorLogSeverity: "security",
        where: "aut",
        additionalInfo: `User Claims Invalid`,
      })
    );
  }
};

export default auth;
