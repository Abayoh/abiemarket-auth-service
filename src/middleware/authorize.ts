import { Request, Response, NextFunction } from "express";
import { AccessTokenClaims, verifyJWTToken } from "../lib/auth";
import { AccessToken } from "../lib/types";
import { CustomError } from "../lib/error";
import { authErrorCodes } from "../lib/errorCodes";
import logger from "../lib/logger";
import { decodeUserClaimsFromBase64String } from "../lib/auth";

const auth = async (req: Request, _: Response, next: NextFunction) => {
  const user = req.headers["x-user"] as string;

  try {
    const userClaims = decodeUserClaimsFromBase64String(user);
    req.user = userClaims;
  } catch (e) {
    const err = e as Error;
    logger.warn(`${err.message}: ${user}`, {
      action: "invalid_user_claims",
      requestId: req.requestId,
      userIdentifier: `${"anonymous"} `,
      ipAddress: req.forwardedForIp,
      endpoint: req.path,
      httpMethod: req.method,
      userAgent: req.forwardedUserAgent,
      errorCode: "AUTH_INVALID_USER_CLAIMS",
      statusCode: 401,
    });
    return next(new CustomError(authErrorCodes.AUTH_UNAUTHORIZE));
  }
};

export default auth;
