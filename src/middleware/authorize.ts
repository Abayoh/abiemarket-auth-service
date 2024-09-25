import { Request, Response, NextFunction } from "express";
import { AccessTokenClaims, verifyJWTToken } from "../lib/auth";
import { AccessToken } from "../lib/types";
import { CustomError } from "../lib/error";
import { authErrorCodes } from "../lib/errorCodes";
import { jwtSecretsLoader } from "../config/configurations";

const auth = async (req: Request, _: Response, next: NextFunction) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "");
    if (!token) throw new CustomError(authErrorCodes.AUTH_UNAUTHORIZE);

    let decodedResult = await verifyJWTToken<AccessToken>(
      {
        secret: jwtSecretsLoader.getConfig().newJwtSecert,
        token,
      },
      jwtSecretsLoader.getConfig().oldJwtSecert
    );

    if (decodedResult.type === "error")
      throw new CustomError(authErrorCodes.AUTH_UNAUTHORIZE);

    if (decodedResult.type === "expired")
      throw new CustomError(
        authErrorCodes.AUTH_TOKEN_EXPIRED,
        "access token expired"
      );

    const { payload } = decodedResult;

    const user: AccessTokenClaims = {
      sub: payload.sub,
      roles: payload.roles,
      name: payload.name,
    };

    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
};

export default auth;
