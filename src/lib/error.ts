import { Request, Response, NextFunction } from "express";
import mongoose, { MongooseError } from "mongoose";
import { responseDefault } from "./constants";
import { authErrorCodesMap, authErrorCodes } from "./errorCodes";
import { toPascalCase } from "../utils";
import logger from "./logger";

const appErrorMap = {
  ...authErrorCodesMap,
};

/**
 * Same as the default `Error`, but it is JSON serializable.
 * @source https://iaincollins.medium.com/error-handling-in-javascript-a6172ccdf9af
 */

export class CustomError extends Error {
  status: number;
  code: string;
  constructor(code: string, message?: string) {
    let statusAndMessage = appErrorMap[code];
    if (!statusAndMessage) {
      statusAndMessage = {
        message: message ? message : "this error code do not exist",
        status: 500,
      };
    }
    super(message ? message : statusAndMessage.message);
    this.code = code;
    this.status = statusAndMessage.status;
    this.name = toPascalCase(code);
    Error.captureStackTrace(this, this.constructor);
  }

  toJSON() {
    return toJSON(this);
  }
}

function toJSON(err: CustomError) {
  let stackTrace = {};
  let cooldownPeriod = {};
  if (process.env.NODE_ENV === "development") {
    stackTrace = {
      stack: err.stack,
    };
  }

  if (err instanceof TooManyVerificationRequestError) {
    cooldownPeriod = { cooldownPeriod: err.cooldownPeriod };
  }
  return {
    ...responseDefault,
    success: false,
    error: {
      name: err.name,
      message: err.message,
      code: err.code,
      status: err.status,
      ...cooldownPeriod,
    },
  };
}

export class TooManyVerificationRequestError extends CustomError {
  cooldownPeriod: Date;
  constructor(code: string, cooldownPeriod: Date) {
    super(code);
    this.cooldownPeriod = cooldownPeriod;
  }
}

export function errorHandler(
  err: any,
  req: Request,
  res: Response,
  __: NextFunction
) {
  ///induced change
  if (err instanceof CustomError) {
    res.status(err.status).json(err.toJSON());
  } else if (err instanceof TooManyVerificationRequestError) {
    logger.security(err.message, {
      statusCode:
        authErrorCodesMap[authErrorCodes.AUTH_TOO_MANY_VERIFICATION_REQUEST]
          .status,
      action: "too_many_verification_request",
      endpoint: req.path,
      httpMethod: req.method,
      userAgent: req.get("User-Agent") || "",
      ipAddress: req.forwardedForIp,
      errorCode: authErrorCodes.AUTH_TOO_MANY_VERIFICATION_REQUEST,
      requestId: req.requestId,
      userIdentifier: req.user ? req.user.sub : "anonymous",
      stack: err.stack,
    });

    res.status(err.status).json(err.toJSON());
  } else if (err instanceof mongoose.Error) {
    if (err instanceof mongoose.Error.ValidationError) {
      logger.debug(err.message, {
        stack: err.stack,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_DB_VALIDATION_ERROR].status,
        action: "mongoose_validation_error",
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.get("User-Agent") || "",
        ipAddress: req.forwardedForIp,
        errorCode: authErrorCodes.AUTH_DB_VALIDATION_ERROR,
        requestId: req.requestId,
        userIdentifier: req.user ? req.user.sub : "anonymous",
      });

      res
        .status(400)
        .json(toJSON(new CustomError(authErrorCodes.AUTH_DB_VALIDATION_ERROR)));
    } else {
      logger.error(err.message, {
        stack: err.stack,
        statusCode: authErrorCodesMap[authErrorCodes.AUTH_DB_ERROR].status,
        action: "mongoose_validation_error",
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.get("User-Agent") || "",
        ipAddress: req.forwardedForIp,
        errorCode: authErrorCodes.AUTH_DB_ERROR,
        requestId: req.requestId,
        userIdentifier: req.user ? req.user.sub : "anonymous",
      });
      res
        .status(500)
        .json(toJSON(new CustomError(authErrorCodes.AUTH_DB_ERROR)));
    }
  } else {
    logger.error(err.message, {
      stack: err.stack,
      statusCode: authErrorCodesMap[authErrorCodes.AUTH_DB_ERROR].status,
      action: "mongoose_validation_error",
      endpoint: req.path,
      httpMethod: req.method,
      userAgent: req.get("User-Agent") || "",
      ipAddress: req.forwardedForIp,
      errorCode: authErrorCodes.AUTH_DB_ERROR,
      requestId: req.requestId,
      userIdentifier: req.user ? req.user.sub : "anonymous",
    });

    res
      .status(500)
      .json(toJSON(new CustomError(authErrorCodes.AUTH_UNKNOWN_ERROR)));
  }
}
