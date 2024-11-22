import logger from "../lib/logger";
import { AppError } from "./AppError";
import { generalErrorCodes } from "./errorCodes";
import { Request } from "express";

const errorLogger = (error: any, req: Request) => {
  console.log("error", error);
  if (error instanceof AppError) {
    const stack = error.errorLogLevel === "error" ? { stack: error.stack } : {};
    logger[error.errorLogLevel](`${error.message}`, {
      where: error.where ? error.where : "error",
      endpoint: req.path,
      errorCode: error.code,
      httpMethod: req.method,
      ipAddress: req.forwardedForIp,
      requestId: req.requestId,
      service: req.service,
      severity: "major",
      statusCode: error.status,
      userAgent: req.forwardedUserAgent,
      userIdentifier: req.user.sub,
      neededActions: error.neededActions,
      ...stack,
    });
  } else {
    logger["error"](`Error: ${error.message}`, {
      where: "error",
      endpoint: req.path,
      errorCode: generalErrorCodes.INTERNAL_ERROR,
      httpMethod: req.method,
      ipAddress: req.forwardedForIp,
      requestId: req.requestId,
      service: req.service,
      severity: "critical",
      statusCode: 500,
      userAgent: req.forwardedUserAgent,
      userIdentifier: req?.user?.sub || "",
      neededActions: ["Check error Stack for more information"],
      stack: error.stack,
    });
  }
};

export default errorLogger;
