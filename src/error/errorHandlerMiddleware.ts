import { Request, Response, NextFunction } from "express";
import { AppError } from "./AppError";
import { generalErrorCodes } from "./errorCodes";
import { AxiosError } from "axios";
import errorLogger from "./errorLogger";

export function errorHandler(
  err: any,
  req: Request,
  res: Response,
  __: NextFunction
) {
  errorLogger(err, req);
  if (err instanceof AxiosError) {
    const code =
      err.response?.data?.error?.code || generalErrorCodes.INTERNAL_ERROR;
    const message =
      err.response?.data?.error?.message || "Internal server error";
    const statusAndMessage = {
      status: err.response?.status || 500,
      message: err.response?.data?.error?.message || "Internal server error",
    };
    const appError = new AppError(code, message, {
      errorLogSeverity: "critical",
      logLevel: "error",
      where: "errorHandler",
    });

    res.status(statusAndMessage.status).json(appError.toJSON());
  } else if (err instanceof AppError) {
    res.status(err.status).json(err.toJSON());
  } else {
    res.status(500).json(
      new AppError(generalErrorCodes.INTERNAL_ERROR, "Internal Error", {
        errorLogSeverity: "critical",
        logLevel: "error",
        where: "errorHandler",
      }).toJSON()
    );
  }
}
