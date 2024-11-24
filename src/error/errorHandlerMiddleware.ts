import { Request, Response, NextFunction } from "express";
import { AppError } from "./AppError";
import { generalErrorCodes, mongoDbErrorCode } from "./errorCodes";
import errorLogger from "./errorLogger";
import { responseDefault } from "../lib/constants";

export function errorHandler(
  err: any,
  req: Request,
  res: Response,
  __: NextFunction
) {
  try {
    errorLogger(err, req);
    if (err instanceof AppError) {
      if (err.code === mongoDbErrorCode.DB_ERROR) {
        res
          .status(err.status)
          .json(new AppError(generalErrorCodes.INTERNAL_ERROR).toJSON());
      } else {
        res.status(err.status).json(err.toJSON());
      }
    } else {
      res
        .status(500)
        .json(new AppError(generalErrorCodes.INTERNAL_ERROR).toJSON());
    }
  } catch (e) {
    console.error("error", e);
    res.status(500).json({
      ...responseDefault,
      success: false,
      error: {
        code: generalErrorCodes.INTERNAL_ERROR,
        message: "Internal Server Error",
        status: 500,
        name: "InternalServerError",
      },
    });
  }
}
