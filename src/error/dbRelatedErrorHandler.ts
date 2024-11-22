import mongoose from "mongoose";
import { AppError } from "./AppError";
import { mongoDbErrorCode } from "./errorCodes";

export default function handleDbRelatedErrors(
  err: any,
  actionData?: { where?: string; neededActions?: string[] }
) {
  if (err instanceof mongoose.Error.ValidationError) {
    return new AppError(
      mongoDbErrorCode.DB_VALIDATION_ERROR,
      undefined,
      {
        logLevel: "error",
        errorLogSeverity: "major",
        ...actionData,
      },
      err
    );
  } else if (err.code && err.code === 11000) {
    // Duplicate key error
    return new AppError(
      mongoDbErrorCode.DUPLICATE_KEY_ERROR,
      undefined,
      {
        logLevel: "error",
        errorLogSeverity: "major",
        ...actionData,
      },
      err
    );
  } else if (err.message && err.message.includes("ECONNREFUSED")) {
    return new AppError(
      mongoDbErrorCode.DB_CONNECTION_ERROR,
      undefined,
      {
        logLevel: "error",
        errorLogSeverity: "major",
        ...actionData,
      },
      err
    );
  }
  if (err.code && err.code === 5107201) {
    return new AppError(
      mongoDbErrorCode.DB_VALIDATION_ERROR,
      undefined,
      {
        logLevel: "error",
        errorLogSeverity: "major",
        ...actionData,
      },
      err
    );
  } else if (err instanceof AppError) {
    return err;
  } else {
    return new AppError(
      mongoDbErrorCode.DB_ERROR,
      err.message,
      { logLevel: "error", errorLogSeverity: "major", ...actionData },
      err
    );
  }
}
