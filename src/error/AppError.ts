import { toPascalCase } from "../utils";
import { LogLevel, LogSeverity } from "../lib/logger";
import appErrorMap from "./errorCodes";

// const appErrorMap: ErrorCodeToStatusAndMessageMap = {
//   ...generalErrorCodesMap,
//   ...productDetailsErrorCodesMap,
// };

/**
 * Same as the default `Error`, but it is JSON serializable.
 * @source https://iaincollins.medium.com/error-handling-in-javascript-a6172ccdf9af
 */

export class AppError extends Error {
  readonly status: number;
  readonly code: string;
  readonly errorLogSeverity: LogSeverity;
  readonly errorLogLevel: LogLevel;
  readonly where: string | undefined;
  neededActions: string[] | undefined; // This should also be mutable in other parts of the code
  readonly originalError: any;
  readonly additionalInfo: any;
  readonly resMessage: string;

  constructor(
    code: string,
    message?: string,
    logMeta?: {
      errorLogSeverity: LogSeverity;
      logLevel: LogLevel;
      where?: string;
      neededActions?: string[];
      additionalInfo?: any;
    },
    error?: any // Original error if available
  ) {
    // Get the default message and status from the map or use a generic error
    let statusAndMessage = appErrorMap[code] || {
      message: "This error code does not exist",
      status: 500,
    };

    // Set the error message: either from `error`, `message`, or the map's default
    const errorMessage = message || statusAndMessage.message;

    // Call the parent constructor with the error message
    super(error?.message || message || statusAndMessage.message);

    this.code = code;
    this.status = statusAndMessage.status;
    this.name = toPascalCase(code);
    this.errorLogSeverity = logMeta?.errorLogSeverity || "major";
    this.errorLogLevel = logMeta?.logLevel || "warn";
    this.where = logMeta?.where || "error";
    this.neededActions = logMeta?.neededActions || [];
    this.originalError = error;
    this.additionalInfo = logMeta?.additionalInfo;
    this.resMessage = errorMessage;

    // Preserve the original error stack if it exists, otherwise capture new stack trace
    if (error?.stack) {
      this.stack = error.stack;
    } else {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  toJSON() {
    let stackTrace = {};
    if (process.env.NODE_ENV === "development") {
      stackTrace = { stack: this.stack };
    }

    return {
      success: false,
      error: {
        name: this.name,
        message: this.resMessage || "Internal server error",
        code: this.code,
        status: this.status,
        ...stackTrace,
      },
    };
  }
}
