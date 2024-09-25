import { Schema, ValidationResult } from "joi";
import { Request, Response, NextFunction } from "express";
import { CustomError } from "../lib/error";
import { authErrorCodes, authErrorCodesMap } from "../lib/errorCodes";
import logger from "../lib/logger";

/**
 * Interface for validation parameters.
 */
interface ValidationParams {
  /**
   * Schema to validate request data against.
   */
  schema: Schema;
}

/**
 * Middleware function to validate data against a schema.
 *
 * @param params - Validation parameters.
 * @returns Middleware function to validate data.
 */
const validateSchema =
  ({ schema }: ValidationParams) =>
  (req: Request, _: Response, next: NextFunction) => {
    let data = req.body;
    let user = req.user;

    // Validate the data against the provided schema
    const { error }: ValidationResult = schema.validate(data);
    const valid: boolean = !error;

    if (!valid) {
      // If validation fails, generate a BadRequest error with the error details
      const { details = [] } = error || {};
      const message: string = details.map((i) => i.message).join(",");
      logger.debug(message, {
        action: "validateSchema",
        requestId: req.requestId,
        userIdentifier: `${user.sub}`,
        ipAddress: req.ip || "",
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.get("User-Agent") || "",
        errorCode: authErrorCodes.AUTH_REQ_VALIDATION_ERROR,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_INVALID_CREDENTIALS].status,
      });

      return next(
        new CustomError(authErrorCodes.AUTH_REQ_VALIDATION_ERROR, message)
      );
    } else {
      // If validation succeeds, proceed to the next middleware
      next();
    }
  };

export default validateSchema;
