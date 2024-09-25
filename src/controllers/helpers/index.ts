import { Request } from "express";
import Joi from "joi";
import { CustomError } from "../../lib/error";
import { VerificationTokenSchema } from "../../models/verificationTokens";
import {
  ValidationMessages,
  generateVerificationToken,
  sendEmailVerificationCode,
  sendSmsVerificationCode,
  checkVerificationToken,
} from "../../lib/auth";
import { authErrorCodes, authErrorCodesMap } from "../../lib/errorCodes";

import userSchema from "../../models/users/userSchema";
import { fromDate, now } from "../../utils";
import { TooManyVerificationRequestError } from "../../lib/error";
import { authConfigsLoader } from "../../config/configurations";
import logger from "../../lib/logger";
import { log } from "console";

export async function sendVerificationTokenHandler(
  type: "email" | "phone",
  value: string,
  req: Request,
  isPasswordReset = false
) {
  //check if there is user associated with the request type and value
  const user = await userSchema.findOne({ [type]: value });
  const action = isPasswordReset ? "password-reset" : "signup";

  if (user && !isPasswordReset) {
    if (type === "email") {
      logger.security(
        `verification token request failed for email ${value} already exists`,
        {
          action,
          requestId: req.requestId,
          userIdentifier: `${type}:${value}`,
          ipAddress: req.ip || "" || "",
          endpoint: req.path,
          httpMethod: req.method,
          userAgent: req.get("User-Agent") || "" || "",
          errorCode: authErrorCodes.AUTH_INVALID_CREDENTIALS,
          statusCode:
            authErrorCodesMap[authErrorCodes.AUTH_INVALID_CREDENTIALS].status,
        }
      );
      throw new CustomError(authErrorCodes.AUTH_SIGNUP_EMAIL_TAKEN);
    } else {
      logger.security(
        `verification token request failed for phone ${value} already exists`,
        {
          action,
          requestId: req.requestId,
          userIdentifier: `${type}:${value}`,
          errorCode: authErrorCodes.AUTH_INVALID_CREDENTIALS,
          ipAddress: req.ip || "" || "",
          endpoint: req.path,
          httpMethod: req.method,
          userAgent: req.get("User-Agent") || "" || "",
          statusCode:
            authErrorCodesMap[authErrorCodes.AUTH_INVALID_CREDENTIALS].status,
        }
      );
      throw new CustomError(authErrorCodes.AUTH_SIGNUP_PHONE_TAKEN);
    }
  }

  if (!user && isPasswordReset) {
    logger.security(
      `verification token request failed for ${value} user not found on password reset
      `,
      {
        action,
        requestId: req.requestId,
        userIdentifier: `${type}:${value}`,
        ipAddress: req.ip || "",
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.get("User-Agent") || "",
        errorCode: authErrorCodes.AUTH_USER_NOT_FOUND,

        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_USER_NOT_FOUND].status,
      }
    );
    throw new CustomError(authErrorCodes.AUTH_USER_NOT_FOUND);
  }

  let storedVToken = await VerificationTokenSchema.findOne({
    verificationType: { type, value },
  });

  //if the cooldown period has expired delete the token
  if (
    storedVToken &&
    storedVToken.cooldownPeriod &&
    storedVToken.cooldownPeriod < now()
  ) {
    await VerificationTokenSchema.deleteOne({
      verificationType: { type, value },
    });
    storedVToken = null;
  }

  //check if the verification token attempts is equal 10
  if (storedVToken && storedVToken.requestAttempts === 10) {
    //TODO: log this as suspicious activity
    logger.security(
      `verification token request failed for ${value} max request reached`,
      {
        action,
        requestId: req.requestId,
        userIdentifier: `${type}:${value}`,
        ipAddress: req.ip || "",
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.get("User-Agent") || "",
        errorCode: authErrorCodes.AUTH_TOO_MANY_VERI_REQ,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_TOO_MANY_VERI_REQ].status,
      }
    );
    //Add a cooldown period of 1 hour
    if (!storedVToken.cooldownPeriod) {
      storedVToken.cooldownPeriod = fromDate(
        authConfigsLoader.getConfig().coolDownPeriod
      );
      await storedVToken.save();
    }
    const message: ValidationMessages = "max-request-reached";
    throw new TooManyVerificationRequestError(
      authErrorCodes.AUTH_TOO_MANY_VERI_REQ,
      storedVToken.cooldownPeriod
    );
  }

  // Generate a verification token
  const token = generateVerificationToken({
    type: { type, value },
    maxAge: authConfigsLoader.getConfig().vtMaxAge,
  });

  let newVerificationToken;

  //Upadate the verification token attempts
  if (storedVToken) {
    storedVToken.requestAttempts = storedVToken.requestAttempts + 1;
    storedVToken.codes.push(token.code);
    await storedVToken.save();
  } else {
    // Save the verification token in the database
    newVerificationToken = await VerificationTokenSchema.create({
      codes: [token.code],
      verificationType: token.verificationType,
      expires: token.expires,
    });

    if (!newVerificationToken) {
      // If the verification token was not saved successfully, throw a 500 Internal Server Error
      throw new Error("An unexpected error has occurred");
    }
  }

  if (type === "email") {
    try {
      await sendEmailVerificationCode({
        email: value,
        code: token.code,
        isPasswordReset,
      });
    } catch (error) {
      logger.error(
        `verification token request failed for ${value} email verification request could not be sent`,
        {
          action,
          requestId: req.requestId,
          userIdentifier: `${type}:${value}`,
          ipAddress: req.ip || "",
          endpoint: req.path,
          httpMethod: req.method,
          userAgent: req.get("User-Agent") || "",
          errorCode: authErrorCodes.AUTH_VERIF_EMAIL_FAIL,
          statusCode:
            authErrorCodesMap[authErrorCodes.AUTH_VERIF_EMAIL_FAIL].status,
        }
      );
      throw new CustomError(authErrorCodes.AUTH_VERIF_EMAIL_FAIL);
    }
    // Send an email to the user with the verification code
  } else {
    //Send an sms to the user with the verification code
    //  await sendSmsVerificationCode({
    //     phone: value,
    //     code: token.code,
    //     isPasswordReset,
    //   });
  }
}

export async function verifyVerificationTokenHandler(
  type: "email" | "phone",
  value: string,
  code: string,
  req: Request
) {
  //check if the verification code is valid
  const verificationToken = await VerificationTokenSchema.findOne({
    verificationType: { type, value },
  });

  if (!verificationToken) {
    //TODO: log this as suspicious activity (type: 'signup', value: email)
    logger.security(
      `verification token request failed for ${value} verification token not found`,
      {
        action: "signup",
        requestId: req.requestId,
        userIdentifier: `${type}:${value}`,
        ipAddress: req.ip || "",
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.get("User-Agent") || "",
        errorCode: authErrorCodes.AUTH_VERIFICATION_CODE_INVALID,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_VERIFICATION_CODE_INVALID]
            .status,
      }
    );
    throw new CustomError(authErrorCodes.AUTH_VERIFICATION_CODE_INVALID);
  }

  const validation = checkVerificationToken({
    userCode: code,
    cachedCodes: verificationToken.codes,
    expires: verificationToken.expires,
    validationAttempts: verificationToken.validationAttempts,
  });

  if (validation === "expired") {
    //Delete the verification token
    await VerificationTokenSchema.deleteOne({ _id: verificationToken._id });
    logger.security(
      `verification token request failed for ${value} verification code expired`,
      {
        action: "signup",
        requestId: req.requestId,
        userIdentifier: `${type}:${value}`,
        ipAddress: req.ip || "",
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.get("User-Agent") || "",
        errorCode: authErrorCodes.AUTH_VERIFICATION_CODE_EXPIRED,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_VERIFICATION_CODE_EXPIRED]
            .status,
      }
    );
    throw new CustomError(authErrorCodes.AUTH_VERIFICATION_CODE_EXPIRED);
  } else if (validation === "invalid") {
    //TODO: log this as suspicious activity (type: 'signup', value: email)
    logger.security(
      `verification token request failed for ${value} verification code invalid`,
      {
        action: "signup",
        requestId: req.requestId,
        userIdentifier: `${type}:${value}`,
        ipAddress: req.ip || "",
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.get("User-Agent") || "",
        errorCode: authErrorCodes.AUTH_VERIFICATION_CODE_INVALID,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_VERIFICATION_CODE_INVALID]
            .status,
      }
    );
    verificationToken.validationAttempts += 1;
    await verificationToken.save();

    throw new CustomError(authErrorCodes.AUTH_VERIFICATION_CODE_INVALID);
  } else if (validation === "validation-attempts-exceeded") {
    //Delete the verification token
    await VerificationTokenSchema.deleteOne({ _id: verificationToken._id });
    logger.security(
      `verification token request failed for ${value} validation attempts exceeded`,
      {
        action: "signup",
        requestId: req.requestId,
        userIdentifier: `${type}:${value}`,
        ipAddress: req.ip || "",
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.get("User-Agent") || "",
        errorCode: authErrorCodes.AUTH_CODE_MAX_TRIES,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_CODE_MAX_TRIES].status,
      }
    );
    throw new CustomError(authErrorCodes.AUTH_CODE_MAX_TRIES);
  }
}

/**
 * This function takes a Joi schema and a request body as a parameter
 * that can be used to validate the request body against the schema.
 * @param schema
 * @param body
 */

export function validateRequestBody(schema: Joi.ObjectSchema, body: object) {
  const { error } = schema.validate(body);
  // If there is an error, return a 422 Unprocessable Entity
  // error with a message containing the error details.
  if (error) {
    const { details } = error;
    const message = details.map((i) => i.message).join(",");
    logger.debug(message, {
      action: "validateSchema",
      endpoint: "",
      httpMethod: "",
      ipAddress: "",
      userAgent: "",
      userIdentifier: "",
      requestId: "",
      statusCode:
        authErrorCodesMap[authErrorCodes.AUTH_REQ_VALIDATION_ERROR].status,
      errorCode: authErrorCodes.AUTH_REQ_VALIDATION_ERROR,
    });
    throw new CustomError(authErrorCodes.AUTH_REQ_VALIDATION_ERROR, message);
  }
}
