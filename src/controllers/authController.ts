import e, { Request, Response, NextFunction } from "express";
import { CustomError } from "../lib/error";
import { authErrorCodes, authErrorCodesMap } from "../lib/errorCodes";
import { UserSchema } from "../models/users";
import { refreshsSchema } from "../models/refreshTokens";
import {
  hashPassword,
  generateJWTToken,
  verifyPassword,
  verifyJWTToken,
  AccessTokenClaims,
  AccessToken,
  SessionToken,
  SessionTokenClaims,
  RefreshToken,
  RefreshTokenClaims,
  ClientTokenClaims,
  ClientToken,
  TokenTypes,
} from "../lib/auth";
import config from "../config";
import userSchema from "../models/users/userSchema";
import {
  sendVerificationTokenHandler,
  verifyVerificationTokenHandler,
  validateRequestBody,
} from "./helpers";
import { now } from "../utils";
import refreshTokensSchema from "../models/refreshTokens/refreshTokensSchema";
import { fromDate } from "../utils";
import verificationsSchema from "../models/verificationTokens/verificationsSchema";
import { responseDefault } from "../lib/constants";
import { signInSchema, signUpSchema } from "../models/users/types";
import { jwtSecretsLoader, authConfigsLoader } from "../config/configurations";

import {} from "../config/configurations";
import { jwt } from "twilio";
import auth from "../middleware/authorize";
import logger from "../lib/logger";
import { log } from "console";

//public
export async function signin(req: Request, res: Response, next: NextFunction) {
  try {
    validateRequestBody(signInSchema, req.body);
    // Retrieve username and password from request body
    const { type, password, value } = req.body;
    const action = "signin";

    // Find user in the database by username
    const user = await userSchema.findOne({ [type]: value });

    // Check if user exists
    if (!user) {
      logger.security(
        `Signin attempt failed with  ${type}:${value} not found`,
        {
          action,
          requestId: req.requestId,
          userIdentifier: `${type}:${value}`,
          ipAddress: req.forwardedForIp,
          endpoint: req.path,
          httpMethod: req.method,
          userAgent: req.forwardedUserAgent,
          errorCode: authErrorCodes.AUTH_INVALID_CREDENTIALS,
          statusCode:
            authErrorCodesMap[authErrorCodes.AUTH_INVALID_CREDENTIALS].status,
        }
      );
      throw new CustomError(authErrorCodes.AUTH_INVALID_CREDENTIALS);
    }

    // Check if password is correct
    const isValid = await verifyPassword(password, user.password);
    if (!isValid) {
      logger.security(
        `Signin attempt failed with  ${type}:${value} invalid password`,
        {
          action,
          requestId: req.requestId,
          userIdentifier: `${type}:${value}`,
          ipAddress: req.forwardedForIp,
          endpoint: req.path,
          httpMethod: req.method,
          userAgent: req.forwardedUserAgent,
          errorCode: authErrorCodes.AUTH_INVALID_CREDENTIALS,
          statusCode:
            authErrorCodesMap[authErrorCodes.AUTH_INVALID_CREDENTIALS].status,
        }
      );
      throw new CustomError(authErrorCodes.AUTH_INVALID_CREDENTIALS);
    }

    const roles = ["shopper"];
    // Generate access token
    const accessToken = await generateJWTToken<AccessTokenClaims>({
      ...responseDefault,
      audience: "abiemarket",
      type: "at",
      claims: {
        sub: user._id,
        name: `${user.name}`,
        roles,
      },
      maxAge: authConfigsLoader.getConfig().atMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
    });

    // Generate refresh token
    const refreshToken = await generateJWTToken<RefreshTokenClaims>({
      audience: "abiemarket",
      type: "rt",
      claims: {
        sub: user._id,
      },
      maxAge: authConfigsLoader.getConfig().rtMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
    });

    const SessionToken = await generateJWTToken<SessionTokenClaims>({
      audience: "abiemarket",
      type: "st",
      claims: {
        hasStore: user.roles.includes("seller"),
        sub: user._id,
        _sot: type,
        val: value,
        roles,
        name: `${user.name}`,
      },
      maxAge: authConfigsLoader.getConfig().stMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
    });

    // Store refresh token in the database or session
    const storedRT = await refreshsSchema.create({
      refreshToken,
      userId: user._id,
      name: `${user.name}`,
      _sot: type,
      val: value,
      roles,
      expires: fromDate(authConfigsLoader.getConfig().rtMaxAge),
      created: now(),
    });

    if (!storedRT) {
      logger.security(
        `Signin attempt failed with  ${type}:${value} failed to store refresh token`,
        {
          action,
          requestId: req.requestId,
          userIdentifier: `${type}:${value}`,
          ipAddress: req.forwardedForIp,
          endpoint: req.path,
          httpMethod: req.method,
          userAgent: req.forwardedUserAgent,
          errorCode: authErrorCodes.AUTH_RT_CACHED_FAILED,
          statusCode:
            authErrorCodesMap[authErrorCodes.AUTH_RT_CACHED_FAILED].status,
        }
      );
      throw new CustomError(authErrorCodes.AUTH_RT_CACHED_FAILED);
    }

    // Return access token and refresh token in the response
    res.status(200).json({
      ...responseDefault,
      result: {
        accessToken: {
          token: accessToken,
          expires: fromDate(authConfigsLoader.getConfig().atMaxAge),
        },
        refreshToken: {
          token: refreshToken,
          expires: fromDate(authConfigsLoader.getConfig().rtMaxAge),
        },

        session: {
          token: SessionToken,
          user: {
            sub: user._id,
            name: `${user.name} `,
            _sot: type,
            val: value,
            roles,
          },
          expires: fromDate(authConfigsLoader.getConfig().stMaxAge),
        },
      },
    });
  } catch (error) {
    next(error);
  }
}

//private
export async function renewAccessToken(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    // Retrieve refresh token from request body or session
    const refreshToken = req.body.refreshToken;
    const action = "renewAccessToken";

    if (!refreshToken) {
      //TODO: log this
      logger.security("Renew access token failed with no refresh token", {
        action,
        requestId: req.requestId,
        userIdentifier: "no user",
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_INVALID_REFRESH_TOKEN,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_INVALID_REFRESH_TOKEN].status,
      });
      throw new CustomError(authErrorCodes.AUTH_INVALID_REFRESH_TOKEN);
    }

    // Verify refresh token in the database or session
    const decodedResult = await verifyJWTToken<RefreshToken>(
      {
        secret: jwtSecretsLoader.getConfig().newJwtSecert,
        token: refreshToken,
      },
      jwtSecretsLoader.getConfig().oldJwtSecert
    );

    if (decodedResult.type === "error") {
      //TODO: log this as suspicious activity
      logger.security(`Renew access token failed with invalid refresh token`, {
        action,
        requestId: req.requestId,
        userIdentifier: refreshToken,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_INVALID_REFRESH_TOKEN,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_INVALID_REFRESH_TOKEN].status,
      });
      throw new CustomError(authErrorCodes.AUTH_INVALID_REFRESH_TOKEN);
    }

    if (decodedResult.type === "expired") {
      logger.security(`Renew access token failed with expired refresh token`, {
        action,
        requestId: req.requestId,
        userIdentifier: refreshToken,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_TOKEN_EXPIRED,
        statusCode: authErrorCodesMap[authErrorCodes.AUTH_TOKEN_EXPIRED].status,
      });

      throw new CustomError(
        authErrorCodes.AUTH_TOKEN_EXPIRED,
        "refresh token expired"
      );
    }

    const cachedRT = await refreshsSchema.findOne({ refreshToken });
    if (!cachedRT) {
      //TODO: log this as suspicious activity
      logger.security(`Renew access token failed with invalid refresh token`, {
        action,
        requestId: req.requestId,
        userIdentifier: refreshToken,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_INVALID_REFRESH_TOKEN,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_INVALID_REFRESH_TOKEN].status,
      });
      throw new CustomError(authErrorCodes.AUTH_INVALID_REFRESH_TOKEN);
    }
    if (cachedRT.revoked) {
      //TODO: log this
      logger.security(`Renew access token failed with revoked refresh token`, {
        action,
        requestId: req.requestId,
        userIdentifier: refreshToken,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_INVALID_REFRESH_TOKEN,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_INVALID_REFRESH_TOKEN].status,
      });
      throw new CustomError(authErrorCodes.AUTH_INVALID_REFRESH_TOKEN);
    }

    // Generate new access token
    const accessToken = await generateJWTToken<AccessTokenClaims>({
      audience: "abiemarket",
      type: "at",
      claims: {
        name: cachedRT.name,
        sub: cachedRT.userId,
        roles: cachedRT.roles,
      },
      maxAge: authConfigsLoader.getConfig().atMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
    });

    // Return new access token in the response

    res.status(200).json({
      ...responseDefault,
      result: {
        accessToken: {
          token: accessToken,
          expires: fromDate(authConfigsLoader.getConfig().atMaxAge),
        },
      },
    });
  } catch (error) {
    next(error);
  }
}
//induced change
//private
export async function signout(req: Request, res: Response, next: NextFunction) {
  try {
    const refreshToken = req.body.refreshToken;
    //induced change
    // Clear access token and refresh token from database or session
    if (!refreshToken) {
      //TODO: log this
      logger.security("Signout attempt failed with no refresh token", {
        action: "signout",
        requestId: req.requestId,
        userIdentifier: "no user",
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_INVALID_REFRESH_TOKEN,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_INVALID_REFRESH_TOKEN].status,
      });
      throw new CustomError(authErrorCodes.AUTH_INVALID_REFRESH_TOKEN);
    }

    // Verify refresh token in the database or session
    const decodedResult = await verifyJWTToken<RefreshToken>(
      {
        secret: jwtSecretsLoader.getConfig().newJwtSecert,
        token: refreshToken,
      },
      jwtSecretsLoader.getConfig().oldJwtSecert
    );

    if (decodedResult.type === "error") {
      //TODO: log this as suspicious activity
      logger.security(`Signout attempt failed with invalid refresh token`, {
        action: "signout",
        requestId: req.requestId,
        userIdentifier: refreshToken,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_INVALID_REFRESH_TOKEN,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_INVALID_REFRESH_TOKEN].status,
      });
      throw new CustomError(authErrorCodes.AUTH_INVALID_REFRESH_TOKEN);
    }

    let userId = "";

    ///if the refresh token has expired retrieve it from the database
    if (decodedResult.type === "expired") {
      const cachedRefreshToken = await refreshsSchema.findOneAndDelete({
        refreshToken,
      });
      //if there is no such token just return a successful response
      if (!cachedRefreshToken) {
        return res.status(200).json({
          ...responseDefault,
          message: "logout-successful",
          result: {},
        });
      }

      //however if there is a refresh token retrieve the userId and delete
      //all tokens associated with this user
      //@ts-ignore
      userId = cachedRefreshToken.userId;
    } else {
      userId = decodedResult.payload.sub;
    }

    await refreshsSchema.deleteOne({ refreshToken });
    // For example, if you are using express-session: req.session.accessToken = null; req.session.refreshToken = null;
    res.status(200).json({
      ...responseDefault,
      message: "logout-successful",
      result: {},
    });
  } catch (error) {
    next(error);
  }
}

//private
export async function revokeToken(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    // Retrieve token from request body
    const rtToken = req.body.token;

    // Revoke token in the database or session
    await refreshTokensSchema.findOneAndUpdate(
      {
        refreshToken: rtToken,
      },
      { revoked: true }
    );

    res.json({ ...responseDefault, result: { message: "token revoked" } });
  } catch (error) {
    next(error);
  }
}

//public
export async function signup(req: Request, res: Response, next: NextFunction) {
  try {
    validateRequestBody(signUpSchema, req.body);
    const { password, name, type, value, code } = req.body;
    const action = "signup";

    // Check if the value (phone number or email) is already taken
    const isValueTaken = await UserSchema.findOne({ [type]: value });
    if (isValueTaken) {
      // If the value (phone or email) is already taken, throw a 422 Unprocessable Entity error
      if (type === "email") {
        logger.security(
          `Signup attempt failed with  ${type}:${value} already taken`,
          {
            action,
            requestId: req.requestId,
            userIdentifier: `${type}:${value}`,
            ipAddress: req.forwardedForIp,
            endpoint: req.path,
            httpMethod: req.method,
            userAgent: req.forwardedUserAgent,
            errorCode: authErrorCodes.AUTH_SIGNUP_EMAIL_TAKEN,
            statusCode:
              authErrorCodesMap[authErrorCodes.AUTH_SIGNUP_EMAIL_TAKEN].status,
          }
        );
        throw new CustomError(authErrorCodes.AUTH_SIGNUP_EMAIL_TAKEN);
      } else {
        logger.security(
          `Signup attempt failed with  ${type}:${value} already taken`,
          {
            action,
            requestId: req.requestId,
            userIdentifier: `${type}:${value}`,
            ipAddress: req.forwardedForIp,
            endpoint: req.path,
            httpMethod: req.method,
            userAgent: req.forwardedUserAgent,
            errorCode: authErrorCodes.AUTH_SIGNUP_PHONE_TAKEN,
            statusCode:
              authErrorCodesMap[authErrorCodes.AUTH_SIGNUP_PHONE_TAKEN].status,
          }
        );
        throw new CustomError(authErrorCodes.AUTH_SIGNUP_PHONE_TAKEN);
      }
    }

    //verify the verification code
    await verifyVerificationTokenHandler(type, value, code, req);

    // Hash the password
    const hashedPassword = await hashPassword(password);

    // Create a new user with the provided email, hashed password, and name
    const newUser = await UserSchema.create({
      [type]: value,
      password: hashedPassword,
      name,
    });
    if (!newUser) {
      // If the new user was not created successfully, throw a 500 Internal Server Error
      throw new Error("An unexpected error has occurred. no user was created");
    }

    //delete the verification token
    await verificationsSchema.deleteMany({
      verificationType: {
        type,
        value,
      },
    });

    //sign user in
    const roles = ["shopper"];

    //generate an access token for the user
    const accessToken = await generateJWTToken<AccessTokenClaims>({
      audience: "abiemarket",
      type: "at",
      claims: { sub: newUser._id, roles, name: `${name} ` },
      maxAge: authConfigsLoader.getConfig().atMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
    });
    const refreshToken = await generateJWTToken<RefreshTokenClaims>({
      type: "rt",
      audience: "abiemarket",
      claims: { sub: newUser._id },
      maxAge: authConfigsLoader.getConfig().rtMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
    });

    //generate session token
    const sessionToken = await generateJWTToken<SessionTokenClaims>({
      audience: "abiemarket",
      type: "st",
      claims: {
        hasStore: newUser.roles.includes("seller"),
        sub: newUser._id,
        roles,
        _sot: type,
        val: value,
        name: `${name}`,
      },
      maxAge: authConfigsLoader.getConfig().stMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
    });

    const exp = fromDate(authConfigsLoader.getConfig().rtMaxAge);

    //store refresh Token
    await refreshTokensSchema.create({
      refreshToken,
      userId: newUser._id,
      roles: ["shopper"],
      name: `${newUser.name}`,
      _sot: type,
      val: value,
      expires: exp,
      created: now(),
    });

    // If everything is successful, return a 201 Created response with the token in the response body
    res.status(201).json({
      ...responseDefault,
      result: {
        accessToken: {
          token: accessToken,
          expires: fromDate(authConfigsLoader.getConfig().atMaxAge),
        },
        refreshToken: {
          token: refreshToken,
          expires: exp,
        },
        session: {
          token: sessionToken,
          user: {
            sub: newUser._id,
            name: `${newUser.name} `,
            roles: ["shopper"],
            _sot: type,
            val: value,
          },
          expires: fromDate(authConfigsLoader.getConfig().stMaxAge),
        },
      },
    });
  } catch (error) {
    // If an error occurs at any point in the try block, call the next middleware function with the error
    next(error);
  }
}

//private
export function sellerSignup(req: any, res: Response, next: NextFunction) {
  try {
    // Retrieve user information from request body
    const { businessName, businessAddr } = req.body;
    let { sub, roles } = req.user as AccessTokenClaims;

    // Create user in the database
    // For example, you can use the username and password to create a new user in the database

    // Return success response
    res.json({ ...responseDefault });
  } catch (error) {}
}

//private
export async function sellerSignin(
  req: any,
  res: Response,
  next: NextFunction
) {
  try {
    // Retrieve user information from request body
    const { type, value, password } = req.body;
    const action = "sellerSignin";
    //let { sub, roles } = req.user as AccessTokenClaims;

    // Authenticate user
    // For example, you can use the email or phone number to authenticate the user in the database
    let user = await userSchema.findOne({ [type]: value });

    if (!user) {
      logger.security(
        `Seller signin attempt failed with  ${type}:${value} not found`,
        {
          action,
          requestId: req.requestId,
          userIdentifier: `${type}:${value}`,
          ipAddress: req.forwardedForIp,
          endpoint: req.path,
          httpMethod: req.method,
          userAgent: req.forwardedUserAgent,
          errorCode: authErrorCodes.AUTH_INVALID_CREDENTIALS,
          statusCode:
            authErrorCodesMap[authErrorCodes.AUTH_INVALID_CREDENTIALS].status,
        }
      );
      throw new CustomError(authErrorCodes.AUTH_INVALID_CREDENTIALS);
    }
    if (!user.roles.includes("seller")) {
      logger.security(
        `Seller signin attempt failed with  ${type}:${value} not a seller`,
        {
          action,
          requestId: req.requestId,
          userIdentifier: `${type}:${value}`,
          ipAddress: req.forwardedForIp,
          endpoint: req.path,
          httpMethod: req.method,
          userAgent: req.forwardedUserAgent,
          errorCode: authErrorCodes.AUTH_INVALID_CREDENTIALS,
          statusCode:
            authErrorCodesMap[authErrorCodes.AUTH_INVALID_CREDENTIALS].status,
        }
      );
      throw new CustomError(authErrorCodes.AUTH_INVALID_CREDENTIALS);
    }

    const isPasswordValid = await verifyPassword(password, user.password);
    if (!isPasswordValid) {
      logger.security(
        `Seller signin attempt failed with  ${type}:${value} invalid password`,
        {
          action,
          requestId: req.requestId,
          userIdentifier: `${type}:${value}`,
          ipAddress: req.forwardedForIp,
          endpoint: req.path,
          httpMethod: req.method,
          userAgent: req.forwardedUserAgent,
          errorCode: authErrorCodes.AUTH_INVALID_CREDENTIALS,
          statusCode:
            authErrorCodesMap[authErrorCodes.AUTH_INVALID_CREDENTIALS].status,
        }
      );
      throw new CustomError(authErrorCodes.AUTH_INVALID_CREDENTIALS);
    }

    //get refresh token
    await refreshsSchema.deleteMany({ userId: user._id });
    // Generate access token
    const roles = ["shopper", "seller"];

    //create refresh token
    const refreshToken = await generateJWTToken<RefreshTokenClaims>({
      audience: "abiemarket",
      type: "rt",
      claims: { sub: user._id },
      maxAge: authConfigsLoader.getConfig().rtMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
    });

    const storedRT = await refreshsSchema.create({
      refreshToken,
      userId: user._id,
      roles,
      name: `${user.name}`,
      _sot: type,
      val: value,
      expires: fromDate(authConfigsLoader.getConfig().rtMaxAge),
      created: now(),
    });

    const accessToken = await generateJWTToken<AccessTokenClaims>({
      audience: "abiemarket",
      type: "at",
      claims: {
        sub: user._id,
        roles,
        name: `${user.name}`,
      },
      maxAge: authConfigsLoader.getConfig().atMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
    });

    //generate session token
    const sessionToken = await generateJWTToken<SessionTokenClaims>({
      audience: "abiemarket",
      type: "st",
      claims: {
        hasStore: user.roles.includes("seller"),
        sub: user._id,
        roles,
        _sot: type,
        val: value,
        name: `${user.name}`,
      },
      maxAge: authConfigsLoader.getConfig().stMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
    });

    // Return access token in the response
    res.json({
      ...responseDefault,
      result: {
        accessToken: {
          token: accessToken,
          expires: fromDate(authConfigsLoader.getConfig().atMaxAge),
        },
        refreshToken: {
          token: storedRT.refreshToken,
          expires: storedRT.expires,
        },
        session: {
          token: sessionToken,
          user: {
            sub: user._id,
            name: `${user.name} `,
            roles,
            _sot: type,
            val: value,
          },
          expires: fromDate(authConfigsLoader.getConfig().stMaxAge),
        },
      },
    });
  } catch (error) {
    next(error);
  }
}

//public
export function getCsrfToken(req: Request, res: Response, next: NextFunction) {
  try {
    // Generate CSRF token
    //const csrfToken = crypto.randomBytes(32).toString('hex');

    // Store CSRF token in the database or session
    // For example, if you are using express-session: req.session.csrfToken = csrfToken;

    // Return CSRF token in the response
    res.json({
      ...responseDefault,
      result: {
        csrf_token: "csrfToken",
      },
    });
  } catch (error) {}
}

//public
export async function sendVerificationToken(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { value, type } = req.body;

    await sendVerificationTokenHandler(type, value, req);

    // If everything is successful, return a 201 Created response with the token in the response body
    res.status(201).json({
      ...responseDefault,
    });
  } catch (error) {
    // If an error occurs at any point in the try block, call the next middleware function with the error
    next(error);
  }
}

//public
export async function resetPassword(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { password, type, value, code } = req.body;

    const user = await userSchema.findOne({ [type]: value });

    if (!user) {
      logger.security(
        `Password reset attempt failed with  ${type}:${value} not found`,
        {
          action: "resetPassword",
          requestId: req.requestId,
          userIdentifier: `${type}:${value}`,
          ipAddress: req.forwardedForIp,
          endpoint: req.path,
          httpMethod: req.method,
          userAgent: req.forwardedUserAgent,
          errorCode: authErrorCodes.AUTH_USER_NOT_FOUND,
          statusCode:
            authErrorCodesMap[authErrorCodes.AUTH_USER_NOT_FOUND].status,
        }
      );

      throw new CustomError(authErrorCodes.AUTH_USER_NOT_FOUND);
    }

    await verifyVerificationTokenHandler(type, value, code, req);

    // Hash the password
    const hashedPassword = await hashPassword(password);

    // Update user password in the database
    user.password = hashedPassword;
    await user.save();
    // For example, you can use the username and password to update the user password in the database

    await verificationsSchema.deleteMany({ verificationType: { type, value } });

    // Return success response
    res.json({
      ...responseDefault,
      message: "password reset successfully",
    });
  } catch (error) {
    // If an error occurs at any point in the try block, call the next middleware function with the error
    next(error);
  }
}
//public
export async function sendPasswordResetToken(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { value, type } = req.body;

    await sendVerificationTokenHandler(type, value, req, true);

    // If everything is successful, return a 201 Created response with the token in the response body
    res
      .status(201)
      .json({ ...responseDefault, message: "password reset code sent" });
  } catch (error) {
    // If an error occurs at any point in the try block, call the next middleware function with the error
    next(error);
  }
}

//private
// signing in as a seller
export async function grant(req: any, res: Response, next: NextFunction) {
  try {
    const { type, value, password, role } = req.body;
    let { sub, roles } = req.user as AccessTokenClaims;

    const user = await userSchema.findOne({ [type]: value });
    if (!user) {
      //TODO: log this
      logger.security(`User ${sub} cannot be found`, {
        action: "grant",
        requestId: req.requestId,
        userIdentifier: `${type}:${value}`,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_USER_NOT_FOUND,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_USER_NOT_FOUND].status,
      });
      throw new CustomError(authErrorCodes.AUTH_USER_GRANT_FAIL);
    }

    const canGrantRole = user.roles.includes(role);

    if (!canGrantRole) {
      //TODO: Log this as an auth error
      logger.security(`User ${sub} cannot grant ${role} to ${type}:${value}`, {
        action: "grant",
        requestId: req.requestId,
        userIdentifier: `${type}:${value}`,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_UNAUTHORIZE,
        statusCode: authErrorCodesMap[authErrorCodes.AUTH_UNAUTHORIZE].status,
      });
      throw new CustomError(
        authErrorCodes.AUTH_UNAUTHORIZE,
        "User cannot be granted this role"
      );
    }
    const isPasswordValid = await verifyPassword(password, user.password);

    if (!isPasswordValid) {
      //TODO: Log this as
      logger.security(
        `User ${sub} cannot grant ${role} to ${type}:${value} invalid password`,
        {
          action: "grant",
          requestId: req.requestId,
          userIdentifier: `${type}:${value}`,
          ipAddress: req.forwardedForIp,
          endpoint: req.path,
          httpMethod: req.method,
          userAgent: req.forwardedUserAgent,
          errorCode: authErrorCodes.AUTH_INVALID_CREDENTIALS,
          statusCode:
            authErrorCodesMap[authErrorCodes.AUTH_INVALID_CREDENTIALS].status,
        }
      );
      throw new CustomError(
        authErrorCodes.AUTH_UNAUTHORIZE,
        "Invalid credentials"
      );
    }

    roles = [...roles, role];

    // Generate access token
    const accessToken = await generateJWTToken<AccessTokenClaims>({
      audience: "abiemarket",
      type: "at",
      claims: {
        sub,
        roles,
        name: `${user.name}`,
      },
      maxAge: 1200,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
    });

    //generate session token
    const sessionToken = await generateJWTToken<SessionTokenClaims>({
      audience: "abiemarket",
      type: "st",
      claims: {
        hasStore: user.roles.includes("seller"),
        sub,
        roles,
        _sot: type,
        val: value,
        name: `${user.name}`,
      },
      maxAge: authConfigsLoader.getConfig().stMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
    });

    res.status(201).json({
      ...responseDefault,
      result: {
        accessToken: {
          token: accessToken,
          expires: fromDate(1200),
        },
        session: {
          token: sessionToken,
          user: {
            sub,
            name: `${user.name}`,
            roles,
            _sot: type,
            val: value,
          },
          expires: fromDate(authConfigsLoader.getConfig().stMaxAge),
        },
      },
    });
  } catch (error) {
    next(error);
  }
}

export async function session(req: Request, res: Response, next: NextFunction) {
  const { sessionToken } = req.body;
  try {
    const action = "session";
    let decodedResult = await verifyJWTToken<SessionToken>(
      {
        secret: jwtSecretsLoader.getConfig().newJwtSecert,
        token: sessionToken,
      },
      jwtSecretsLoader.getConfig().oldJwtSecert
    );

    if (decodedResult.type === "error") {
      //TODO: log this
      logger.security(`Invalid session token`, {
        action,
        requestId: req.requestId,
        userIdentifier: sessionToken,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_INVALID_SESSION_TOKEN,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_INVALID_SESSION_TOKEN].status,
      });
      throw new CustomError(authErrorCodes.AUTH_INVALID_SESSION_TOKEN);
    }

    if (decodedResult.type === "expired") {
      await refreshTokensSchema.findOneAndUpdate(
        {
          sessionToken,
        },
        { revoked: true }
      );

      logger.security(`Expired session token`, {
        action,
        requestId: req.requestId,
        userIdentifier: sessionToken,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_TOKEN_EXPIRED,
        statusCode: authErrorCodesMap[authErrorCodes.AUTH_TOKEN_EXPIRED].status,
      });
      throw new CustomError(
        authErrorCodes.AUTH_TOKEN_EXPIRED,
        "session token expired"
      );
    }

    const { payload } = decodedResult;

    const newSessionToken = await generateJWTToken<SessionTokenClaims>({
      audience: "abiemarket",
      type: "st",
      claims: {
        hasStore: payload.hasStore,
        sub: payload.sub,
        roles: ["shopper"],
        _sot: payload._sot,
        val: payload.val,
        name: payload.name,
      },
      maxAge: authConfigsLoader.getConfig().stMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
    });

    res.json({
      ...responseDefault,
      result: {
        session: {
          user: {
            hasStore: payload.hasStore,
            sub: payload.sub,
            name: payload.name,
            _sot: payload._sot,
            val: payload.val,
            roles: payload.roles,
          },
          token: newSessionToken,
          expires: fromDate(authConfigsLoader.getConfig().stMaxAge),
        },
      },
    });
  } catch (error) {
    next(error);
  }
}

//private
//this route is intended to make a user a seller by adding the seller role to the user
export async function makeUserSeller(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { userId } = req.body;
    const user = await userSchema.findById(userId);

    if (!user) {
      logger.security(`User Not found while granting user seller permission`, {
        action: "makeUserSeller",
        requestId: req.requestId,
        userIdentifier: userId,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_USER_NOT_FOUND,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_USER_NOT_FOUND].status,
      });
      throw new CustomError(authErrorCodes.AUTH_USER_NOT_FOUND);
    }

    if (user.roles.includes("seller")) {
      logger.security(`User is already a seller`, {
        action: "makeUserSeller",
        requestId: req.requestId,
        userIdentifier: userId,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_USER_ALREADY_SELLER,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_USER_ALREADY_SELLER].status,
      });
      throw new CustomError(authErrorCodes.AUTH_USER_ALREADY_SELLER);
    }

    user.roles.push("seller");

    await user.save();

    res.json({
      ...responseDefault,
      result: {
        message: "User is now a seller",
      },
    });
  } catch (error) {
    next(error);
  }
}

type Platfrom = "web" | "android" | "ios";

export async function generateClientToken(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { verificationToken, platform: p } = req.body;

    let platform: Platfrom = p as Platfrom;

    if (!verificationToken) {
      logger.debug(`Client verification token is required`, {
        action: "generateClientToken",
        requestId: req.requestId,
        userIdentifier: "no user",
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_BAD_REQUEST,
        statusCode: authErrorCodesMap[authErrorCodes.AUTH_BAD_REQUEST].status,
      });
      throw new CustomError(
        authErrorCodes.AUTH_BAD_REQUEST,
        "client verification token is required"
      );
    }

    if (!platform) {
      throw new CustomError(
        authErrorCodes.AUTH_BAD_REQUEST,
        "platform is required"
      );
    }

    //mock the verification token
    const androidVerificationToken = "abcd1234";
    const iosVerificationToken = "efgh5678";
    const webVerificationToken = "ijkl9012";

    //verify the attestation token
    //send the attestation token to google or apple to verify the token
    //if the token is valid, generate a session token for the client and return it

    //for now just  mock the response
    if (platform === "web" && verificationToken !== webVerificationToken) {
      throw new CustomError(authErrorCodes.AUTH_INVALID_VERIFICATION_TOKEN);
    } else if (
      platform === "android" &&
      verificationToken !== androidVerificationToken
    ) {
      throw new CustomError(authErrorCodes.AUTH_INVALID_VERIFICATION_TOKEN);
    } else if (
      platform === "ios" &&
      verificationToken !== iosVerificationToken
    ) {
      throw new CustomError(authErrorCodes.AUTH_INVALID_VERIFICATION_TOKEN);
    }

    const clientToken = await generateJWTToken<ClientTokenClaims>({
      audience: "abiemarket",
      type: "ct",
      claims: {
        platform,
      },
      maxAge: authConfigsLoader.getConfig().ctMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
    });

    res.json({
      ...responseDefault,
      result: {
        clientToken: {
          token: clientToken,
          expires: fromDate(authConfigsLoader.getConfig().ctMaxAge),
        },
        message: "Mobile client verified",
      },
    });
  } catch (error) {
    next(error);
  }
}

export async function verifyToken(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { token, type } = req.body;

    console.log(token, type);

    const tokenType = type as TokenTypes;

    const decodedResult = await verifyJWTToken(
      {
        secret: jwtSecretsLoader.getConfig().newJwtSecert,
        token,
      },
      jwtSecretsLoader.getConfig().oldJwtSecert
    );

    if (decodedResult.type === "error") {
      logger.security(`${decodedResult.error}-tokenType:${tokenType}`, {
        action: "verifyToken",
        requestId: req.requestId,
        userIdentifier: token,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_INVALID_TOKEN,
        statusCode: authErrorCodesMap[authErrorCodes.AUTH_INVALID_TOKEN].status,
      });
      throw new CustomError(
        authErrorCodes.AUTH_INVALID_TOKEN,
        `invalid ${tokenType} token`
      );
    }

    if (decodedResult.type === "expired") {
      logger.security(`Expired ${tokenType} token`, {
        action: "verifyToken",
        requestId: req.requestId,
        userIdentifier: token,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_TOKEN_EXPIRED,
        statusCode: authErrorCodesMap[authErrorCodes.AUTH_TOKEN_EXPIRED].status,
      });
      throw new CustomError(
        authErrorCodes.AUTH_TOKEN_EXPIRED,
        `${tokenType} token expired`
      );
    }

    if (decodedResult.payload.type !== tokenType) {
      logger.security(`Invalid ${tokenType} token`, {
        action: "verifyToken",
        requestId: req.requestId,
        userIdentifier: token,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_INVALID_TOKEN,
        statusCode: authErrorCodesMap[authErrorCodes.AUTH_INVALID_TOKEN].status,
      });
      throw new CustomError(
        authErrorCodes.AUTH_INVALID_TOKEN,
        `invalid ${tokenType} token`
      );
    }

    let result = {};
    if (tokenType === "at") {
      const payload = decodedResult.payload as AccessToken;
      result = {
        sub: payload.sub,
        exp: payload.exp,
        roles: payload.roles,
        name: payload.name,
      };
    } else if (tokenType === "rt") {
      const payload = decodedResult.payload as RefreshToken;
      result = {
        sub: payload.sub,
        exp: payload.exp,
      };
    } else if (tokenType === "st") {
      const payload = decodedResult.payload as SessionToken;
      result = {
        sub: payload.sub,
        exp: payload.exp,
        roles: payload.roles,
        name: payload.name,
        _sot: payload._sot,
        val: payload.val,
        hasStore: payload.hasStore,
      };
    } else if (tokenType === "ct") {
      const payload = decodedResult.payload as ClientToken;
      result = {
        platform: payload.platform,
      };
    } else {
      logger.security(`Invalid ${tokenType} token`, {
        action: "verifyToken",
        requestId: req.requestId,
        userIdentifier: token,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_INVALID_TOKEN,
        statusCode: authErrorCodesMap[authErrorCodes.AUTH_INVALID_TOKEN].status,
      });
      throw new CustomError(
        authErrorCodes.AUTH_INVALID_TOKEN,
        `invalid ${tokenType} token`
      );
    }

    res.json({
      ...responseDefault,
      result: {
        message: "token verified",
        claims: result,
      },
    });
  } catch (error) {
    next(error);
  }
}

export async function verifyOTP(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { code, type, value } = req.body;

    await verifyVerificationTokenHandler(type, value, code, req);

    res.status(204).json({
      ...responseDefault,
      result: {},
      message: "verification token verified",
    });
  } catch (error) {
    next(error);
  }
}
