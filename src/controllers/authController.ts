import e, { Request, Response, NextFunction } from "express";
import { AppError } from "../error/AppError";
import { authErrorCodes } from "../error/errorCodes";
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
import { now, nowInSeconds } from "../utils";
import refreshTokensSchema from "../models/refreshTokens/refreshTokensSchema";
import { fromDate } from "../utils";
import verificationsSchema from "../models/verificationTokens/verificationsSchema";
import { responseDefault } from "../lib/constants";
import { signInSchema, signUpSchema } from "../models/users/types";
import { jwtSecretsLoader, authConfigsLoader } from "../config/configurations";

import {} from "../config/configurations";
import mongoose from "mongoose";
import logger from "../lib/logger";

//public
export async function signin(req: Request, res: Response, next: NextFunction) {
  try {
    // Retrieve username and password from request body
    const { type, password, value, clientId } = req.body;

    // Find user in the database by username
    const user = await userSchema.findOne({ [type]: value });

    // Check if user exists
    if (!user) {
      throw new AppError(authErrorCodes.AUTH_INVALID_CREDENTIALS, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "signin",
        additionalInfo: "Signin attempt failed with invalid credentials",
      });
    }

    // Check if password is correct
    const isValid = await verifyPassword(password, user.password);
    if (!isValid) {
      throw new AppError(authErrorCodes.AUTH_INVALID_CREDENTIALS, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "signin",
        additionalInfo: `Signin attempt failed with  ${type}:${value} invalid password`,
      });
    }

    const sit = nowInSeconds();

    const roles = user.roles;
    // Generate access token
    const accessToken = await generateJWTToken<AccessTokenClaims>({
      ...responseDefault,
      audience: "abiemarket",
      type: "at",
      claims: {
        sit,
        sub: user._id,
        name: `${user.name}`,
        roles,
      },
      maxAge: authConfigsLoader.getConfig().atMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
      ver: user.__v,
    });

    // Generate refresh token
    const refreshToken = await generateJWTToken<RefreshTokenClaims>({
      audience: "abiemarket",
      type: "rt",
      claims: {
        sit,
        sub: user._id,
      },
      maxAge: authConfigsLoader.getConfig().rtMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
      ver: user.__v,
    });

    // const SessionToken = await generateJWTToken<SessionTokenClaims>({
    //   audience: "abiemarket",
    //   type: "st",
    //   claims: {
    //     sit,
    //     hasStore: user.roles.includes("vendor"),
    //     sub: user._id,
    //     _sot: type,
    //     val: value,
    //     roles,
    //     name: `${user.name}`,
    //   },
    //   maxAge: authConfigsLoader.getConfig().stMaxAge,
    //   secret: jwtSecretsLoader.getConfig().newJwtSecert,
    // });

    // Store refresh token in the database or session
    const storedRT = await refreshsSchema.findOneAndUpdate(
      {
        userId: user._id,
        clientId,
      },
      {
        refreshToken,
        userId: user._id,
        name: `${user.name}`,
        _sot: type,
        val: value,
        roles,
        expires: fromDate(authConfigsLoader.getConfig().rtMaxAge),
        created: now(),
        ver: user.__v,
        clientId,
        sit: nowInSeconds(),
        userAgent: req.forwardedUserAgent || "default",
      },
      { upsert: true, sort: { created: -1 } }
    );

    // if (!storedRT) {
    //   throw new AppError(authErrorCodes.AUTH_RT_CACHED_FAILED, undefined, {
    //     logLevel: "security",
    //     errorLogSeverity: "major",
    //     where: "signin",
    //     additionalInfo: `Signin attempt failed with  ${type}:${value} failed to store refresh token`,
    //   });
    // }

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

        user: {
          sub: user._id,
          name: `${user.name} `,
          _sot: type,
          val: value,
          roles,
        },
      },
    });
  } catch (error) {
    next(error);
  }
}

//public - guest
export async function getGuestTokens(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    let { guestId } = req.body;
    if (guestId) {
      guestId = guestId.split("-")[0];
    }

    if (guestId && !mongoose.Types.ObjectId.isValid(guestId)) {
      throw new AppError(authErrorCodes.AUTH_INVALID_GUEST_ID, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "getGuestTokens",
        neededActions: ["check the client request"],
        additionalInfo: `Get guest token failed with invalid guestId`,
      });
    }
    const sub = guestId ? guestId : new mongoose.Types.ObjectId().toHexString();
    const sit = nowInSeconds();
    const accessToken = await generateJWTToken<AccessTokenClaims>({
      audience: "abiemarket",
      type: "at",
      claims: {
        sit,
        sub: sub + "-guest",
        roles: ["guest"],
        name: "guest",
      },
      maxAge: authConfigsLoader.getConfig().atMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
      ver: 1,
    });

    const refreshToken = await generateJWTToken<RefreshTokenClaims>({
      audience: "abiemarket",
      type: "rt",
      claims: {
        sit,
        sub: sub + "-guest",
      },
      maxAge: authConfigsLoader.getConfig().rtMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
      ver: 1,
    });

    // const sessionToken = await generateJWTToken<SessionTokenClaims>({
    //   audience: "abiemarket",
    //   type: "st",
    //   claims: {
    //     sit,
    //     hasStore: false,
    //     sub: sub + "-guest",
    //     roles: ["guest"],
    //     name: "Guest",
    //     _sot: "guest",
    //     val: "guest",
    //   },
    //   maxAge: authConfigsLoader.getConfig().stMaxAge,
    //   secret: jwtSecretsLoader.getConfig().newJwtSecert,
    // });

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
        guestId: sub + "-guest",
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
    const clientId = req.body.clientId;

    if (!refreshToken) {
      throw new AppError(
        authErrorCodes.AUTH_REFRESH_UNAUTHORIZED,
        "unauthorized",
        {
          logLevel: "security",
          errorLogSeverity: "critical",
          where: "renewAccessToken",
          neededActions: ["check the client request"],
          additionalInfo:
            "Renew access token failed with no refresh token provided, This seems like a misused of the API which should be investigated",
        }
      );
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
      throw new AppError(authErrorCodes.AUTH_REFRESH_UNAUTHORIZED, undefined, {
        logLevel: "security",
        errorLogSeverity: "critical",
        where: "renewAccessToken",
        neededActions: ["check the client request"],
        additionalInfo:
          "Renew access token failed with invalid refresh token. This is a security threat and should be investigated",
      });
    }

    if (decodedResult.type === "expired") {
      throw new AppError(
        authErrorCodes.AUTH_REFRESH_UNAUTHORIZED,
        "refresh token expired",
        {
          logLevel: "warn",
          errorLogSeverity: "major",
          where: "renewAccessToken",
          neededActions: ["check the client request"],
          additionalInfo:
            "Renew access token failed with expired refresh token",
        }
      );
    }
    let cachedRT;
    let isGuestToken = false;
    //Do not check the result if the token is a guest token - guest token are not cached to the DB! only regular signin
    if (decodedResult.payload.sub.includes("-guest")) {
      isGuestToken = true;
      cachedRT = { revoked: false } as any;
    } else {
      console.log("signin user");
      cachedRT = await refreshsSchema.findOneAndDelete({
        refreshToken,
      });
    }

    // Check if the refresh token is revoked
    if (!cachedRT) {
      throw new AppError(authErrorCodes.AUTH_REFRESH_UNAUTHORIZED, undefined, {
        logLevel: "security",
        errorLogSeverity: "critical",
        where: "renewAccessToken",
        neededActions: ["check for suspicious activity"],
        additionalInfo:
          "This refresh token does not exist in the database, seems like an attacker is trying to renew access token with a revoked token",
      });
    }
    if (cachedRT.revoked) {
      throw new AppError(authErrorCodes.AUTH_REFRESH_UNAUTHORIZED, undefined, {
        logLevel: "security",
        errorLogSeverity: "critical",
        where: "renewAccessToken",
        neededActions: ["check the client request"],
        additionalInfo:
          "This refresh token has been revoked and seems like an attacker is trying to renew access token with a revoked token",
      });
    }

    //Generate new refreshToken
    const newRefreshToken = await generateJWTToken<RefreshTokenClaims>({
      type: "rt",
      audience: "abiemarket",
      claims: {
        sit: !isGuestToken ? cachedRT.sit : `${decodedResult.payload.sit}`,
        sub: !isGuestToken ? cachedRT.userId : `${decodedResult.payload.sub}`,
      },
      maxAge: authConfigsLoader.getConfig().rtMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
      ver: cachedRT.ver,
    });

    const clientProfileUpdated = decodedResult.payload.ver !== cachedRT.ver;

    //store refresh token
    if (!isGuestToken) {
      await refreshsSchema.create({
        refreshToken: newRefreshToken,
        userId: cachedRT.userId,
        roles: cachedRT.roles,
        name: cachedRT.name,
        _sot: cachedRT._sot,
        val: cachedRT.val,
        expires: fromDate(authConfigsLoader.getConfig().rtMaxAge),
        created: now(),
        ver: cachedRT.ver,
        clientId,
        sit: cachedRT.sit,
        userAgent: cachedRT.userAgent,
      });
    }

    // Generate new access token
    const accessToken = await generateJWTToken<AccessTokenClaims>({
      audience: "abiemarket",
      type: "at",
      claims: {
        sit: !isGuestToken ? cachedRT.sit : `${decodedResult.payload.sit}`,
        name: !isGuestToken ? cachedRT.name : "Guest",
        sub: !isGuestToken ? cachedRT.userId : `${decodedResult.payload.sub}`,
        roles: !isGuestToken ? cachedRT.roles : ["guest"],
      },
      maxAge: authConfigsLoader.getConfig().atMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
      ver: decodedResult.payload.ver,
    });

    // Return new access token in the response

    res.status(200).json({
      ...responseDefault,
      result: {
        accessToken: {
          token: accessToken,
          expires: fromDate(authConfigsLoader.getConfig().atMaxAge),
        },
        refreshToken: {
          token: newRefreshToken,
          expires: fromDate(authConfigsLoader.getConfig().rtMaxAge),
        },
        ...(clientProfileUpdated ///return the user profile if it has been updated
          ? {
              user: {
                sub: cachedRT.userId,
                name: cachedRT.name,
                _sot: cachedRT._sot,
                val: cachedRT.val,
                roles: cachedRT.roles,
              },
            }
          : {}),
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
      throw new AppError(authErrorCodes.AUTH_INVALID_REFRESH_TOKEN, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "signout",
        neededActions: ["check the client request"],
        additionalInfo: "Signout attempt failed with no refresh token",
      });
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
      throw new AppError(authErrorCodes.AUTH_INVALID_REFRESH_TOKEN, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "signout",
        neededActions: ["check the client request"],
        additionalInfo: "Signout attempt failed with invalid refresh token",
      });
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
    logger.info(`User ${userId} logged out`);
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
    const { password, name, type, value, code, clientId } = req.body;

    // Check if the value (phone number or email) is already taken
    const isValueTaken = await UserSchema.findOne({ [type]: value });
    if (isValueTaken) {
      // If the value (phone or email) is already taken, throw a 422 Unprocessable Entity error
      if (type === "email") {
        throw new AppError(authErrorCodes.AUTH_SIGNUP_EMAIL_TAKEN, undefined, {
          logLevel: "security",
          errorLogSeverity: "major",
          where: "signup",
          neededActions: ["check the client request"],
          additionalInfo: `Signup attempt failed with  ${type}:${value} already taken`,
        });
      } else {
        throw new AppError(authErrorCodes.AUTH_SIGNUP_PHONE_TAKEN, undefined, {
          logLevel: "security",
          errorLogSeverity: "major",
          where: "signup",
          neededActions: ["check the client request"],
          additionalInfo: `Signup attempt failed with  ${type}:${value} already taken`,
        });
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
    const roles = newUser.roles;
    const sit = nowInSeconds();

    //generate an access token for the user
    const accessToken = await generateJWTToken<AccessTokenClaims>({
      audience: "abiemarket",
      type: "at",
      claims: { sub: newUser._id, roles, name: `${name} `, sit },
      maxAge: authConfigsLoader.getConfig().atMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
      ver: newUser.__v,
    });
    const refreshToken = await generateJWTToken<RefreshTokenClaims>({
      type: "rt",
      audience: "abiemarket",
      claims: { sub: newUser._id, sit },
      maxAge: authConfigsLoader.getConfig().rtMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
      ver: newUser.__v,
    });

    //generate session token
    const sessionToken = await generateJWTToken<SessionTokenClaims>({
      audience: "abiemarket",
      type: "st",
      claims: {
        sit,
        hasStore: newUser.roles.includes("vendor"),
        sub: newUser._id,
        roles,
        _sot: type,
        val: value,
        name: `${name}`,
      },
      maxAge: authConfigsLoader.getConfig().stMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
      ver: newUser.__v,
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
      ver: newUser.__v,
      clientId,
      sit: nowInSeconds(),
      userAgent: req.forwardedUserAgent || "default",
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
        user: {
          sub: newUser._id,
          name: `${newUser.name} `,
          roles: ["shopper"],
          _sot: type,
          val: value,
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
export async function vendorSignin(
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
      throw new AppError(authErrorCodes.AUTH_INVALID_CREDENTIALS, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "sellerSignin",
        neededActions: ["check the client request"],
        additionalInfo: `Signin attempt failed with  ${type}:${value} not found`,
      });
    }
    if (!user.roles.includes("vendor")) {
      throw new AppError(authErrorCodes.AUTH_INVALID_CREDENTIALS, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "sellerSignin",
        neededActions: ["check the client request"],
        additionalInfo: `Signin attempt failed with  ${type}:${value} not a seller`,
      });
    }

    const isPasswordValid = await verifyPassword(password, user.password);
    if (!isPasswordValid) {
      throw new AppError(authErrorCodes.AUTH_INVALID_CREDENTIALS, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "sellerSignin",
        neededActions: ["check the client request"],
        additionalInfo: `Signin attempt failed with  ${type}:${value} invalid password`,
      });
    }

    //get refresh token
    await refreshsSchema.deleteMany({ userId: user._id });
    // Generate access token
    const roles = user.roles;
    const sit = nowInSeconds();

    //create refresh token
    const refreshToken = await generateJWTToken<RefreshTokenClaims>({
      audience: "abiemarket",
      type: "rt",
      claims: { sub: user._id, sit },
      maxAge: authConfigsLoader.getConfig().rtMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
      ver: user.__v,
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
        sit,
        sub: user._id,
        roles,
        name: `${user.name}`,
      },
      maxAge: authConfigsLoader.getConfig().atMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
      ver: user.__v,
    });

    //generate session token
    const sessionToken = await generateJWTToken<SessionTokenClaims>({
      audience: "abiemarket",
      type: "st",
      claims: {
        sit,
        hasStore: user.roles.includes("vendor"),
        sub: user._id,
        roles,
        _sot: type,
        val: value,
        name: `${user.name}`,
      },
      maxAge: authConfigsLoader.getConfig().stMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
      ver: user.__v,
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

        user: {
          sub: user._id,
          name: `${user.name} `,
          roles,
          _sot: type,
          val: value,
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
export async function verifyPasswordResetToken(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { type, value, code } = req.body;

    const user = await userSchema.findOne({ [type]: value });

    if (!user) {
      throw new AppError(authErrorCodes.AUTH_USER_NOT_FOUND, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "resetPassword",
        neededActions: ["check the client request"],
        additionalInfo: `Password reset attempt failed with  ${type}:${value} not found`,
      });
    }

    await verifyVerificationTokenHandler(type, value, code, req);

    //Generate a short reset token
    const resetToken = await generateJWTToken<AccessTokenClaims>({
      audience: "abiemarket",
      type: "at",
      claims: { sub: user._id, sit: nowInSeconds(), roles: [], name: `` },
      maxAge: 600,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
      ver: user.__v,
    });

    // // Hash the password
    // const hashedPassword = await hashPassword(password);

    // // Update user password in the database
    // user.password = hashedPassword;
    // await user.save();
    // For example, you can use the username and password to update the user password in the database

    await verificationsSchema.deleteMany({ verificationType: { type, value } });

    // Return success response
    res.json({
      ...responseDefault,

      result: {
        resetToken,
      },
    });
  } catch (error) {
    // If an error occurs at any point in the try block, call the next middleware function with the error
    next(error);
  }
}

export async function resetPassword(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { password, type, value, resetToken } = req.body;

    const user = await userSchema.findOne({ [type]: value });

    if (!user) {
      throw new AppError(authErrorCodes.AUTH_USER_NOT_FOUND, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "resetPassword",
        neededActions: ["check the client request"],
        additionalInfo: `Password reset attempt failed with  ${type}:${value} not found`,
      });
    }

    const decodedResetToken = await verifyJWTToken<AccessToken>(
      {
        token: resetToken,
        secret: jwtSecretsLoader.getConfig().newJwtSecert,
      },
      jwtSecretsLoader.getConfig().oldJwtSecert
    );

    if (decodedResetToken.type === "error") {
      throw new AppError(authErrorCodes.AUTH_INVALID_RESET_TOKEN, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "resetPassword",
        neededActions: ["check the client request"],
        additionalInfo: `Password reset attempt failed with  ${type}:${value} invalid reset token`,
      });
    }

    if (decodedResetToken.type === "expired") {
      throw new AppError(authErrorCodes.AUTH_TOKEN_EXPIRED, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "resetPassword",
      });
    }

    const { payload } = decodedResetToken;

    if (payload.sub !== user._id.toString()) {
      throw new AppError(authErrorCodes.AUTH_INVALID_RESET_TOKEN, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "resetPassword",
        neededActions: ["check the client request"],
        additionalInfo: `Password reset attempt failed with  ${type}:${value} invalid reset token`,
      });
    }

    const hashedPassword = await hashPassword(password);

    user.password = hashedPassword;
    await user.save();

    // Return success response
    res.json({
      ...responseDefault,
      result: {
        message: "password reset successfully",
      },
    });
  } catch (error) {
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
      throw new AppError(authErrorCodes.AUTH_USER_GRANT_FAIL, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "grant",
        neededActions: ["check the client request"],
        additionalInfo: `User ${sub} cannot be found`,
      });
    }

    const canGrantRole = user.roles.includes(role);

    if (!canGrantRole) {
      throw new AppError(
        authErrorCodes.AUTH_UNAUTHORIZED,
        "User cannot be granted this role",
        {
          logLevel: "security",
          errorLogSeverity: "critical",
          where: "grant",
          neededActions: ["Check this request for Suspecious activities"],
          additionalInfo: `User ${sub} cannot grant ${role} to ${type}:${value} - The Role does not exist on the user`,
        }
      );
    }
    const isPasswordValid = await verifyPassword(password, user.password);

    if (!isPasswordValid) {
      //TODO: Log this as

      throw new AppError(
        authErrorCodes.AUTH_INVALID_CREDENTIALS,
        "Invalid credentials",
        {
          logLevel: "security",
          errorLogSeverity: "critical",
          where: "grant",
          neededActions: [""],
          additionalInfo: `User ${sub} cannot grant ${role} to ${type}:${value} invalid password`,
        }
      );
    }

    roles = [...roles, role];

    // Generate access token
    const accessToken = await generateJWTToken<AccessTokenClaims>({
      audience: "abiemarket",
      type: "at",
      claims: {
        //ATTENTION!!! the below line needs to be resolved
        sit: nowInSeconds(), //this is wrong, the signin Time (sit) should be set from the old refresh token, but there is no way of accessing it from this controller. This needs to be fixed. only signin controller should be setting new signin time (sit)
        sub,
        roles,
        name: `${user.name}`,
      },
      maxAge: 1200,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
      ver: user.__v,
    });

    //generate session token
    const sessionToken = await generateJWTToken<SessionTokenClaims>({
      audience: "abiemarket",
      type: "st",
      claims: {
        hasStore: user.roles.includes("vendor"),
        //ATTENTION!!! the below line needs to be attended to
        sit: nowInSeconds(), //this is wrong, the signin Time (sit) should be set from the old refresh token, but there is no way of accessing it from this controller. This needs to be fixed. only signin controller should be setting new signin time (sit)
        sub,
        roles,
        _sot: type,
        val: value,
        name: `${user.name}`,
      },
      maxAge: authConfigsLoader.getConfig().stMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
      ver: user.__v,
    });

    res.status(201).json({
      ...responseDefault,
      result: {
        accessToken: {
          token: accessToken,
          expires: fromDate(1200),
        },
        user: {
          sub,
          name: `${user.name}`,
          roles,
          _sot: type,
          val: value,
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
      throw new AppError(authErrorCodes.AUTH_INVALID_SESSION_TOKEN, "", {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "session",
        neededActions: ["Check for Suspecious Activities"],
        additionalInfo: `Invalid session token`,
      });
    }

    if (decodedResult.type === "expired") {
      await refreshTokensSchema.findOneAndUpdate(
        {
          sessionToken,
        },
        { revoked: true }
      );
      throw new AppError(
        authErrorCodes.AUTH_TOKEN_EXPIRED,
        "session token expired",
        {
          logLevel: "security",
          errorLogSeverity: "major",
          where: "session",
          neededActions: [""],
          additionalInfo: `session token expired`,
        }
      );
    }

    const { payload } = decodedResult;

    const newSessionToken = await generateJWTToken<SessionTokenClaims>({
      audience: "abiemarket",
      type: "st",
      claims: {
        sit: payload.sit,
        hasStore: payload.hasStore,
        sub: payload.sub,
        roles: payload.roles,
        _sot: payload._sot,
        val: payload.val,
        name: payload.name,
      },
      maxAge: authConfigsLoader.getConfig().stMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
      ver: payload.ver || 1,
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
export async function makeUserVendor(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { userId } = req.body;
    const user = await userSchema.findById(userId);

    if (!user) {
      throw new AppError(authErrorCodes.AUTH_USER_NOT_FOUND, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "makeUserSeller",
        neededActions: ["check for suspecious activity"],
        additionalInfo: `User ${userId} not found while granting seller permission`,
      });
    }

    if (user.roles.includes("vendor")) {
      throw new AppError(authErrorCodes.AUTH_USER_ALREADY_VENDOR, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "makeUserVendor",
        additionalInfo: `User ${userId} not found while granting vendor permission`,
      });
    }

    user.roles.push("vendor");

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
      throw new AppError(
        authErrorCodes.AUTH_BAD_REQUEST,
        "client verification token is required",
        {
          logLevel: "security",
          errorLogSeverity: "major",
          where: "generateClientToken",
          neededActions: ["check for suspecious activity"],
          additionalInfo: `Client Verification token is required`,
        }
      );
    }

    if (!platform) {
      throw new AppError(
        authErrorCodes.AUTH_BAD_REQUEST,
        "platform is required",
        {
          logLevel: "security",
          errorLogSeverity: "major",
          where: "makeUserSeller",
          neededActions: ["check for suspecious activity"],
          additionalInfo: `Platform Not provide`,
        }
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
      throw new AppError(
        authErrorCodes.AUTH_INVALID_VERIFICATION_TOKEN,
        undefined,
        {
          logLevel: "security",
          errorLogSeverity: "major",
          where: "generateClienttoken",
          neededActions: ["check for suspecious activities"],
          additionalInfo: `Invalid Client Verification Token`,
        }
      );
    } else if (
      platform === "android" &&
      verificationToken !== androidVerificationToken
    ) {
      throw new AppError(
        authErrorCodes.AUTH_INVALID_VERIFICATION_TOKEN,
        undefined,
        {
          logLevel: "security",
          errorLogSeverity: "major",
          where: "generateClientToken",
          neededActions: ["check for suspecious activity"],
          additionalInfo: `Invalid Client Verification Token`,
        }
      );
    } else if (
      platform === "ios" &&
      verificationToken !== iosVerificationToken
    ) {
      throw new AppError(
        authErrorCodes.AUTH_INVALID_VERIFICATION_TOKEN,
        undefined,
        {
          logLevel: "security",
          errorLogSeverity: "major",
          where: "generateClientToken",
          neededActions: ["check for suspecious activity"],
          additionalInfo: `Invalid Client Verification Token`,
        }
      );
    }

    const clientToken = await generateJWTToken<ClientTokenClaims>({
      audience: "abiemarket",
      type: "ct",
      claims: {
        platform,
      },
      maxAge: authConfigsLoader.getConfig().ctMaxAge,
      secret: jwtSecretsLoader.getConfig().newJwtSecert,
      ver: 1,
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

    const tokenType = type as TokenTypes;

    const decodedResult = await verifyJWTToken(
      {
        secret: jwtSecretsLoader.getConfig().newJwtSecert,
        token,
      },
      jwtSecretsLoader.getConfig().oldJwtSecert
    );

    if (decodedResult.type === "error") {
      throw new AppError(
        authErrorCodes.AUTH_INVALID_TOKEN,
        `invalid ${tokenType} token`,
        {
          logLevel: "security",
          errorLogSeverity: "critical",
          where: "verifyToken",
          neededActions: ["check for suspecious activity"],
          additionalInfo: `Invalid access token -${decodedResult.error}-tokenType:${tokenType}. This seems like a security threat and should be investigated`,
        }
      );
    }

    if (decodedResult.type === "expired") {
      // logger.security(`Expired ${tokenType} token`, {
      //   action: "verifyToken",
      //   requestId: req.requestId,
      //   userIdentifier: token,
      //   ipAddress: req.forwardedForIp,
      //   endpoint: req.path,
      //   httpMethod: req.method,
      //   userAgent: req.forwardedUserAgent,
      //   errorCode: authErrorCodes.AUTH_TOKEN_EXPIRED,
      //   statusCode: authErrorCodesMap[authErrorCodes.AUTH_TOKEN_EXPIRED].status,
      // });
      throw new AppError(
        authErrorCodes.AUTH_TOKEN_EXPIRED,
        `${tokenType} token expired`,
        {
          logLevel: "warn",
          errorLogSeverity: "major",
          where: "verifyToken",
          additionalInfo: `expired token`,
        }
      );
    }

    if (decodedResult.payload.type !== tokenType) {
      throw new AppError(
        authErrorCodes.AUTH_INVALID_TOKEN,
        `invalid ${tokenType} token`,
        {
          logLevel: "security",
          errorLogSeverity: "major",
          where: "verifyToken",
          neededActions: ["check for suspecious activity"],
          additionalInfo: `Invalid ${tokenType} token. Expected ${tokenType} token but got ${decodedResult.payload.type} token, seems like an attacker is trying to use a different token type`,
        }
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
      throw new AppError(
        authErrorCodes.AUTH_INVALID_TOKEN,
        `invalid ${tokenType} token`,
        {
          logLevel: "security",
          errorLogSeverity: "major",
          where: "verifyToken",
          neededActions: ["check for suspecious activity"],
          additionalInfo: `Invalid ${tokenType} token`,
        }
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

    res.status(200).json({
      ...responseDefault,
      result: {},
      message: "verification token verified",
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Get all active sessions (devices) the user is currently logged into
 * @param req - The request object
 * @param res - The response object
 * @param next - The next function
 * @returns A JSON response with all active sessions
 */
export async function getActiveSessions(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.user.sub;

    // Find all active refresh tokens for this user
    const activeSessions = await refreshsSchema
      .find(
        {
          userId: userId,
          revoked: false,
          expires: { $gt: new Date() }, // Only return non-expired tokens
        },
        {
          _id: 1,
          clientId: 1,
          userAgent: 1,
          created: 1,
          expires: 1,
          sit: 1,
        }
      )
      .lean();

    if (!activeSessions || activeSessions.length === 0) {
      return res.json({
        ...responseDefault,
        result: {
          sessions: [],
          currentSession: req.forwardedUserAgent || "Unknown",
        },
      });
    }

    // Map the sessions to a more user-friendly format
    const sessions = activeSessions.map((session) => ({
      id: session._id,
      clientId: session.clientId,
      device: session.userAgent,
      createdAt: session.created,
      expiresAt: session.expires,
      signInAt: session.sit,
      isCurrentDevice: session.userAgent === req.forwardedUserAgent,
    }));

    res.json({
      ...responseDefault,
      result: {
        sessions,
        currentSession: req.forwardedUserAgent || "Unknown",
      },
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Log out from all devices or a specific device
 * @param req - The request object
 * @param res - The response object
 * @param next - The next function
 * @returns A JSON response indicating success
 */
export async function logoutFromDevices(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.user.sub;
    const { clientId, allDevices, currentDeviceId } = req.body;

    // Validate request parameters
    if (!allDevices && !clientId && !currentDeviceId) {
      throw new AppError(
        authErrorCodes.AUTH_BAD_REQUEST,
        "You must specify either clientId, or allDevices=true",
        {
          logLevel: "warn",
          errorLogSeverity: "minor",
          where: "logoutFromDevices",
          additionalInfo: "Invalid request parameters",
        }
      );
    }

    let result;

    // Logout from all devices
    if (allDevices) {
      //logout from all devices except the current one
      result = await refreshsSchema.deleteMany({
        userId: userId,
        clientId: { $ne: currentDeviceId },
      });

      logger.info(`User ${userId} logged out from all devices`);
    }
    // Logout from a specific device by clientId
    else {
      result = await refreshsSchema.deleteMany({
        userId: userId,
        clientId: clientId,
      });

      if (result.deletedCount === 0) {
        throw new AppError(
          authErrorCodes.AUTH_ADDRESS_NOT_FOUND,
          "No active sessions found for this client",
          {
            logLevel: "warn",
            errorLogSeverity: "minor",
            where: "logoutFromDevices",
            additionalInfo: "No sessions found for client",
          }
        );
      }

      logger.info(`User ${userId} logged out from client ${clientId}`);
    }

    res.json({
      ...responseDefault,
      result: {
        message: allDevices
          ? "Logged out from all devices"
          : "Logged out from specified client",
        sessionCount: result.deletedCount || 0,
      },
    });
  } catch (error) {
    next(error);
  }
}
