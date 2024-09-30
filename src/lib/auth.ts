import { SignJWT, importPKCS8, EncryptJWT, jwtDecrypt } from "jose";
//@ts-ignore
import { v4 as uuid } from "uuid";
import crypto from "crypto";
import type {
  JWTDecodeParams,
  TokenParams,
  RefreshToken,
  GenerateVerificationTokenParams,
  AccessToken,
  SessionToken,
  AccessTokenClaims,
  RefreshTokenClaims,
  SessionTokenClaims,
  ClientTokenClaims,
  ClientToken,
} from "./types";
import { fromDate, hasExpired, nowInSeconds } from "../utils";

import hkdf from "@panva/hkdf";

import bcrypt from "bcrypt";
import { VerificationToken } from "../models/verificationTokens";
import nodemailer from "nodemailer";
import { CustomError } from "./error";
import twilio from "twilio";
import { authErrorCodes } from "./errorCodes";

export * from "./types";

import {
  twilioSecrets,
  emailSecrets,
  authConfigsLoader,
} from "../config/configurations";

/** Issues a RefreshToken. By default, the RefreshToken is encrypted using "A256GCM". */
export async function generateJWTToken<
  T extends
    | AccessTokenClaims
    | RefreshTokenClaims
    | SessionTokenClaims
    | ClientTokenClaims
>(params: TokenParams<T>) {
  const { claims, secret, maxAge, type } = params;
  const encryptionSecret = await getDerivedEncryptionKey(secret);
  return await new EncryptJWT({ ...claims, type })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt(nowInSeconds())
    .setIssuer("beak8.com")
    .setExpirationTime(nowInSeconds() + maxAge)
    .setJti(uuid())
    .encrypt(encryptionSecret);
}

/** Decodes a NextAuth.js issued JWT. */
export async function verifyJWTToken<
  T extends RefreshToken | AccessToken | SessionToken | ClientToken
>(params: JWTDecodeParams, oldSecret: string): Promise<DecodeResult<T>> {
  const { token, secret } = params;
  try {
    if (!token) {
      return { type: "error", error: "no token provided" };
    }

    const encryptionSecret = await getDerivedEncryptionKey(secret);

    const { payload } = await jwtDecrypt(token, encryptionSecret, {
      clockTolerance: 15,
    });

    if (hasExpired(payload?.exp || 0)) {
      return { type: "expired" };
    }

    return { type: "success", payload: payload as unknown as T };
  } catch (error) {
    try {
      if (!token) {
        return { type: "error", error: "no token provided" };
      }
      //try the old secret
      const encryptionSecret = await getDerivedEncryptionKey(oldSecret);

      const { payload } = await jwtDecrypt(token, encryptionSecret, {
        clockTolerance: 15,
      });

      if (hasExpired(payload?.exp || 0)) {
        return { type: "expired" };
      }
    } catch (err) {
      return { type: "error", error };
    }

    return { type: "error", error };
  }
}

type DecodeResult<T> =
  | SuccessDecodeResult<T>
  | ExpiredDecodeResult
  | ErrorDecodeResult;

type SuccessDecodeResult<T> = {
  type: "success";
  payload: T;
};

type ExpiredDecodeResult = {
  type: "expired";
};

type ErrorDecodeResult = {
  type: "error";
  error: any;
};

/**
 * generates a confirmation token to be sent to user email address or phone number
 * @param params
 * @returns generated verification token
 */
export const generateVerificationToken = (
  params: GenerateVerificationTokenParams
): VerificationToken => {
  const tokenValue = crypto.randomBytes(20).toString("hex");
  const code = generateRandomCode();
  const token: VerificationToken = {
    code,
    expires: fromDate(params.maxAge),
    verificationType: params.type,
  };

  return token;
};

/**
 * Checks if a verification token is valid by comparing it to a confirmation code.
 * @param {object} params - the confirmation code entered by the user
 * @param {string} params.userCode - the confirmation code entered by the user
 * @param {string} params.cachedCodes - the persisted codes.
 * @param {string} params.expires - The expiry time for the token.
 * @param {number} params.validationAttempts - The number of times the user has attempted to validate the token.
 * @returns {string} - Returns 'expired' if the token has expired, 'invalid' if the code does not match the token, or 'valid' if the token is valid.
 */
export function checkVerificationToken(params: {
  cachedCodes: string[];
  userCode: string;
  expires: Date;
  validationAttempts: number;
}): "expired" | "invalid" | "valid" | "validation-attempts-exceeded" {
  if (hasExpired(params.expires)) return "expired";
  if (
    params.validationAttempts >
    authConfigsLoader.getConfig().maxValidationAttempts
  )
    return "validation-attempts-exceeded";
  if (!params.cachedCodes.includes(params.userCode)) return "invalid";

  return "valid";
}

function generateRandomCode() {
  const code = Math.floor(100000 + Math.random() * 900000);
  return code.toString();
}

async function getDerivedEncryptionKey(secret: string) {
  return await hkdf(
    "sha256",
    secret,
    "",
    "EseyBuy Generated Encryption Key",
    32
  );
}

/**
 * Generates a hash of the password
 * @param password
 * @returns Generated hash
 */
export async function hashPassword(password: string): Promise<string> {
  const saltRounds = 10;
  const salt = await bcrypt.genSalt(saltRounds);
  const hash = await bcrypt.hash(password, salt);
  return hash;
}

/**
 * Verifies the password against the hash
 * @param password password to verify
 * @param hash hash to verify against
 * @returns  true if the password matches the hash
 */
export async function verifyPassword(
  password: string,
  hash: string
): Promise<boolean> {
  return await bcrypt.compare(password, hash);
}

export interface SendEmailVerificationCodeParams {
  email: string;
  code: string;
  isPasswordReset?: boolean;
}

export interface SendSmsVerificationCodeParams {
  phone: string;
  code: string;
  isPasswordReset?: boolean;
}

export async function sendEmailVerificationCode(
  params: SendEmailVerificationCodeParams
): Promise<void> {
  try {
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      service: "gmail",
      auth: {
        user: emailSecrets.getConfig().emailUser,
        pass: emailSecrets.getConfig().emailPass,
      },
      tls: {
        rejectUnauthorized: false,
      },
    });
    const { email, code, isPasswordReset = false } = params;
    const pwdResetHtml = `<p>Reset Your Password with the Below Code:<br> ${code}</p>`;
    const emailHtml = `<p>Verify Your Email with the Below Code:<br> ${code}</p>`;

    const mailOptions = {
      from: emailSecrets.getConfig().emailUser,
      to: email,
      subject: isPasswordReset
        ? "Password Verification Code"
        : "Verify Your Email Address",
      html: isPasswordReset ? pwdResetHtml : emailHtml,
    };

    await transporter.sendMail(mailOptions);
  } catch (error) {
    const err = new CustomError(authErrorCodes.AUTH_VERIF_EMAIL_FAIL);
    err.stack = (error as Error).stack;
    throw err;
  }
}

export async function sendSmsVerificationCode(
  params: SendSmsVerificationCodeParams
): Promise<void> {
  try {
    const accountSid = twilioSecrets.getConfig().twilioAccId;
    const authToken = twilioSecrets.getConfig().twilioAuthToken;
    const client = twilio(accountSid, authToken);
    const { phone, code, isPasswordReset } = params;
    await client.messages.create({
      body: `Your EseyBuy ${
        isPasswordReset ? "Password Reset" : "Phone Number Verification"
      } code is: ${code}`,
      from: "+19783572956",
      to: phone,
    });
  } catch (error) {
    const err = new CustomError(authErrorCodes.AUTH_PHONE_VERI_FAIL);
    err.stack = (error as Error).stack;
    throw err;
  }
}

export function decodeUserClaimsFromBase64String(
  base64String: string
): AccessTokenClaims {
  //verify the string is base64
  if (!Buffer.from(base64String, "base64").toString("base64")) {
    throw new Error("Invalid base64 string");
  }
  const decodedString = Buffer.from(base64String, "base64").toString("ascii");

  //check if is a valid JSON
  try {
    const user = JSON.parse(decodedString) as AccessTokenClaims;

    //check if the user object has the required fields AccessTokenClaims
    if (!user.sub || !user.name || !user.roles) {
      throw new Error("Invalid user object");
    }

    return user;
  } catch (error) {
    throw new Error("Invalid JSON string");
  }
}
