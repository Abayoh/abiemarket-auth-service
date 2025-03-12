import {
  VerificationToken,
  VerificationTokenType,
} from "../models/verificationTokens";

export interface JWTDecodeParams {
  /** The NextAuth.js issued JWT to be decoded */
  token?: string;
  /** The secret used to decode the NextAuth.js issued JWT. */
  secret: string;
}

export type TokenTypes = "at" | "rt" | "st" | "ct";

export interface TokenParams<
  T extends
    | AccessTokenClaims
    | RefreshTokenClaims
    | SessionTokenClaims
    | ClientTokenClaims
> {
  /**
   * The custom Claims for Access token if enabled
   */
  claims: T;
  /**
   * The  Private Key used to sign the Access
   * Token should be base64  encoded string
   * */
  secret: string;

  /**
   * The audience claim is used to identify the intended recipient of the JWT.
   * example@beak8.com
   */
  audience: string;

  /**
   * The maximum age of the Beak8 issued access token in second
   *
   */

  maxAge: number;

  /**
   * Token type
   */
  type: TokenTypes;

  /** The version of the token */
  ver: number;
}

export interface AccessTokenClaims {
  sit: number;
  sub: string;
  roles: string[];
  name: string;
}

export interface SessionTokenClaims {
  /** */
  sit: number;
  hasStore: boolean;
  name: string;
  sub: string;
  roles: string[];
  _sot: string;
  val: string;
}

export interface RefreshTokenClaims {
  /** The subject of the JWT. */
  sit: number;
  sub: string;
}

export interface ClientTokenClaims {
  platform: string;
}

export interface Token {
  /** The issuer of the JWT. */
  iss: string;
  /** The audience of the JWT. */
  aud: string;
  /** The time the JWT was issued. */
  iat: number;
  /** The JWT ID. */
  jti: string;
  /** The expiration time of the JWT. */
  exp: number;
  /** The type of token at, rt, st, ct */
  type: TokenTypes;
  /** The version of the token */
  ver: number;
}

export interface RefreshToken extends Token, RefreshTokenClaims {}

export interface ClientToken extends Token, ClientTokenClaims {}

export interface AccessToken extends Token, AccessTokenClaims {}

export interface SessionToken extends Token, SessionTokenClaims {}

export interface GenerateVerificationTokenParams {
  /**
   * The maximum age of  the Token in second
   */
  maxAge: number;
  /**
   * The type of the Token
   * @param value The value of the type (email, phone)
   * @param type The type of the token
   * */
  type: VerificationTokenType;
}

export interface CheckVerificationTokenParams {
  /**
   * The confirmation token from the database to verify.
   * */
  token: VerificationToken;
  /**
   * The confirmation code entered by the user.
   * */
  code: string;
}

export type ValidationMessages =
  | "invalid-code"
  | "code-expired"
  | "max-request-reached"
  | "validation-attempts-exceeded";
