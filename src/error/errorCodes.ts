export interface ErrorStatusAndMessage {
  status: number;
  message: string;
}

export interface ErrorCodeToStatusAndMessageMap {
  [key: string]: ErrorStatusAndMessage;
}

export const authErrorCodes = {
  AUTH_INVALID_CREDENTIALS: "AUTH_INVALID_CREDENTIALS",
  AUTH_TOKEN_EXPIRED: "AUTH_TOKEN_EXPIRED",
  AUTH_SIGNUP_EMAIL_TAKEN: "AUTH_SIGNUP_EMAIL_TAKEN",
  AUTH_SIGNUP_PHONE_TAKEN: "AUTH_SIGNUP_PHONE_TAKEN",
  AUTH_TOO_MANY_VERIFICATION_REQUEST: "AUTH_TOO_MANY_VERIFICATION_REQUEST",
  AUTH_INVALID_REFRESH_TOKEN: "AUTH_INVALID_REFRESH_TOKEN",
  AUTH_INVALID_TOKEN: "AUTH_INVALID_TOKEN",
  AUTH_INVALID_SESSION_TOKEN: "AUTH_INVALID_ACCESS_TOKEN",
  AUTH_USER_NOT_FOUND: "AUTH_USER_NOT_FOUND",
  AUTH_VERIFICATION_CODE_EXPIRED: "AUTH_VERIFICATION_CODE_EXPIRED",
  AUTH_VERIFICATION_CODE_INVALID: "AUTH_VERIFICATION_CODE_INVALID",
  AUTH_CODE_MAX_TRIES: "AUTH_CODE_MAX_TRIES",
  AUTH_VERIF_EMAIL_FAIL: "AUTH_VERIF_EMAIL_FAIL",
  AUTH_REQ_VALIDATION_ERROR: "AUTH_REQ_VALIDATION_ERROR",
  AUTH_USER_GRANT_FAIL: "AUTH_USER_GRANT_FAIL",
  AUTH_UNAUTHORIZED: "AUTH_UNAUTHORIZED",
  AUTH_RT_CACHED_FAILED: "AUTH_RT_CACHED_FAILED",
  AUTH_PASSWORD_CHANGE_FAIL: "AUTH_PASSWORD_CHANGE_FAIL",
  AUTH_INTERNAL_SERVER_ERROR: "AUTH_INTERNAL_SERVER_ERROR",
  AUTH_ADDRESS_NOT_FOUND: "AUTH_ADDRESS_NOT_FOUND",
  AUTH_EMAIL_CONFLICT: "AUTH_EMAIL_CONFLICT",
  AUTH_PHONE_CONFLICT: "AUTH_PHONE_CONFLICT",
  AUTH_ROUTE_NOT_FOUND: "AUTH_ROUTE_NOT_FOUND",
  AUTH_EMAIL_VERI_FAIL: "AUTH_EMAIL_VERI_FAIL",
  AUTH_PHONE_VERI_FAIL: "AUTH_PHONE_VERI_FAIL",
  AUTH_TOO_MANY_VERI_REQ: "AUTH_TOO_MANY_VERI_REQ",
  AUTH_DB_ERROR: "AUTH_DB_ERROR",
  AUTH_DB_VALIDATION_ERROR: "AUTH_DB_VALIDATION_ERROR",
  AUTH_UNKNOWN_ERROR: "AUTH_UNKNOWN_ERROR",
  AUTH_USER_ALREADY_VENDOR: "AUTH_USER_ALREADY_VENDOR",
  AUTH_INVALID_VERIFICATION_TOKEN: "AUTH_INVALID_VERIFICATION_TOKEN",
  AUTH_BAD_REQUEST: "AUTH_BAD_REQUEST",
  AUTH_INVALID_CLIENT_TOKEN: "AUTH_INVALID_CLIENT_TOKEN",
  AUTH_ROLE_CONFLICT: "AUTH_ROLE_CONFLICT",
  AUTH_ROLE_NOT_FOUND: "AUTH_ROLE_NOT_FOUND",
  AUTH_INVALID_GUEST_ID: "AUTH_INVALID_GUEST_ID",
};

const authErrorCodesMap: ErrorCodeToStatusAndMessageMap = {
  AUTH_INVALID_CREDENTIALS: {
    message: "Please check your credentials and try again",
    status: 401,
  },
  AUTH_SIGNUP_EMAIL_TAKEN: {
    message: "This email is already in use",
    status: 409,
  },
  AUTH_SIGNUP_PHONE_TAKEN: {
    message: "This phone number is already in use",
    status: 409,
  },
  AUTH_TOO_MANY_VERIFICATION_REQUEST: {
    message:
      "please wait for cooldown period to expire (too many verification request)",
    status: 429,
  },
  AUTH_INVALID_REFRESH_TOKEN: {
    message: "Invalid refresh token",
    status: 401,
  },
  AUTH_INVALID_ACCESS_TOKEN: {
    message: "Invalid access token",
    status: 401,
  },

  AUTH_INVALID_SESSION_TOKEN: {
    message: "Invalid session token",
    status: 401,
  },

  AUTH_USER_NOT_FOUND: {
    message: "The user for the specified credential do not exist",
    status: 404,
  },
  AUTH_VERIFICATION_CODE_EXPIRED: {
    message: "Your verification code has expired",
    status: 400,
  },

  AUTH_VERIFICATION_CODE_INVALID: {
    message: "The verification code you entered is incorrect. Please try again",
    status: 400,
  },
  AUTH_CODE_MAX_TRIES: {
    message:
      "You've exceeded the maximum number of verification code attempts. Please Send a new Code",
    status: 400,
  },
  AUTH_VERIF_EMAIL_FAIL: {
    message: "Something went wrong while sending email verification code",
    status: 500,
  },
  AUTH_REQ_VALIDATION_ERROR: {
    message: "request validation error",
    status: 422,
  },
  AUTH_USER_GRANT_FAIL: {
    message: "user grant failed! There is no such user",
    status: 401,
  },
  AUTH_UNAUTHORIZED: {
    message: "unauthorize",
    status: 401,
  },
  AUTH_TOKEN_EXPIRED: {
    message: "",
    status: 400,
  },
  AUTH_RT_CACHED_FAILED: {
    message: "refresh token was not stored",
    status: 500,
  },
  AUTH_INTERNAL_SERVER_ERROR: {
    message: "",
    status: 500,
  },
  AUTH_ADDRESS_NOT_FOUND: {
    message: "An error occurs while deleting user address",
    status: 404,
  },
  AUTH_PHONE_CONFLICT: {
    message: "User with this phone number already exist",
    status: 400,
  },
  AUTH_EMAIL_CONFLICT: {
    message: "User with this email already exist",
    status: 400,
  },
  AUTH_ROUTE_NOT_FOUND: {
    message: "route not found",
    status: 404,
  },
  AUTH_EMAIL_VERI_FAIL: {
    status: 500,
    message: "Email Verification request could not be sent",
  },
  AUTH_PHONE_VERI_FAIL: {
    message: "Phone Verification request could not be sent ",
    status: 500,
  },

  AUTH_TOO_MANY_VERI_REQ: {
    message: "Too many verifications request sent",
    status: 429,
  },
  AUTH_DB_ERROR: {
    message: "Database Error",
    status: 500,
  },
  AUTH_DB_VALIDATION_ERROR: {
    message: "Database Validation Error",
    status: 400,
  },
  AUTH_UNKNOWN_ERROR: {
    message: "something went wrong",
    status: 500,
  },
  AUTH_USER_ALREADY_VENDOR: {
    message: "User is already a seller",
    status: 400,
  },
  AUTH_INVALID_VERIFICATION_TOKEN: {
    message: "Unauthorized",
    status: 401,
  },
  AUTH_BAD_REQUEST: {
    message: "",
    status: 400,
  },
  AUTH_INVALID_CLIENT_TOKEN: {
    message: "Invalid client token",
    status: 401,
  },
  AUTH_INVALID_TOKEN: {
    message: "Invalid token",
    status: 401,
  },
  AUTH_ROLE_CONFLICT: {
    message: "User already has this role",
    status: 400,
  },
  AUTH_ROLE_NOT_FOUND: {
    message: "Role not found",
    status: 404,
  },
  AUTH_INVALID_GUEST_ID: {
    message: "Invalid guest id",
    status: 400,
  },
};

export const generalErrorCodes = {
  INTERNAL_ERROR: "INTERNAL_ERROR",
  NOT_FOUND: "NOT_FOUND",
  BAD_REQUEST: "BAD_REQUEST",
};
const generalErrorCodesMap: ErrorCodeToStatusAndMessageMap = {
  INTERNAL_ERROR: {
    message: "Internal server error",
    status: 500,
  },
  NOT_FOUND: {
    message: "Not found",
    status: 404,
  },
  BAD_REQUEST: {
    message: "Bad request",
    status: 400,
  },
};

export const mongoDbErrorCode = {
  DB_VALIDATION_ERROR: "DB_VALIDATION_ERROR",
  DUPLICATE_KEY_ERROR: "DUPLICATE_KEY_ERROR",
  DB_CONNECTION_ERROR: "DB_CONNECTION_ERROR",
  DB_ERROR: "DB_ERROR",
};

const dbErrorCodeMap: ErrorCodeToStatusAndMessageMap = {
  DB_VALIDATION_ERROR: {
    message: "Database validation error",
    status: 400,
  },
  DUPLICATE_KEY_ERROR: {
    message: "Duplicate key error",
    status: 400,
  },
  DB_CONNECTION_ERROR: {
    message: "Database connection error",
    status: 500,
  },
  DB_ERROR: {
    message: "Database error",
    status: 500,
  },
};

export const mongooseErrorCodes = {};

const appErrorMap = {
  ...authErrorCodesMap,
  ...generalErrorCodesMap,
  ...dbErrorCodeMap,
} as ErrorCodeToStatusAndMessageMap;

export default appErrorMap;
