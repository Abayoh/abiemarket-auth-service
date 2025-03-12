import Joi from "joi";

// Schema for signin endpoint
export const signinSchema = Joi.object({
  type: Joi.string().valid("email", "phone").required(),
  value: Joi.string().required(),
  password: Joi.string().required(),
  clientId: Joi.string().required(),
});

// Schema for getGuestTokens endpoint
export const guestTokensSchema = Joi.object({
  guestId: Joi.string().optional(),
});

// Schema for renewAccessToken endpoint
export const renewAccessTokenSchema = Joi.object({
  refreshToken: Joi.string().required(),
});

// Schema for signout endpoint
export const signoutSchema = Joi.object({
  refreshToken: Joi.string().required(),
});

// Schema for revokeToken endpoint
export const revokeTokenSchema = Joi.object({
  token: Joi.string().required(),
});

// Schema for signup endpoint - this already exists in the code as signUpSchema
// but including it here for completeness
export const signupSchema = Joi.object({
  password: Joi.string().required(),
  name: Joi.string().required(),
  type: Joi.string().valid("email", "phone").required(),
  value: Joi.string().required(),
  code: Joi.string().required(),
  clientId: Joi.string().required(),
});

// Schema for vendorSignin endpoint
export const vendorSigninSchema = Joi.object({
  type: Joi.string().valid("email", "phone").required(),
  value: Joi.string().required(),
  password: Joi.string().required(),
  clientId: Joi.string().required(),
});

// Schema for sendVerificationToken endpoint
export const sendVerificationTokenSchema = Joi.object({
  type: Joi.string().valid("email", "phone").required(),
  value: Joi.string().required(),
});

// Schema for verifyPasswordResetToken endpoint
export const verifyPasswordResetTokenSchema = Joi.object({
  type: Joi.string().valid("email", "phone").required(),
  value: Joi.string().required(),
  code: Joi.string().required(),
});

// Schema for resetPassword endpoint
export const resetPasswordSchema = Joi.object({
  password: Joi.string().required(),
  type: Joi.string().valid("email", "phone").required(),
  value: Joi.string().required(),
  resetToken: Joi.string().required(),
});

// Schema for sendPasswordResetToken endpoint
export const sendPasswordResetTokenSchema = Joi.object({
  type: Joi.string().valid("email", "phone").required(),
  value: Joi.string().required(),
});

// Schema for grant endpoint
export const grantSchema = Joi.object({
  type: Joi.string().valid("email", "phone").required(),
  value: Joi.string().required(),
  password: Joi.string().required(),
  role: Joi.string().required(),
});

// Schema for session endpoint
export const sessionSchema = Joi.object({
  sessionToken: Joi.string().required(),
});

// Schema for makeUserVendor endpoint
export const makeUserVendorSchema = Joi.object({
  userId: Joi.string().required(),
});

// Schema for generateClientToken endpoint
export const generateClientTokenSchema = Joi.object({
  verificationToken: Joi.string().required(),
  platform: Joi.string().valid("web", "android", "ios").required(),
});

// Schema for verifyToken endpoint
export const verifyTokenSchema = Joi.object({
  token: Joi.string().required(),
  type: Joi.string().valid("at", "rt", "st", "ct").required(),
});

// Schema for verifyOTP endpoint
export const verifyOTPSchema = Joi.object({
  code: Joi.string().required(),
  type: Joi.string().valid("email", "phone").required(),
  value: Joi.string().required(),
});
