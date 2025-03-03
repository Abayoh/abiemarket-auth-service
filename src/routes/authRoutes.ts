import { Router } from "express";

import {
  getCsrfToken,
  renewAccessToken,
  resetPassword,
  sendVerificationToken,
  signin,
  signup,
  vendorSignin,
  sellerSignup,
  revokeToken,
  signout,
  sendPasswordResetToken,
  grant,
  session,
  makeUserVendor,
  generateClientToken,
  verifyToken,
  verifyOTP,
  getGuestTokens,
  verifyPasswordResetToken,
} from "../controllers/authController";

const router = Router();

router
  .post("/signin", signin)
  .post("/signup/verify", signup)
  .post("/seller/signin", vendorSignin)
  .post("/seller/signup", sellerSignup)
  .post("/reset-password", resetPassword)
  .post("/pwd-reset-token/send", sendPasswordResetToken)
  .post("/pwd-reset-token/verify", verifyPasswordResetToken)
  .post("/revoke", revokeToken)
  .post("/renew", renewAccessToken)
  .post("/signout", signout)
  .post("/verification-token/send", sendVerificationToken)
  .post("/grant", grant)
  .get("/csrf", getCsrfToken)
  .post("/session", session)
  .post("/make-user-seller", makeUserVendor)
  .post("/generate-client-token", generateClientToken)
  .post("/verify-token", verifyToken)
  .post("/verify-otp", verifyOTP)
  .post("/guest-tokens", getGuestTokens);

export default router;
