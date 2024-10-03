import { Router } from "express";

import {
  getCsrfToken,
  renewAccessToken,
  resetPassword,
  sendVerificationToken,
  signin,
  signup,
  sellerSignin,
  sellerSignup,
  revokeToken,
  signout,
  sendPasswordResetToken,
  grant,
  session,
  makeUserSeller,
  generateClientToken,
  verifyToken,
  verifyOTP,
} from "../controllers/authController";

const router = Router();

router
  .post("/signin", signin)
  .post("/signup/verify", signup)
  .post("/seller/signin", sellerSignin)
  .post("/seller/signup", sellerSignup)
  .post("/reset-password", resetPassword)
  .post("/pwd-reset-token/send", sendPasswordResetToken)
  .post("/revoke", revokeToken)
  .post("/renew", renewAccessToken)
  .post("/signout", signout)
  .post("/verification-token/send", sendVerificationToken)
  .post("/grant", grant)
  .get("/csrf", getCsrfToken)
  .post("/session", session)
  .post("/make-user-seller", makeUserSeller)
  .post("/generate-client-token", generateClientToken)
  .post("/verify-token", verifyToken)
  .post("/verify-otp", verifyOTP);

export default router;
