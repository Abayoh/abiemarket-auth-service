import { Router } from "express";
import validateSchema from "../middleware/validateSchema";
import * as schemas from "./authRoutesJoiSchema";

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
  .post("/signin", validateSchema({ schema: schemas.signinSchema }), signin)
  .post(
    "/signup/verify",
    validateSchema({ schema: schemas.signupSchema }),
    signup
  )
  .post(
    "/seller/signin",
    validateSchema({ schema: schemas.vendorSigninSchema }),
    vendorSignin
  )
  .post(
    "/seller/signup",
    validateSchema({ schema: schemas.signupSchema }),
    sellerSignup
  )
  .post(
    "/reset-password",
    validateSchema({ schema: schemas.resetPasswordSchema }),
    resetPassword
  )
  .post(
    "/pwd-reset-token/send",
    validateSchema({ schema: schemas.sendPasswordResetTokenSchema }),
    sendPasswordResetToken
  )
  .post(
    "/pwd-reset-token/verify",
    validateSchema({ schema: schemas.verifyPasswordResetTokenSchema }),
    verifyPasswordResetToken
  )
  .post(
    "/revoke",
    validateSchema({ schema: schemas.revokeTokenSchema }),
    revokeToken
  )
  .post(
    "/renew",
    validateSchema({ schema: schemas.renewAccessTokenSchema }),
    renewAccessToken
  )
  .post("/signout", validateSchema({ schema: schemas.signoutSchema }), signout)
  .post(
    "/verification-token/send",
    validateSchema({ schema: schemas.sendVerificationTokenSchema }),
    sendVerificationToken
  )
  .post("/grant", validateSchema({ schema: schemas.grantSchema }), grant)
  .get("/csrf", getCsrfToken)
  .post("/session", validateSchema({ schema: schemas.sessionSchema }), session)
  .post(
    "/make-user-seller",
    validateSchema({ schema: schemas.makeUserVendorSchema }),
    makeUserVendor
  )
  .post(
    "/generate-client-token",
    validateSchema({ schema: schemas.generateClientTokenSchema }),
    generateClientToken
  )
  .post(
    "/verify-token",
    validateSchema({ schema: schemas.verifyTokenSchema }),
    verifyToken
  )
  .post(
    "/verify-otp",
    validateSchema({ schema: schemas.verifyOTPSchema }),
    verifyOTP
  )
  .post(
    "/guest-tokens",
    validateSchema({ schema: schemas.guestTokensSchema }),
    getGuestTokens
  );

export default router;
