import { Router } from "express";
import can from "../middleware/can";
import validateSchema from "../middleware/validateSchema";

import {
  addUserAddress,
  changeUserEmail,
  changeUserPassword,
  changeUserPhone,
  deleteUserAddress,
  getUserAddress,
  updateUserAddress,
  verifyUserEmail,
  verifyUserPhone,
  getUserAddresses,
  setAddressAsDefault,
  getUserInfo,
  changeUserName,
} from "../controllers/usersController";
import auth from "../middleware/authorize";

import {
  changeUserEmailSchema,
  changeUserPasswordSchema,
  changeUserPhoneSchema,
  newUserAddressSchema,
  verifyUserEmailSchema,
  verifyUserPhoneSchema,
} from "../models/users/userRequestVerificationSchemas";

const router = Router();

router
  .post(
    "/addresses",
    auth,
    validateSchema({ schema: newUserAddressSchema }),
    addUserAddress
  )
  .patch(
    "/change-email",
    auth,
    validateSchema({ schema: changeUserEmailSchema }),
    changeUserEmail
  )
  .patch(
    "/change-password",
    auth,
    validateSchema({ schema: changeUserPasswordSchema }),
    changeUserPassword
  )
  .patch(
    "/change-phone",
    auth,
    validateSchema({ schema: changeUserPhoneSchema }),
    changeUserPhone
  )
  .delete("/addresses/:addressId", auth, deleteUserAddress)
  .get("/addresses/get-addr", auth, getUserAddress)
  .get("/addresses", auth, getUserAddresses)
  .put(
    "/addresses/:addressId",
    auth,
    validateSchema({ schema: newUserAddressSchema }),
    updateUserAddress
  )
  .patch(
    "/email/verify",
    auth,
    validateSchema({ schema: verifyUserEmailSchema }),
    verifyUserEmail
  )
  .patch(
    "/phone/verify",
    auth,
    validateSchema({ schema: verifyUserPhoneSchema }),
    verifyUserPhone
  )
  .patch("/addresses/:addressId/default", auth, setAddressAsDefault)
  .get("/info", auth, getUserInfo)
  .patch("/username", auth, changeUserName);

export default router;
