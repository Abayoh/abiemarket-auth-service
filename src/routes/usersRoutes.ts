import { Router } from "express";
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
  addUserRole,
  removeUserRole,
} from "../controllers/usersController";
import auth from "../middleware/authorize";

import {
  changeUserEmailSchema,
  changeUserPasswordSchema,
  changeUserPhoneSchema,
  newUserAddressSchema,
  verifyUserEmailSchema,
  verifyUserPhoneSchema,
  changeUserNameSchema,
  logoutFromDevicesSchema,
} from "../models/users/userRequestVerificationSchemas";
import { addUserRoleSchema } from "../middleware/userValidationRequestSchema";

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
  .patch(
    "/username",
    auth,
    validateSchema({ schema: changeUserNameSchema }),
    changeUserName
  )
  .patch(
    "/:userId/roles/add",
    auth,
    validateSchema({ schema: addUserRoleSchema }),
    addUserRole
  )
  .patch(
    "/:userId:/roles/remove",
    auth,
    validateSchema({ schema: addUserRoleSchema }),
    removeUserRole
  );

export default router;
