import Joi from "joi";
import { userRoles } from "../models/users/userSchema";

export const addUserRoleSchema = Joi.object({
  role: Joi.string()
    .valid(...userRoles)
    .required(),
});
