import { verify } from "crypto";
import Joi from "joi";

export const changeUserEmailSchema = Joi.object({
  email: Joi.string().email().required(),
  currentPassword: Joi.string().min(8).required(),
});

export const changeUserPasswordSchema = Joi.object({
  currentPassword: Joi.string().min(8).required(),
  newPassword: Joi.string().min(8).required(),
});

export const changeUserPhoneSchema = Joi.object({
  phone: Joi.string().min(8).required(),
  currentPassword: Joi.string().min(8).required(),
});

export const changeUserNameSchema = Joi.object({
  name: Joi.string().required(),
  currentPassword: Joi.string().min(8).required(),
});

export const newUserAddressSchema = Joi.object({
  add1: Joi.string().required(),
  city: Joi.string().required(),
  state: Joi.string().required(),
  country: Joi.string().required(),
  zip: Joi.string().required(),
  kind: Joi.string().valid(...["home", "work"]),
  phone: Joi.string().required(),
  name: Joi.string().required(),
  landmark: Joi.string().optional(),
  isDefault: Joi.boolean(),
});

export const verifyUserEmailSchema = Joi.object({
  email: Joi.string().required(),
  code: Joi.string().required(),
});

export const verifyUserPhoneSchema = Joi.object({
  phone: Joi.string().required(),
  code: Joi.string().required(),
});

export const verifyUsernameChangeSchema = Joi.object({
  name: Joi.string().required(),
  currentPassword: Joi.string().min(8).required(),
});

export const logoutFromDevicesSchema = Joi.object({
  clientId: Joi.string().optional(),
  allDevices: Joi.boolean().optional(),
  currentDeviceId: Joi.string().optional(),
}).or("clientId", "allDevices", "currentDeviceId");
