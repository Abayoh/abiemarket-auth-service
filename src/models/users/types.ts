import Joi from 'joi';
import mongoose from 'mongoose';
/**
 * Defines a union type for user roles.
 * Possible values include 'shopper' and 'seller'.
 */
export type Roles = 'shopper' | 'seller';

/**
 * Defines a union type for address kinds.
 * Possible values include 'home' and 'work'.
 */
export type AddressKind = 'home' | 'work';

/**
 * Interface representing a user's name.
 */
export interface IName {
  /**
   * The person's first name.
   */
  fname: string;

  /**
   * The person's last name.
   */
  lname: string;

  /**
   * The person's middle name.
   */
  mname?: string;
}

/**
 * Interface representing a postal address.
 */
export interface IAddress {
  /**
 * The unique identifier of the address.
 */
  _id: mongoose.Types.ObjectId;
  /**
   * The recipient's name.
   */
  name: string;

  /**
   * A landmark or other identifiable feature near the address.
   */
  landmark?: string;

  /**
   * The first line of the street address.
   */
  add1: string;

  /**
   * The city or locality.
   */
  city: string;

  /**
   * The state or region.
   */
  state: string;

  /**
   * The country.
   */
  country: string;

  /**
   * The postal or zip code.
   */
  zip: string;

  /**
   * The kind of address (e.g. residential, business, etc.).
   */
  kind: AddressKind;

  /**
   * The phone number associated with the address.
   */
  phone: string;

  /**
   * Indicates whether this is the default address for the user.
   */
  isDefault?: boolean;

  /**
   * The email address associated with the address.
   */
  email?: string;
}

/**
 * Interface representing a phone number.
 */
export interface IPhone {
  /**
   * The phone number's country code.
   */
  countryCode: string;

  /**
   * The phone number.
   */
  phoneNumber: string;
}

/**
 * Interface representing a user.
 */
export interface IUser {
  /**
   * The user's name.
   */
  name: IName;

  /**
   * The user's phone number.
   */
  phone?: IPhone;

  /**
   * The user's email address.
   */
  email: string;

  /**
   * The user's password.
   */

  password: string;

  /**
   * The user's roles.
   */
  roles: Roles[];

  /**
   * The user's addresses.
   */
  addresses: IAddress[];

  /**
   * The user's date of birth.
   */
  dob: Date;

  /**
   * Indicates whether the user's email address has been verified.
   */
  emailVerified: boolean;

  /**
   * Indicates whether the user's phone number has been verified.
   */
  phoneVerified: boolean;
}

/**
 * This exports a Joi schema for validating user sign up requests.
 */
export const signUpSchema = Joi.object({
  type: Joi.any().valid('phone', 'email').required(),
  value: Joi.when('type', {
    is: 'email',
    then: Joi.string().email().required(),
    otherwise: Joi.string().pattern(/^[0-9]+$/).required()
  }),
  password: Joi.string().min(8).required(),
  fname: Joi.string().required(),
  lname: Joi.string().required(),
  mname: Joi.string().allow(''),
  code: Joi.string().required(),
});


export const signInSchema = Joi.object({
  type: Joi.string().valid('phone', 'email').required(),
  value: Joi.when('type', {
    is: 'email',
    then: Joi.string().email().required(),
    otherwise: Joi.string().required()
  }),
  password: Joi.string().required()
})

export const addressSchema = Joi.object({
  name: Joi.string().required(),
  landmark: Joi.string(),
  add1: Joi.string().required(),
  city: Joi.string().required(),
  state: Joi.string().required(),
  country: Joi.string().required(),
  zip: Joi.number().required(),
  kind: Joi.string().valid(...['home', 'work']),
  phone: Joi.string().required(),
});

export const joiPasswordChangeSchema = Joi.object({
  currentPassword: Joi.string().min(8).required(),
  newPassword: Joi.string().min(8).required(),
});

export const joiTokenVerifySchema = Joi.object({
  token: Joi.string().required(),
  code: Joi.string().required(),
});
