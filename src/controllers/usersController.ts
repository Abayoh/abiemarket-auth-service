import { Request, Response, NextFunction, response } from "express";
import { authErrorCodes } from "../error/errorCodes";
import { hashPassword, verifyPassword } from "../lib/auth";
import { UserSchema } from "../models/users";
import { IAddress } from "../models/users/types";
import {
  sendVerificationTokenHandler,
  verifyVerificationTokenHandler,
} from "./helpers";
import { responseDefault } from "../lib/constants";
import mongoose from "mongoose";
import logger from "../lib/logger";
import { log } from "console";
import { verifyUsernameChangeSchema } from "../models/users/userRequestVerificationSchemas";
import { AppError } from "../error/AppError";
import { UnsecuredJWT } from "jose";
import { create } from "domain";

export async function getUserInfo(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.user.sub;

    const user = await UserSchema.findOne(
      { _id: userId },
      { name: 1, email: 1, phone: 1 }
    ).lean();

    if (!user) {
      throw new AppError(authErrorCodes.AUTH_USER_NOT_FOUND, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "getUserInfo",
        neededActions: ["check for suspecious activity"],
        additionalInfo: `getUserInfo`,
      });
    }

    res.json({ ...responseDefault, result: { ...user } });
  } catch (error) {
    next(error);
  }
}

export async function changeUserPassword(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.user.sub;
    const { currentPassword, newPassword } = req.body;

    // Retrieve user information from the database
    let user = await UserSchema.findOne({ _id: userId });

    if (!user) {
      throw new AppError(
        authErrorCodes.AUTH_USER_NOT_FOUND,
        "Invalid credentials",
        {
          logLevel: "security",
          errorLogSeverity: "major",
          where: "changeUserPassword",
          neededActions: ["check for suspecious activity"],
          additionalInfo: `User not found`,
        }
      );
    }

    // Verify user password
    const isVerified = await verifyPassword(currentPassword, user.password);

    if (!isVerified) {
      //log this
      throw new AppError(
        authErrorCodes.AUTH_INVALID_CREDENTIALS,
        "The current password is wrong! Please change the password and try again",
        {
          logLevel: "security",
          errorLogSeverity: "major",
          where: "changeUserPassword",
          neededActions: ["check for suspecious activity"],
          additionalInfo: `Password not verified, User password is wrong`,
        }
      );
    }

    // Update user password in the database
    const hashedPassword = await hashPassword(newPassword);

    user.password = hashedPassword;

    await user.save();

    res.status(200).json({
      ...responseDefault,
      result: {},
      message: "User Password successfully changed",
    });
  } catch (error) {
    next(error);
  }
}

export async function changeUserEmail(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.user.sub;
    const { email } = req.body;
    const action = "changeUserEmail";
    //check if the user already exists
    const user = await UserSchema.findOne({ _id: userId });

    if (!user) {
      throw new AppError(authErrorCodes.AUTH_USER_NOT_FOUND, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "changeUserEmail",
        neededActions: ["check for suspecious activity"],
        additionalInfo: `Email cannot be changed! User not found`,
      });
    }

    await sendVerificationTokenHandler("email", email, req);

    res.status(200).json({
      ...responseDefault,
      result: {},
      message: "Email verification token sent successfully",
    });
  } catch (error) {
    next(error);
  }
}

export async function changeUserPhone(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.user.sub;
    const { phone } = req.body;

    //check if the user already exists
    const user = await UserSchema.findOne({ _id: userId });

    if (!user) {
      throw new AppError(authErrorCodes.AUTH_USER_NOT_FOUND, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "changeUserPhone",
        additionalInfo: `User Phone number cannot be changed! User not found`,
      });
    }

    await sendVerificationTokenHandler("phone", phone, req);
    res.json({ ...responseDefault });
  } catch (error) {
    next(error);
  }
}

export async function changeUserName(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.user.sub;
    const { name } = req.body;
    verifyUsernameChangeSchema.validateAsync({ name });
    //check if the user already exists
    const user = await UserSchema.findOne({ _id: userId });

    if (!user) {
      throw new AppError(authErrorCodes.AUTH_USER_NOT_FOUND, undefined, {
        logLevel: "security",
        errorLogSeverity: "major",
        where: "changeUserName",
        additionalInfo: `User name cannot be changed! User not found`,
      });
    }

    if (name.trim()) user.name = name;

    await user.save();

    res.json({
      ...responseDefault,
      result: {},
      message: "User name successfully changed",
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Add a new address to a user's list of addresses
 * @param req - The request object from Express
 * @param res - The response object from Express
 * @param next - The next function from Express
 * @returns A JSON response with the newly added address or an error message.
 */
export async function addUserAddress(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    // Get the user ID and new address from the request
    const userId = req.user.sub;
    let newAddress: IAddress = req.body;

    let setAsDefault = newAddress.isDefault;

    newAddress = {
      ...newAddress,
      _id: new mongoose.Types.ObjectId(),
    };

    // Find the user by ID in the database
    const user = await UserSchema.findOne({ _id: userId });

    // If the user is not found, throw a 404 error
    if (!user) {
      throw new AppError(authErrorCodes.AUTH_USER_NOT_FOUND, undefined, {
        logLevel: "warn",
        errorLogSeverity: "major",
        where: "addUserAddress",
        additionalInfo: `User address cannot be added! User not found`,
      });
    }

    // If the user's addresses property is undefined or null, create an empty array for it
    if (!user.addresses) {
      user.addresses = [];
    }

    if (setAsDefault) {
      user.addresses = user.addresses.map((address) => {
        if (address.isDefault) {
          address.isDefault = false;
        }
        return address;
      });
    }

    // Add the new address to the user's list of addresses
    user.addresses.push(newAddress);

    // Save the updated user object in the database
    const updatedUser = await user.save();

    // If the updated user object is falsy, throw a 500 error
    if (!updatedUser) {
      throw new AppError(
        authErrorCodes.AUTH_INTERNAL_SERVER_ERROR,
        "An unexecepted error occured why updating user address",
        {
          logLevel: "warn",
          errorLogSeverity: "major",
          where: "addUserAddress",
          additionalInfo: `An unexecepted error occured why updating user address`,
        }
      );
    }

    // retriev the last element of the addresses array of the
    // updatedUser object, which is the new address that was just added to the array
    const addedAddress =
      updatedUser.addresses?.[updatedUser.addresses.length - 1];

    const addressId = addedAddress?._id;

    // Return a success response
    res.status(201).json({ ...responseDefault, result: { ...newAddress } });
  } catch (error) {
    // Pass any errors to the Express error handler
    next(error);
  }
}

/**
 * Deletes a specific address for a given user.
 * @param req - The request object.
 * @param res - The response object.
 * @param next - The next function.
 * @returns A JSON response indicating the deleted address id or an error message.
 * @throws NotFound - If the address is not found.
 * @throws InternalServerError - If there is an error while deleting the address.
 */
export async function deleteUserAddress(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { addressId } = req.params;
    const userId = req.user.sub;

    // Remove the specified address from the user's addresses array.
    const result = await UserSchema.updateOne(
      { _id: userId },
      { $pull: { addresses: { _id: addressId } } }
    );

    // If the modified count is not 1, then the address was not found.
    if (result.modifiedCount !== 1) {
      throw new AppError(authErrorCodes.AUTH_ADDRESS_NOT_FOUND, undefined);
    }

    // Return a success message to the client.
    res.status(201).json({ ...responseDefault, result: { id: addressId } });
  } catch (error) {
    // Pass the error to the next middleware.
    next(error);
  }
}

export async function updateUserAddress(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { addressId } = req.params;
    const userId = req.user.sub;
    const newAddress = req.body;

    const result = await UserSchema.updateOne(
      { _id: userId, "addresses._id": addressId },
      {
        $set: {
          "addresses.$": newAddress,
        },
      }
    );

    if (result.matchedCount !== 1) {
      throw new AppError(
        authErrorCodes.AUTH_ADDRESS_NOT_FOUND,
        "An error occurs while updating addess",
        {
          logLevel: "warn",
          errorLogSeverity: "major",
          where: "updateUserAddress",
          additionalInfo: `Address cannot be updated! User address not found`,
        }
      );
    }

    // Return success response
    res.json({ ...responseDefault, result: { _id: addressId } });
  } catch (error) {
    next(error);
  }
}

export async function getUserAddresses(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.user.sub;
    const addresses = await UserSchema.findOne(
      { _id: userId },
      { addresses: 1, _id: 0 }
    ).lean();

    if (!addresses) {
      throw new AppError(
        authErrorCodes.AUTH_ADDRESS_NOT_FOUND,
        "An error occurs while retreving user address",
        {
          logLevel: "warn",
          errorLogSeverity: "major",
          where: "getUserAddresses",
          additionalInfo: `User addresses cannot be retrieved! User not found`,
        }
      );
    }

    // Return success response
    res.json({ ...responseDefault, result: { ...addresses } });
  } catch (error) {
    next(error);
  }
}

export async function getUserAddress(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { addressId, da: defaultAddress } = req.query;
    if (defaultAddress && addressId) {
      throw new AppError(
        authErrorCodes.AUTH_BAD_REQUEST,
        "Invalid query parameters! Both defaultAddress and addressId cannot be used together",
        {
          logLevel: "warn",
          errorLogSeverity: "major",
          where: "getUserAddress",
          additionalInfo: `Invalid query parameters! Both defaultAddress and addressId cannot be used together`,
        }
      );
    }

    if (!defaultAddress && !addressId) {
      throw new AppError(
        authErrorCodes.AUTH_BAD_REQUEST,
        "Invalid query parameters! Either da:defaultAddress or addressId must be used",
        {
          logLevel: "warn",
          errorLogSeverity: "major",
          where: "getUserAddress",
          additionalInfo: `Invalid query parameters! Either defaultAddress or addressId must be used`,
        }
      );
    }

    if (defaultAddress) {
      const userId = req.user.sub;

      const address = await UserSchema.findOne(
        { _id: userId, "addresses.isDefault": true },
        { addresses: { $elemMatch: { isDefault: true } }, _id: 0 }
      ).lean();

      if (!address) {
        throw new AppError(
          authErrorCodes.AUTH_ADDRESS_NOT_FOUND,
          "An error occurs while retreving user address",
          {
            logLevel: "warn",
            errorLogSeverity: "major",
            where: "getUserAddress",
            additionalInfo: `User address cannot be retrieved! User address not found`,
          }
        );
      }

      // Return success response
      res.json({
        ...responseDefault,
        result: { address: address.addresses[0] },
      });
    } else if (addressId) {
      const userId = req.user.sub;

      const address = await UserSchema.findOne(
        { _id: userId },
        { addresses: { $elemMatch: { _id: addressId } }, _id: 0 }
      ).lean();

      if (!address) {
        throw new AppError(
          authErrorCodes.AUTH_ADDRESS_NOT_FOUND,
          "An error occurs while retreving user address",
          {
            logLevel: "warn",
            errorLogSeverity: "major",
            where: "getUserAddress",
            additionalInfo: `User address cannot be retrieved! User address not found`,
          }
        );
      }

      // Return success response
      res.json({
        ...responseDefault,
        result: { address: address.addresses[0] },
      });
    } else {
      throw new AppError(
        authErrorCodes.AUTH_BAD_REQUEST,
        "Invalid query parameters! Either da:defaultAddress or addressId must be used",
        {
          logLevel: "warn",
          errorLogSeverity: "major",
          where: "getUserAddress",
          additionalInfo: `Invalid query parameters! Either defaultAddress or addressId must be used`,
        }
      );
    }
  } catch (error) {
    next(error);
  }
}

export async function verifyUserEmail(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { code, email } = req.body;
    const userId = req.user.sub;

    //check if the email already exists
    let user = await UserSchema.findOne({ email });
    if (user) {
      throw new AppError(authErrorCodes.AUTH_EMAIL_CONFLICT, undefined, {
        logLevel: "warn",
        errorLogSeverity: "major",
        where: "verifyUserEmail",
        additionalInfo: `Email cannot be changed! User not found`,
      });
    }

    await verifyVerificationTokenHandler("email", email, code, req);

    //change user email
    user = await UserSchema.findOneAndUpdate({ _id: userId }, { email });

    if (!user) {
      throw new AppError(
        authErrorCodes.AUTH_USER_NOT_FOUND,
        "Something went wrong while updating user email",
        {
          logLevel: "warn",
          errorLogSeverity: "major",
          where: "verifyUserEmail",
          additionalInfo: "Email cannot be changed! User not found",
        }
      );
    }

    //TODO: send email to the user to notify them that their email has been changed
    //TODO: Sign in the user

    // Return success response
    res.json({ ...responseDefault });
  } catch (error) {
    next(error);
  }
}

export async function verifyUserPhone(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { code, phone } = req.body;
    const userId = req.user.sub;
    //check if the Phone number already exists
    let user = await UserSchema.findOne({ phone });
    if (user) {
      throw new AppError(authErrorCodes.AUTH_PHONE_CONFLICT, undefined, {
        logLevel: "warn",
        errorLogSeverity: "major",
        where: "verifyUserPhone",
        additionalInfo: "Phone number cannot be changed! User not found",
      });
    }

    await verifyVerificationTokenHandler("phone", phone, code, req);

    //change user Phone number
    user = await UserSchema.findOneAndUpdate({ _id: userId }, { phone });

    if (!user) {
      throw new AppError(
        authErrorCodes.AUTH_USER_NOT_FOUND,
        "Something went wrong while updating user phone number",
        {
          logLevel: "warn",
          errorLogSeverity: "major",
          where: "verifyUserPhone",
          additionalInfo: "Phone number cannot be changed! User not found",
        }
      );
    }

    //TODO: send sms to the user to notify them that their Phone number has been changed
    //TODO: Sign in the user
    // Return success response
    res.json({ ...responseDefault, message: "phone number changed" });
  } catch (error) {
    next(error);
  }
}

export async function setAddressAsDefault(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { addressId } = req.params;
    const userId = req.user.sub;

    const result = await UserSchema.findOne({
      _id: userId,
    });

    if (!result) {
      throw new AppError(
        authErrorCodes.AUTH_ADDRESS_NOT_FOUND,
        "An error occurs while updating addess",
        {
          logLevel: "warn",
          errorLogSeverity: "major",
          where: "setAddressAsDefault",
          additionalInfo: "Address cannot be set as default! User not found",
        }
      );
    }

    //unset the old default address to false
    if (result.addresses) {
      result.addresses = result.addresses.map((address) => {
        if (address.isDefault) {
          address.isDefault = false;
        }
        if (address._id.toString() === addressId) {
          address.isDefault = true;
        }
        return address;
      });
    }

    await result.save();

    // Return success response
    res.json({
      ...responseDefault,
      result: { message: "Default address set successfully" },
    });
  } catch (error) {
    next(error);
  }
}

export async function createNewUser(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { name, email, password, phone } = req.body;

    const hashedPassword = await hashPassword(password);

    const user = new UserSchema({
      name,
      email,
      password: hashedPassword,
      phone,
    });

    await user.save();

    res.status(201).json({ ...responseDefault, result: { ...user } });
  } catch (error) {
    next(error);
  }
}

export async function addUserRole(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { role } = req.body;
    const userId = req.params.userId;

    const user = await UserSchema.findOne({ _id: userId });

    if (!user) {
      throw new AppError(authErrorCodes.AUTH_USER_NOT_FOUND, undefined, {
        logLevel: "warn",
        errorLogSeverity: "major",
        where: "setUserRole",
        additionalInfo: `User role cannot be set! User not found`,
      });
    }

    if (user.roles.includes(role)) {
      throw new AppError(authErrorCodes.AUTH_ROLE_CONFLICT, undefined, {
        logLevel: "warn",
        errorLogSeverity: "major",
        where: "setUserRole",
        additionalInfo: `User role cannot be set! User already has the role`,
      });
    }

    user.roles = [...user.roles, role];

    await user.save();

    res.json({ ...responseDefault, result: { role } });
  } catch (error) {
    next(error);
  }
}

export async function removeUserRole(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { role } = req.body;
    const userId = req.params.userId;

    const user = await UserSchema.findOne({ _id: userId });

    if (!user) {
      throw new AppError(authErrorCodes.AUTH_USER_NOT_FOUND, undefined, {
        logLevel: "warn",
        errorLogSeverity: "major",
        where: "removeUserRole",
        additionalInfo: `User role cannot be removed! User not found`,
      });
    }

    if (!user.roles.includes(role)) {
      throw new AppError(authErrorCodes.AUTH_ROLE_NOT_FOUND, undefined, {
        logLevel: "warn",
        errorLogSeverity: "major",
        where: "removeUserRole",
        additionalInfo: `User role cannot be removed! User does not have the role`,
      });
    }

    //cannot remove seller role
    if (role === "seller") {
      throw new AppError(authErrorCodes.AUTH_UNAUTHORIZE, undefined, {
        logLevel: "warn",
        errorLogSeverity: "major",
        where: "removeUserRole",
        additionalInfo: `User role cannot be removed! User role is not allowed to be removed`,
      });
    }

    //cannot remove last role
    if (user.roles.length === 1) {
      throw new AppError(authErrorCodes.AUTH_UNAUTHORIZE, undefined, {
        logLevel: "warn",
        errorLogSeverity: "major",
        where: "removeUserRole",
        additionalInfo: `User role cannot be removed! Users must have at least one role`,
      });
    }

    user.roles = user.roles.filter((r) => r !== role);

    await user.save();

    res.json({ ...responseDefault, result: { role } });
  } catch (error) {
    next(error);
  }
}
