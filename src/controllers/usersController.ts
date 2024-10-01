import { Request, Response, NextFunction, response } from "express";
import { CustomError } from "../lib/error";
import { authErrorCodes, authErrorCodesMap } from "../lib/errorCodes";
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
      logger.security("User Not found", {
        action: "getUserInfo",
        requestId: req.requestId,
        userIdentifier: userId,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_INVALID_CREDENTIALS,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_INVALID_CREDENTIALS].status,
      });

      throw new CustomError(authErrorCodes.AUTH_USER_NOT_FOUND);
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
      logger.security("User not found", {
        action: "changeUserPassword",
        requestId: req.requestId,
        userIdentifier: userId,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_USER_NOT_FOUND,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_USER_NOT_FOUND].status,
      });
      throw new CustomError(
        authErrorCodes.AUTH_USER_NOT_FOUND,
        "Invalid credentials"
      );
    }

    // Verify user password
    const isVerified = await verifyPassword(currentPassword, user.password);

    if (!isVerified) {
      logger.security("Password not verified, User password is wrong", {
        action: "changeUserPassword",
        requestId: req.requestId,
        userIdentifier: userId,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_INVALID_CREDENTIALS,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_INVALID_CREDENTIALS].status,
      });
      //log this
      throw new CustomError(
        authErrorCodes.AUTH_INVALID_CREDENTIALS,
        "The current password is wrong! Please change the password and try again"
      );
    }

    // Update user password in the database
    const hashedPassword = await hashPassword(newPassword);

    user.password = hashedPassword;

    await user.save();

    res.status(200).json({
      ...responseDefault,
      result: { message: "User Password successfully changed" },
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
      logger.security("Email cannot be changed! User not found", {
        action,
        requestId: req.requestId,
        userIdentifier: userId,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_USER_NOT_FOUND,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_INVALID_CREDENTIALS].status,
      });
      throw new CustomError(authErrorCodes.AUTH_USER_NOT_FOUND);
    }

    await sendVerificationTokenHandler("email", email, req);

    res.status(200).json({
      ...responseDefault,
      result: { message: "Email verification token sent successfully" },
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
      logger.security("User Phone number cannot be changed! User not found", {
        action: "changeUserPhone",
        requestId: req.requestId,
        userIdentifier: userId,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_INVALID_CREDENTIALS,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_INVALID_CREDENTIALS].status,
      });
      throw new CustomError(authErrorCodes.AUTH_USER_NOT_FOUND);
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
    const { fname, lname, mname } = req.body;

    //check if the user already exists
    const user = await UserSchema.findOne({ _id: userId });

    if (!user) {
      logger.security("User name cannot be changed! User not found", {
        action: "changeUserName",
        requestId: req.requestId,
        userIdentifier: userId,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_INVALID_CREDENTIALS,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_INVALID_CREDENTIALS].status,
      });
      throw new CustomError(authErrorCodes.AUTH_USER_NOT_FOUND);
    }

    if (fname.trim()) user.name.fname = fname;
    if (lname.trim()) user.name.lname = lname;
    if (mname.trim()) user.name.mname = mname;

    await user.save();

    res.json({
      ...responseDefault,
      result: { message: "User name successfully changed" },
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

    newAddress = {
      ...newAddress,
      _id: new mongoose.Types.ObjectId(),
    };

    // Find the user by ID in the database
    const user = await UserSchema.findOne({ _id: userId });

    // If the user is not found, throw a 404 error
    if (!user) {
      logger.error("User address cannot be added! User not found", {
        action: "addUserAddress",
        requestId: req.requestId,
        userIdentifier: userId,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_USER_NOT_FOUND,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_USER_NOT_FOUND].status,
      });
      throw new CustomError(authErrorCodes.AUTH_USER_NOT_FOUND);
    }

    // If the user's addresses property is undefined or null, create an empty array for it
    if (!user.addresses) {
      user.addresses = [];
    }

    // Add the new address to the user's list of addresses
    user.addresses.push(newAddress);

    // Save the updated user object in the database
    const updatedUser = await user.save();

    // If the updated user object is falsy, throw a 500 error
    if (!updatedUser) {
      logger.error("An unexecepted error occured why updating user address", {
        action: "addUserAddress",
        requestId: req.requestId,
        userIdentifier: userId,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_INTERNAL_SERVER_ERROR,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_INTERNAL_SERVER_ERROR].status,
      });
      throw new CustomError(
        authErrorCodes.AUTH_INTERNAL_SERVER_ERROR,
        "An unexecepted error occured why updating user address"
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
      throw new CustomError(authErrorCodes.AUTH_ADDRESS_NOT_FOUND);
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
      logger.warn("Address cannot be updated! User address not found", {
        action: "updateUserAddress",
        requestId: req.requestId,
        userIdentifier: userId,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_ADDRESS_NOT_FOUND,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_ADDRESS_NOT_FOUND].status,
      });
      throw new CustomError(
        authErrorCodes.AUTH_ADDRESS_NOT_FOUND,
        "An error occurs while updating addess"
      );
    }

    // Return success response
    res.json({ ...responseDefault });
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
      logger.warn("User addresses cannot be retrieved! User not found", {
        action: "getUserAddresses",
        requestId: req.requestId,
        userIdentifier: userId,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_ADDRESS_NOT_FOUND,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_ADDRESS_NOT_FOUND].status,
      });
      throw new CustomError(
        authErrorCodes.AUTH_ADDRESS_NOT_FOUND,
        "An error occurs while retreving user address"
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
    const { addressId } = req.params;
    const userId = req.user.sub;

    const address = await UserSchema.findOne(
      { _id: userId },
      { addresses: { $elemMatch: { _id: addressId } }, _id: 0 }
    ).lean();

    if (!address) {
      logger.warn("User address cannot be retrieved! User address not found", {
        action: "getUserAddress",
        requestId: req.requestId,
        userIdentifier: userId,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_ADDRESS_NOT_FOUND,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_ADDRESS_NOT_FOUND].status,
      });
      throw new CustomError(
        authErrorCodes.AUTH_ADDRESS_NOT_FOUND,
        "An error occurs while retreving user address"
      );
    }

    // Return success response
    res.json({ ...responseDefault, result: { address: address.addresses[0] } });
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
      logger.security("Email cannot be changed! User not found", {
        action: "verifyUserEmail",
        requestId: req.requestId,
        userIdentifier: userId,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_EMAIL_CONFLICT,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_EMAIL_CONFLICT].status,
      });
      throw new CustomError(authErrorCodes.AUTH_EMAIL_CONFLICT);
    }

    await verifyVerificationTokenHandler("email", email, code, req);

    //change user email
    user = await UserSchema.findOneAndUpdate({ _id: userId }, { email });

    if (!user) {
      logger.error("Email cannot be changed! User not found", {
        action: "verifyUserEmail",
        requestId: req.requestId,
        userIdentifier: userId,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_USER_NOT_FOUND,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_USER_NOT_FOUND].status,
      });

      throw new CustomError(
        authErrorCodes.AUTH_USER_NOT_FOUND,
        "Something went wrong while updating user email"
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
      logger.security("Phone number cannot be changed! User not found", {
        action: "verifyUserPhone",
        requestId: req.requestId,
        userIdentifier: userId,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_PHONE_CONFLICT,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_PHONE_CONFLICT].status,
      });
      throw new CustomError(authErrorCodes.AUTH_PHONE_CONFLICT);
    }

    await verifyVerificationTokenHandler("phone", phone, code, req);

    //change user Phone number
    user = await UserSchema.findOneAndUpdate({ _id: userId }, { phone });

    if (!user) {
      logger.error("Phone number cannot be changed! User not found", {
        action: "verifyUserPhone",
        requestId: req.requestId,
        userIdentifier: userId,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_USER_NOT_FOUND,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_USER_NOT_FOUND].status,
      });
      throw new CustomError(
        authErrorCodes.AUTH_USER_NOT_FOUND,
        "Something went wrong while updating user phone number"
      );
    }

    //TODO: send sms to the user to notify them that their Phone number has been changed
    //TODO: Sign in the user
    // Return success response
    res.json({ ...responseDefault, messages: ["phone number changed"] });
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
      logger.warn("Address cannot be set as default! User not found", {
        action: "setAddressAsDefault",
        requestId: req.requestId,
        userIdentifier: userId,
        ipAddress: req.forwardedForIp,
        endpoint: req.path,
        httpMethod: req.method,
        userAgent: req.forwardedUserAgent,
        errorCode: authErrorCodes.AUTH_USER_NOT_FOUND,
        statusCode:
          authErrorCodesMap[authErrorCodes.AUTH_USER_NOT_FOUND].status,
      });
      throw new CustomError(
        authErrorCodes.AUTH_ADDRESS_NOT_FOUND,
        "An error occurs while updating addess"
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
