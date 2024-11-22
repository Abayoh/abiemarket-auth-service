import { Request, Response, NextFunction } from "express";
import rolesMapPermissions from "../models/permissions";
import { authErrorCodes } from "../error/errorCodes";
import { AppError } from "../error/AppError";

interface CanParams {
  action: string;
  verifyOwner?: boolean;
}

const can = ({ action, verifyOwner = false }: CanParams) =>
  function (req: Request, _: Response, next: NextFunction) {
    try {
      const user = req.user;
      let isPermitted = false;
      user.roles.forEach((role) => {
        const permissions = rolesMapPermissions[role];
        if (permissions.includes(action)) {
          isPermitted = true;
          return;
        }
      });

      if (!isPermitted) {
        throw new AppError(authErrorCodes.AUTH_UNAUTHORIZE, undefined, {
          logLevel: "warn",
          errorLogSeverity: "security",
          where: "can",
          additionalInfo: `User ${user.sub} is not authorized to perform ${action}`,
        });
      }

      if (verifyOwner && req.params.userId !== user.sub) {
        throw new AppError(authErrorCodes.AUTH_UNAUTHORIZE, undefined, {
          logLevel: "warn",
          errorLogSeverity: "security",
          where: "can",
          additionalInfo: `User ${user.sub} is not authorized to perform ${action}`,
        });
      }

      next();
    } catch (error) {
      next(error);
    }
  };

export default can;
