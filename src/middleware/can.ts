import { Request, Response, NextFunction } from "express";
import rolesMapPermissions from "../models/permissions";
import { CustomError } from "../lib/error";
import { authErrorCodes, authErrorCodesMap } from "../lib/errorCodes";
import logger from "../lib/logger";

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
        logger.security(
          `User ${user.sub} is not authorized to perform ${action}`,
          {
            action,
            requestId: req.requestId,
            userIdentifier: `${user.sub}`,
            ipAddress: req.forwardedForIp,
            endpoint: req.path,
            httpMethod: req.method,
            userAgent: req.get("User-Agent") || "",
            errorCode: authErrorCodes.AUTH_UNAUTHORIZE,
            statusCode:
              authErrorCodesMap[authErrorCodes.AUTH_UNAUTHORIZE].status,
          }
        );

        throw new CustomError(authErrorCodes.AUTH_UNAUTHORIZE);
      }

      if (verifyOwner && req.params.userId !== user.sub) {
        logger.security(
          `User ${user.sub} is not authorized to perform ${action}`,
          {
            action,
            requestId: req.requestId,
            userIdentifier: `${user.sub}`,
            ipAddress: req.forwardedForIp,
            endpoint: req.path,
            httpMethod: req.method,
            userAgent: req.get("User-Agent") || "",
            errorCode: authErrorCodes.AUTH_UNAUTHORIZE,
            statusCode:
              authErrorCodesMap[authErrorCodes.AUTH_UNAUTHORIZE].status,
          }
        );
        throw new CustomError(authErrorCodes.AUTH_UNAUTHORIZE);
      }

      next();
    } catch (error) {
      next(error);
    }
  };

export default can;
