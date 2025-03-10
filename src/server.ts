import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import dbConfig from "./config/dbConfig";
import { authErrorCodes } from "./error/errorCodes";
import logger from "./lib/logger";
//routes
import authRoutes from "./routes/authRoutes";
import usersRoutes from "./routes/usersRoutes";
// middleware

//error handler
import { errorHandler } from "./error/errorHandlerMiddleware";

import { AccessTokenClaims } from "./lib/types";
import { AppError } from "./error/AppError";
import { authConfigsLoader } from "./config/configurations";

declare global {
  namespace Express {
    interface Request {
      user: AccessTokenClaims;
      requestId: string;
      forwardedForIp: string;
      forwardedUserAgent: string;
      service: string;
    }
  }
}

dotenv.config();
dbConfig();
const app = express();
const port = authConfigsLoader.getConfig().port;

app.use(cors());

app.use(express.json());

// Tell Express to trust the proxy chain, so it uses X-Forwarded-For
app.set("trust proxy", true);

// const;

// function ipWhitelistMiddleware(
//   req: express.Request,
//   res: express.Response,
//   next: express.NextFunction
// ) {
//   const ipWhitelist = [""]; //authConfigsLoader.getConfig().ipWhitelist;
//   if (ipWhitelist && !ipRangeCheck(req.ip, ipWhitelist)) {
//     logger.warn(`Unauthorized IP address: ${req.ip}`, {
//       action: "unauthorized_ip",
//       requestId: req.requestId,
//       userIdentifier: `${"anonymous"} `,
//       ipAddress: req.forwardedForIp,
//       endpoint: req.path,
//       httpMethod: req.method,
//       userAgent: req.forwardedUserAgent,
//       errorCode: authErrorCodes.AUTH_UNAUTHORIZED_IP,
//       statusCode: authErrorCodesMap[authErrorCodes.AUTH_UNAUTHORIZED_IP].status,
//     });
//     return next(new CustomError(authErrorCodes.AUTH_UNAUTHORIZED_IP));
//   }
//   next();
// }

// Middleware to log response time

app.use((req, res, next) => {
  try {
    if (req.path === "/v1/health") return next(); //do not log health check requests from kubernetes

    req.requestId = req.headers["x-request-id"] as string;
    res.setHeader("x-request-id", req.requestId);
    req.forwardedForIp = req.headers["x-original-forwarded-for"] as string;
    req.forwardedUserAgent = req.headers["x-forwarded-user-agent"] as string;

    const startHrTime = process.hrtime();

    // //Temporary IP whitelist
    // const ipWhitelist = ["196.250.182.196", "164.160.11.210"];
    // if (ipWhitelist && !ipRangeCheck(req.forwardedForIp, ipWhitelist)) {
    //   logger.warn(`Unauthorized IP address: ${req.forwardedForIp}`, {
    //     action: "unauthorized_ip",
    //     requestId: req.requestId,
    //     userIdentifier: `${"anonymous"} `,
    //     ipAddress: req.forwardedForIp,
    //     endpoint: req.path,
    //     httpMethod: req.method,
    //     userAgent: req.forwardedUserAgent,
    //     errorCode: "AUTH_UNAUTHORIZED_IP",
    //     statusCode: 401,
    //   });
    //   return next(new CustomError(authErrorCodes.AUTH_UNAUTHORIZE));
    // }
    req.service = "Auth Service";

    res.on("finish", () => {
      const elapsedHrTime = process.hrtime(startHrTime);
      const elapsedTimeInMs = elapsedHrTime[0] * 1000 + elapsedHrTime[1] / 1e6;

      if (req.path === "/v1/health") return; //do not log health check requests from kubernetes

      logger.http(
        `${req.method} ${req.url} ${res.statusCode} - ${elapsedTimeInMs} ms - requestId:${req.requestId}`
      );
    });

    next();
  } catch (e) {
    next(e);
  }
});

//kubernetes health check
app.get("/v1/health", (req, res) => {
  res.send("OK");
});

// auth routes
app.use("/v1/auth", authRoutes);

// users routes
app.use("/v1/users", usersRoutes);

app.use((req, res, next) => {
  next(
    new AppError(authErrorCodes.AUTH_ROUTE_NOT_FOUND, undefined, {
      logLevel: "warn",
      errorLogSeverity: "major",
      where: "routeNotfind",
      neededActions: ["check suspecious activities"],
      additionalInfo: "The Route is unavailable",
    })
  );
});

//error Route
//made changes
app.use(errorHandler);

app.listen(port, () => {
  logger.info(`Server is running on port ${port}`);
});
