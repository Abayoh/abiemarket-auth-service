import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import dbConfig from "./config/dbConfig";
import { CustomError } from "./lib/error";
import { authErrorCodes, authErrorCodesMap } from "./lib/errorCodes";
import logger from "./lib/logger";
import os from "os";
import ipRangeCheck from "ip-range-check";
//routes
import authRoutes from "./routes/authRoutes";
import usersRoutes from "./routes/usersRoutes";
// middleware
import authorize from "./middleware/authorize";

//error handler
import { errorHandler } from "./lib/error";

import { AccessTokenClaims } from "./lib/types";
import { authConfigsLoader } from "./config/configurations";

declare global {
  namespace Express {
    interface Request {
      user: AccessTokenClaims;
      requestId: string;
      forwardedForIp: string;
      forwardedUserAgent: string;
    }
  }
}

dotenv.config();
dbConfig();
const app = express();
const port = 80;

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
//       userAgent: req.get("User-Agent") || "",
//       errorCode: authErrorCodes.AUTH_UNAUTHORIZED_IP,
//       statusCode: authErrorCodesMap[authErrorCodes.AUTH_UNAUTHORIZED_IP].status,
//     });
//     return next(new CustomError(authErrorCodes.AUTH_UNAUTHORIZED_IP));
//   }
//   next();
// }

// Middleware to log response time
app.use((req, res, next) => {
  req.requestId = req.headers["x-request-id"] as string;
  res.setHeader("x-request-id", req.requestId);
  req.forwardedForIp = req.headers["x-forwarded-for"] as string;
  req.forwardedUserAgent = req.headers["x-forwarded-user-agent"] as string;
  const startHrTime = process.hrtime();

  console.log("Request received", {
    requestId: req.requestId,
    forwardedForIp: req.forwardedForIp,
    forwardedUserAgent: req.forwardedUserAgent,
  });

  res.on("finish", () => {
    const elapsedHrTime = process.hrtime(startHrTime);
    const elapsedTimeInMs = elapsedHrTime[0] * 1000 + elapsedHrTime[1] / 1e6;

    if (req.path === "/v1/health") return; //do not log health check requests from kubernetes

    logger.http(
      `${req.method} ${req.url} ${res.statusCode} - ${elapsedTimeInMs} ms`
    );
  });

  next();
});

// Define a route
app.get("/v1", (req, res) => {
  res.send(`Hello, Auth Server ${os.hostname()}`);
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
  logger.warn(`Route not found: ${req.url}`, {
    action: "route_not_found",
    requestId: req.requestId,
    userIdentifier: `${"anonymous"} `,
    ipAddress: req.forwardedForIp,
    endpoint: req.path,
    httpMethod: req.method,
    userAgent: req.get("User-Agent") || "",
    errorCode: authErrorCodes.AUTH_ROUTE_NOT_FOUND,
    statusCode: authErrorCodesMap[authErrorCodes.AUTH_ROUTE_NOT_FOUND].status,
  });
  next(new CustomError(authErrorCodes.AUTH_ROUTE_NOT_FOUND));
});

//error Route
//made changes
app.use(errorHandler);

app.listen(port, () => {
  logger.info(`Server is running on port ${port}`);
});
