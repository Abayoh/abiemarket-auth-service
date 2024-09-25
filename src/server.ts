import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import dbConfig from "./config/dbConfig";
import { CustomError } from "./lib/error";
import { authErrorCodes, authErrorCodesMap } from "./lib/errorCodes";
import logger from "./lib/logger";
import os from "os";
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
    }
  }
}

dotenv.config();
dbConfig();
const app = express();
const port = 80;

app.use(cors());

app.use(express.json());

// Middleware to log response time
app.use((req, res, next) => {
  //generate a unique request id
  req.headers["x-request-id"] = Date.now().toString(); //TODO: replace from the incoming request
  req.requestId = req.headers["x-request-id"];
  res.setHeader("x-request-id", req.requestId);
  const startHrTime = process.hrtime();

  res.on("finish", () => {
    const elapsedHrTime = process.hrtime(startHrTime);
    const elapsedTimeInMs = elapsedHrTime[0] * 1000 + elapsedHrTime[1] / 1e6;
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

// auth routes
app.use("/v1/auth", authRoutes);

// users routes
app.use("/v1/users", usersRoutes);

app.use((req, res, next) => {
  logger.warn(`Route not found: ${req.url}`, {
    action: "route_not_found",
    requestId: req.requestId,
    userIdentifier: `${"anonymous"} `,
    ipAddress: req.ip || "",
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
