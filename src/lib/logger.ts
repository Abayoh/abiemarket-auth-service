import winston from "winston";
import DailyRotateFile from "winston-daily-rotate-file";
import { logConfigs } from "../config/configurations";
import { arraysAreDifferent } from "../utils";
import { create } from "domain";
import auth from "../middleware/authorize";

// Define custom log levels
const defaultLogLevels = {
  levels: {
    error: 0,
    warn: 1,
    info: 2,
    security: 3,
    http: 4,
    transaction: 5,
    verbose: 6,
    debug: 7,
  },
  colors: {
    error: "red",
    warn: "yellow",
    info: "green",
    http: "magenta",
    verbose: "cyan",
    debug: "blue",
    security: "cyan",
    transaction: "grey",
  },
};

export type LogLevel =
  | "error"
  | "warn"
  | "info"
  | "security"
  | "http"
  | "transaction"
  | "verbose"
  | "debug";

export type LogLevels = Record<LogLevel, number>;

export interface LogMetadata {
  action: string;
  requestId: string;
  userIdentifier: string;
  ipAddress: string;
  endpoint: string;
  httpMethod: string;
  userAgent: string;
  statusCode: number;
  errorCode: string;
  stack?: string;
}

// Apply colors to winston
winston.addColors(defaultLogLevels.colors);

class Logger {
  private dailyRotateFileTransport: DailyRotateFile;
  private logger: winston.Logger;
  private level: LogLevel;
  private levels: LogLevels;
  private logTransports: string[];

  constructor() {
    // Create a daily rotate file transport
    this.dailyRotateFileTransport = this.createDailyRotateFileTransport();

    logConfigs.on("configChange", this.updateLogger.bind(this));

    this.level = logConfigs.getConfig().logLevel;
    this.levels = logConfigs.getConfig().logLevels;
    this.logTransports = logConfigs.getConfig().logTransports || [
      "file",
      "console",
    ];
    // Create the logger instance
    this.logger = this.createLogger();
  }

  private updateLogger() {
    this.dailyRotateFileTransport = this.createDailyRotateFileTransport();
    this.logger = this.createLogger();
    console.log(this.logger.level);
  }

  // Get logger child instance for a specific level
  // Create helper methods for custom levels
  public transaction(message: string, metadata?: LogMetadata) {
    this.logger.log("transaction", message, { ...metadata });
  }

  public security(message: string, metadata?: LogMetadata) {
    this.logger.log("security", message, { ...metadata });
  }

  // Other methods for standard levels
  public error(message: string, metadata?: LogMetadata) {
    this.logger.error(message, { ...metadata });
  }

  public warn(message: string, metadata?: LogMetadata) {
    this.logger.warn(message, { ...metadata });
  }

  public info(message: string, metadata?: LogMetadata) {
    this.logger.info(message, { ...metadata });
  }

  public http(message: string, metadata?: LogMetadata) {
    this.logger.http(message, { ...metadata });
  }

  public debug(message: string, metadata?: LogMetadata) {
    this.logger.debug(message, { ...metadata });
  }

  private createLogger() {
    console.log("Creating logger");
    return winston.createLogger({
      levels: logConfigs.getConfig().logLevels,
      level: logConfigs.getConfig().logLevel,
      format: winston.format.combine(
        winston.format.timestamp({ format: "YYYY-MM-DD HH:mm:ss" }), // Add timestamps
        winston.format.json() // Use JSON format for file logs
      ),
      transports: [...this.createTransports()],
    });
  }

  private createDailyRotateFileTransport() {
    console.log("Creating daily rotate file transport");
    return new DailyRotateFile({
      filename: logConfigs.getConfig().logFile || "logs/application-%DATE%.log", // Ensure logs directory exists
      datePattern: logConfigs.getConfig().datePattern || "YYYY-MM-DD",
      maxFiles: logConfigs.getConfig().logFileMaxFiles || "14d", // Keep logs for 14 days
      maxSize: logConfigs.getConfig().logFileMaxSize || "20m", // Rotate files after 20 MB
      zippedArchive: logConfigs.getConfig().zippedArchive || true, // Compress old logs
    });
  }

  private createTransports() {
    const enabledTransports = logConfigs.getConfig().logTransports || [
      "file",
      "console",
    ];
    const transports = [];

    if (enabledTransports.includes("file")) {
      transports.push(this.dailyRotateFileTransport);
    }

    if (enabledTransports.includes("console")) {
      transports.push(
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(), // Enable colorization in console
            winston.format.simple() // Simple format for console output
          ),
        })
      );
    }

    return transports;
  }
}

// Export instances for different logging levels
export default new Logger();
