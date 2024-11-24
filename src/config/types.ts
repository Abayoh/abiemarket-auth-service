import { PathLike, WatchOptions } from "fs";
import { FileChangeInfo } from "fs/promises";
import { LogLevel, LogLevels } from "../lib/logger";

// Define the configuration interfaces
export interface ServiceUrlsConfig {
  apiGatewayUrl: string;
}

export interface JwtSecrets {
  oldJwtSecert: string;
  newJwtSecert: string;
}

export interface AuthConfigs {
  atMaxAge: number;
  ctMaxAge: number;
  rtMaxAge: number;
  stMaxAge: number;
  vtMaxAge: number;
  coolDownPeriod: number;
  maxValidationAttempts: number;
  env: "dev" | "prod";
  port: number;
}

export interface LogConfigs {
  logLevel: LogLevel;
  logLevels: LogLevels;
  logTransports: string[];
  logFile: string; //Filename to be used to log to. This filename can include the %DATE% placeholder which will include the formatted datePattern at that point in the filename. (default: 'winston.log.%DATE%)
  logFileMaxSize: string; //Maximum size of the file after which it will rotate. This can be a number of bytes, or units of kb, mb, and gb. If using the units, add 'k', 'm', or 'g' as the suffix. The units need to directly follow the number. (default: null)
  logFileMaxFiles: string; //Maximum number of logs to keep. If not set, no logs will be removed. This can be a number of files or number of days. If using days, add 'd' as the suffix. (default: null)
  datePattern: string; //A string representing the moment.js date format to be used for rotating. The meta characters used in this string will dictate the frequency of the file rotation. For example, if your datePattern is simply 'HH' you will end up with 24 log files that are picked up and appended to every day. (default 'YYYY-MM-DD')
  zippedArchive: true; //Compress old logs
}

export interface DbSecrets {
  mongodbUri: string;
  mongodbName: string;
}

export interface EmailSecrets {
  emailUser: string;
  emailPass: string;
}

export interface TwilioSecrets {
  twilioAuthToken: string;
  twilioAccId: string;
}

export type ConfigStructureMap = {
  serviceUrls: ServiceUrlsConfig;
  jwtSecrets: JwtSecrets;
  authConfigs: AuthConfigs;
  dbSecrets: DbSecrets;
  emailSecrets: EmailSecrets;
  twilioSecrets: TwilioSecrets;
};

export type ConfigType =
  | "serviceUrls"
  | "jwtSecrets"
  | "authConfigs"
  | "dbSecrets"
  | "emailSecrets"
  | "twilioSecrets"
  | "logConfigs";

export type FSWatcher = (
  filename: PathLike,
  options?: WatchOptions | BufferEncoding
) => AsyncIterable<FileChangeInfo<string>>;
