import ConfigLoader from "./ConfigLoader";
import { watch } from "fs/promises";
import {
  ServiceUrlsConfig,
  JwtSecrets,
  AuthConfigs,
  DbSecrets,
  EmailSecrets,
  TwilioSecrets,
  LogConfigs,
} from "./types";
import exp from "constants";

// Create instances for each type of configuration
// export const serviceUrlsLoader = new ConfigLoader<ServiceUrlsConfig>(
//   "../../config/service_urls.yml",
//   watch
// );
export const jwtSecretsLoader = new ConfigLoader<JwtSecrets>(
  "../../config/jwt_secrets.yml",
  watch
);

export const authConfigsLoader = new ConfigLoader<AuthConfigs>(
  "../../config/auth_configs.yml",
  watch
);

export const dbSecrets = new ConfigLoader<DbSecrets>(
  "../../config/auth_db_secrets.yml",
  watch
);

export const emailSecrets = new ConfigLoader<EmailSecrets>(
  "../../config/email_secrets.yml",
  watch
);

export const twilioSecrets = new ConfigLoader<TwilioSecrets>(
  "../../config/twilio_secrets.yml",
  watch
);

export const logConfigs = new ConfigLoader<LogConfigs>(
  "../../config/auth_log_configs.yml",
  watch
);

export const servicesUrsLoader = new ConfigLoader<ServiceUrlsConfig>(
  "../../config/service_urls.yml",
  watch
);
