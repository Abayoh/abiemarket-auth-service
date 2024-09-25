const config = {
  atMaxAge: 300, //access token max age in seconds
  ctMaxAge: 2592000, //client token max age in seconds (one month)
  rtMaxAge: 86400, //refresh token max age in seconds (one Day)
  stMaxAge: 86400, //session token max age in seconds
  vtMaxAge: 7200, //verification token max age in seconds
  coolDownPeriod: 3600, //cool down period in seconds
  maxValidationAttempts: 2, //the maximum validation Attempts
};

export default config;
