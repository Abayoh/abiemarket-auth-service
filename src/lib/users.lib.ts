import crypto from "crypto";

//Decode user hander from base64 string to object

export function decodeUserHandler(userHandler: string) {
  const decoded = Buffer.from(userHandler, "base64").toString("utf-8");
  return JSON.parse(decoded);
}
