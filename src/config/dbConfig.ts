import mongoose from "mongoose";
import { dbSecrets } from "./configurations";

export default async () => {
  try {
    const uri = dbSecrets.getConfig().mongodbUri;
    const dbName = dbSecrets.getConfig().mongodbName;
    const url = `${uri}/${dbName}?retryWrites=true&w=majority`;
    const conn = await mongoose.connect(url);
    console.log(`MongoDB connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(error);
    process.exit(1);
  }
};
