import mongoose, { Document, Schema } from "mongoose";
import { IUser, IAddress, IName, IPhone } from "./types";

interface IUserDocument extends IUser, Document {}

// an array of objects representing the user's addresses.
const addressSchema: Schema = new Schema<IAddress>({
  name: { type: String },
  landmark: { type: String },
  add1: { type: String, require: true },
  city: { type: String, require: true },
  state: { type: String, require: true },
  country: { type: String, require: true },
  zip: { type: String, require: true },
  kind: { type: String, default: "home", require: true },
  phone: { type: String, require: true },
  isDefault: { type: Boolean },
  email: { type: String },
});

const nameSchema: Schema = new Schema<IName>({
  fname: { type: String, require: [true, "first Name is requrie"] },
  lname: { type: String, require: [true, "last name is require"] },
  mname: { type: String },
});

const userSchema: Schema = new Schema({
  name: {
    type: String,
    require: [true, "name is required"],
  },
  email: {
    type: String,
    unique: true,
    sparse: true,
    validate: {
      validator: function (value: string) {
        return value || (this as unknown as IUser).email;
      },
      message: "Either phone number or email is required.",
    },
  },
  password: {
    type: String,
    require: [true, "password is required"],
  },
  phone: {
    type: String,
    unique: true,
    sparse: true,
    validate: {
      validator: function (value: string) {
        return value || (this as unknown as IUser).email;
      },
      message: "Either phone number or email is required.",
    },
  },
  dob: {
    type: Date,
    require: [true, "date of birth is require"],
  },
  roles: {
    type: Array,
    require: [true, "roles is require"],
    default: ["shopper", "shopperAdmin"],
  },
  addresses: [addressSchema],
});

export default mongoose.model<IUserDocument>("User", userSchema);
