import mongoose, { Document, Schema } from 'mongoose';
import { VerificationToken } from './types';

export interface VerificationTokenDocument
  extends VerificationToken,
    Document {
      requestAttempts: number;
      validationAttempts: number;
      cooldownPeriod: Date;
      codes: string[];
    }

const verificationSchema: Schema = new Schema<VerificationTokenDocument>(
  {
    expires: { type: Date, required: true },
    codes: { type: [String], required: true },
    requestAttempts: { type: Number, required: true, default: 1 },
    validationAttempts: { type: Number, required: true, default: 1 },
    cooldownPeriod: { type: Date },
    verificationType: {
        type: { type: String, required: true },
        value: { type: String, required: true },
      },
      // required: true,
    
  },
  { timestamps: true }
);

export default mongoose.model<VerificationTokenDocument>(
  'VerificationToken',
  verificationSchema
);
