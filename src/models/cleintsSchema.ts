import mongoose, { Document, Schema } from 'mongoose';

interface IClient extends Document {
  clientId: string;
  clientName: string;
  redirectUris: string[];
  clientSecret?: string;
  clientUrls?: string[];
  mobileClient: boolean;
}

const clientSchema: Schema = new Schema({
  clientId: { type: String, required: true },
  clientName: { type: String, required: true },
  redirectUris: [{ type: String, required: true }],
  clientSecret: { type: String }, // Optional client secret
  clientUrls: [{ type: String }], // Optional client URLs
  mobileClient: { type: Boolean, required: true },
});

export default mongoose.model<IClient>('Client', clientSchema);
