import mongoose, {Document, Schema} from "mongoose";



interface RefreshTokenDocument extends Document {
    refreshToken: string;
    userId: string;
    roles: string[];
    name: string;
    _sot: 'email' | 'phone';
    val: string;
    revoked: boolean;
    expires: Date;
    created: Date;
    createdByIp: string;
}

const refreshTokenSchema: Schema = new Schema<RefreshTokenDocument>({
    refreshToken: {type: String, required: true},
    userId: {type: String, required: true},
    roles: {type: [String], required: true},
    name: {type: String, required: true},
    _sot: {
        type: String, 
        required: true
    },
    val: {type: String, required: true},
    revoked: {type: Boolean, required: true, default: false},
    expires: {type: Date, required: true},
    created: {type: Date, required: true},
});

export default mongoose.model<RefreshTokenDocument>("RefreshToken", refreshTokenSchema);



