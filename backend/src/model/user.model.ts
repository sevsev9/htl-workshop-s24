import { Schema, Document, model, ObjectId } from "mongoose";

export type User = {
    username: string;
    email: string;
    password: string;
}

export type UserDocument = Document<ObjectId> & User;

export const UserSchema = new Schema<UserDocument>({
    username: { type: String, unique: true, required: true },
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true }
}, {
    timestamps: true,
    toJSON: {
        virtuals: true,
        transform: (_, ret) => {
            ret.id = ret._id.toString();
            delete ret._id;
            delete ret.__v;
            delete ret.password;
        }
    },
    toObject: {
        virtuals: true,
        transform: (_, ret) => {
            ret.id = ret._id.toString();
            delete ret._id;
            delete ret.__v;
            delete ret.password;
        }
    }
});

export const UserModel = model<UserDocument>("User", UserSchema);