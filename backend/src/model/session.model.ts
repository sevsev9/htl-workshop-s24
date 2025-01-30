import mongoose from "mongoose";
import { UserDocument } from "./user.model";

export type Session = {
    userId: UserDocument["id"];
    valid: boolean;
    userAgent: string;

    createdAt?: Date;
    updatedAt?: Date;
};

export type SessionDocument = mongoose.Document<string> & Session;

const sessionSchema = new mongoose.Schema<SessionDocument>({
    userId: { type: mongoose.Types.ObjectId, ref: "User", required: true },
    valid: { type: Boolean, required: true, default: true },
    userAgent: { type: String },
},
    // add timestamps, remove __v from toJSON and toObject and show id as string
    {
        timestamps: true,
        toJSON: {
            virtuals: true,
            transform: function (doc, ret) {
                ret.id = ret._id.toString();
                delete ret._id;
                delete ret.__v;
            }
        },
        toObject: {
            virtuals: true,
            transform: function (doc, ret) {
                ret.id = ret._id.toString();
                delete ret._id;
                delete ret.__v;
            }
        }
    }
);

const SessionModel = mongoose.model<SessionDocument>("Session", sessionSchema);

export default SessionModel;
