import mongoose from "mongoose";
const { Schema } = mongoose;

const UserSchema = new Schema({
  username: {type: String, unique: true},
  email: String,
  password: String,
});

export const User = mongoose.model("User", UserSchema);
