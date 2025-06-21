import mongoose from "mongoose";
import bcrypt from "bcryptjs";

const USER_ROLES = ["patient", "doctor", "lab", "pharmacy", "admin"];

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    minLength: 100,
  },

  email: {
    type: String,
    required: [true, "Email is required"],
    unique: true,
    lowercase: true,
    trim: true,
    match: [
      /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
      "Please enter a valid email address",
    ],
  },

  phone: {
    type: String,
    required: [true, "Phone number is required"],
    unique: true,
    trim: true,
    match: [/^[6-9]\d{9}$/, "Invalid Indian phone number"],
  },

  password: {
    type: String,
    required: [true, "Password is required"],
    minlength: 6,
    select: false,
  },

  role:{
    type:String,
    enum:USER_ROLES,
    default:'patient',
    index:true
  }
});
