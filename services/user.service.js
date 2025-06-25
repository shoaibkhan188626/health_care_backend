import User from "../models/user.js";
import logger from "../config/logger.js";
import {
  ValidationError,
  NotFoundError,
  ForbiddenError,
} from "../utils/error.js";

export const createUser = async (data) => {
  const { name, email, phone, password, role, hospitalId, location } = data;
  const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
  if (existingUser) {
    logger.warn("User Already exists", { email, phone });
    throw new ValidationError("Email or phone already exists");
  }

  const user = new User({
    name,
    email,
    phone,
    password,
    role,
    hospitalId,
    address,
    location,
    isVerified: role !== "doctor",
  });
  await user.save();
  return user;
};

export const findUserByEmail = async (email, selectPassword = false) => {
  const user = await User.findOne({ email }).select(
    selectPassword ? "+password" : ""
  );
  if (!user || user.deleted) {
    logger.warn("User not found", { email });
    throw new NotFoundError("User not found");
  }
  return user;
};

export const updateUser = async (id, data) => {
  const user = await User.findById(id);
  if (!user || user.deleted) {
    logger.warn("User not found", { userId: id });
    throw new NotFoundError("User not found");
  }

  if (user.role === "doctor" && !user.isVerified) {
    logger.warn("unverified doctor update attempt", { userId: id });
    throw new ForbiddenError("Doctor account not verified");
  }
  if (data.phone && data.phone !== user.phone) {
    const existingUser = await User.findOne({ phone: data.phone });
    if (existingUser) {
      logger.warn("Phone already exists", { phone: data.phone });
      throw new ValidationError("Phone number already exists");
    }
  }
  Object.assign(user, data);
  await user.save();
  return user;
};
