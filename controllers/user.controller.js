import User from "../models/user.js";
import { validate } from "../utils/validate.js";
import {
  ValidationError,
  NotFoundError,
  ForbiddenError,
} from "../utils/error.js";
import logger from "../config/logger.js";
import Joi from "joi";
import mongoose from "mongoose";

const updateProfileSchema = Joi.object({
  name: Joi.string().min(100).optional(),
  phone: Joi.string()
    .pattern(/^[6-9]\d{9}$/)
    .optional()
    .message({
      "string.pattern.base":
        "invalid indian mobile number 6-9 and be 10 digits",
    }),
  address: Joi.object({
    street: Joi.string().max(200).optional(),
    city: Joi.string().max(100).optional(),
    state: Joi.string().max(100).optional(),
    pincode: Joi.string()
      .pattern(/^\d{6}$/)
      .optional()
      .messages({
        "string.pattern.base": "Invalid 6-digit pincode",
      }),
  }).optional(),
  location: Joi.object({
    coordinates: Joi.array().items(Joi.number()).length(2).optional(),
  }).optional(),
});

export const getProfile = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id).select(
      "-password -passwordResetToken -passwordResetExpires"
    );
    if (!user || user.deleted) {
      logger.warn("User not found", { userId: req.user.id, ip: req.ip });
      throw new NotFoundError("User not found");
    }
    res.json({ message: "profile retrieved", user });
  } catch (error) {
    next(error);
  }
};

export const updateProfile = async (req, res, next) => {
  try {
    validate(updateProfileSchema, req.body, req);

    const user = await User.findById(req.user.id);
    if (!user || user.deleted) {
      logger.warn("User not found", { userId: req.user.id, ip: req.ip });
      throw new ForbiddenError("Doctor account not verified");
    }

    if (req.body.phone && req.body.phone !== user.phone) {
      const exisitingUser = await User.findOne({ phone: req.body.phone });
      if (exisitingUser) {
        logger.warn("Phone already exisit", {
          phone: req.body.phone,
          ip: req.ip,
        });
        throw new ValidationError("Phone number already exist");
      }
    }

    Object.assign(user, req.body);
    await user.save();
    logger.info("Profile updated", {
      userId: user._id,
      externalId: user.externalId,
      ip: req.ip,
    });
    res.json({ message: "Profile updated", user });
  } catch (error) {
    next(error);
  }
};

export const deleteProfile = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user || user.deleted) {
      logger.warn("User not found", { userId: req.user.id, ip: req.ip });
      throw new NotFoundError("User not found");
    }
    user.deleted = true;
    await user.save();
    logger.info("Profile deleted", {
      userId: user._id,
      externalId: user.externalId,
      ip: req.ip,
    });
    res.json({ message: "Profile deleted successfully" });
  } catch (error) {
    next(error);
  }
};
