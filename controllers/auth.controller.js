import User from "../models/user.js";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import logger from "../config/logger.js";
import { validate } from "../utils/validate.js";
import {
  ValidationError,
  UnauthorizedError,
  NotFoundError,
  ForbiddenError,
} from "../utils/error.js";
import { generateToken, hashToken } from "../utils/crypto.js";
import httpClient from "../utils/httpclient.js";
import mongoose from "mongoose";
import {
  registerSchema,
  loginSchema,
  passwordResetSchema,
  resetPasswordSchema,
  refreshTokenSchema,
} from "../validations/auth.validation.js";

// Configure environment
dotenv.config();

// Register user
export const register = async (req, res, next) => {
  try {
    validate(registerSchema, req.body, req);

    const {
      name,
      email,
      phone,
      password,
      role,
      hospitalId,
      address,
      location,
    } = req.body;

    const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
    if (existingUser) {
      logger.warn("User already exists", { email, phone, ip: req.ip });
      throw new ValidationError("Email or phone already exists");
    }

    if (hospitalId) {
      try {
        const response = await httpClient.get(
          `${process.env.HOSPITAL_SERVICE_URL}/api/hospitals/${hospitalId}`
        );
        if (!response.data.hospital) {
          logger.warn("Invalid hospital ID", { hospitalId, ip: req.ip });
          throw new ValidationError("Invalid hospital ID");
        }
      } catch (err) {
        logger.error("Hospital service error", {
          error: err.message,
          hospitalId,
          ip: req.ip,
        });
        throw new AppError("Unable to validate hospital ID", 503);
      }
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
    logger.info("User registered", {
      userId: user._id,
      externalId: user.externalId,
      role,
      email,
      ip: req.ip,
    });

    const accessToken = jwt.sign(
      {
        id: user._id,
        externalId: user.externalId,
        role: user.role,
        hospitalId: user.hospitalId,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    const refreshToken = jwt.sign(
      { id: user._id, externalId: user.externalId },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "30d" }
    );

    try {
      await httpClient.post(
        `${process.env.NOTIFICATION_SERVICE_URL}/api/notifications`,
        {
          userId: user.externalId,
          type: "system",
          message: `Welcome to the healthcare ecosystem, ${name}!`,
        }
      );
    } catch (err) {
      logger.warn("Failed to send welcome notification", {
        userId: user._id,
        error: err.message,
      });
    }

    res.status(201).json({
      message: "User registered successfully",
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        externalId: user.externalId,
        name,
        email,
        role,
        isVerified: user.isVerified,
      },
    });
  } catch (error) {
    next(error);
  }
};

// Login user
export const login = async (req, res, next) => {
  try {
    validate(loginSchema, req.body, req);

    const { email, password } = req.body;

    const user = await User.findOne({ email }).select("+password");
    if (!user || !(await user.comparePassword(password))) {
      logger.warn("Invalid credentials", { email, ip: req.ip });
      throw new UnauthorizedError("Invalid email or password");
    }

    if (user.deleted) {
      logger.warn("Attempt to login with deleted account", {
        email,
        ip: req.ip,
      });
      throw new ForbiddenError("Account is deactivated");
    }

    if (user.role === "doctor" && !user.isVerified) {
      logger.warn("Unverified doctor login attempt", { email, ip: req.ip });
      throw new ForbiddenError("Doctor account not verified. Complete KYC.");
    }

    user.lastLogin = new Date();
    await user.save();

    const accessToken = jwt.sign(
      {
        id: user._id,
        externalId: user.externalId,
        role: user.role,
        hospitalId: user.hospitalId,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    const refreshToken = jwt.sign(
      { id: user._id, externalId: user.externalId },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "30d" }
    );

    logger.info("User logged in", {
      userId: user._id,
      externalId: user.externalId,
      role: user.role,
      email,
      ip: req.ip,
    });

    res.json({
      message: "Login successful",
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        externalId: user.externalId,
        name: user.name,
        email,
        role: user.role,
        isVerified: user.isVerified,
      },
    });
  } catch (error) {
    next(error);
  }
};

// Logout
export const logout = async (req, res, next) => {
  try {
    logger.info("User logged out", {
      userId: req.user.id,
      externalId: req.user.externalId,
      ip: req.ip,
    });
    res.json({ message: "Logout successful" });
  } catch (error) {
    next(error);
  }
};

// Request password reset
export const requestPasswordReset = async (req, res, next) => {
  try {
    validate(passwordResetSchema, req.body, req);

    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user || user.deleted) {
      logger.warn("Password reset requested for non-existent or deleted user", {
        email,
        ip: req.ip,
      });
      throw new NotFoundError("User not found");
    }

    const resetToken = generateToken();
    const hashedToken = hashToken(resetToken);

    user.passwordResetToken = hashedToken;
    user.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    try {
      await httpClient.post(
        `${process.env.NOTIFICATION_SERVICE_URL}/api/notifications`,
        {
          userId: user.externalId,
          type: "system",
          message: `Password reset requested. Click here to reset: ${resetUrl}`,
        }
      );
      logger.info("Password reset email sent", {
        userId: user._id,
        externalId: user.externalId,
        email,
        ip: req.ip,
      });
    } catch (err) {
      logger.warn("Failed to send password reset notification", {
        userId: user._id,
        error: err.message,
      });
      throw new AppError("Failed to send reset email", 500);
    }

    res.json({ message: "Password reset email sent" });
  } catch (error) {
    next(error);
  }
};

// Reset password
export const resetPassword = async (req, res, next) => {
  try {
    validate(resetPasswordSchema, req.body, req);

    const { token, password } = req.body;
    const hashedToken = hashToken(token);

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
      logger.warn("Invalid or expired reset token", { ip: req.ip });
      throw new ValidationError("Invalid or expired reset token");
    }

    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    logger.info("Password reset successful", {
      userId: user._id,
      externalId: user.externalId,
      email: user.email,
      ip: req.ip,
    });

    res.json({ message: "Password reset successful" });
  } catch (error) {
    next(error);
  }
};

// Refresh token
export const refreshToken = async (req, res, next) => {
  try {
    validate(refreshTokenSchema, req.body, req);

    const { refreshToken } = req.body;

    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch (err) {
      logger.warn("Invalid refresh token", { ip: req.ip });
      throw new UnauthorizedError("Invalid refresh token");
    }

    const user = await User.findById(decoded.id);
    if (!user || user.deleted) {
      logger.warn("User not found for refresh token", {
        userId: decoded.id,
        ip: req.ip,
      });
      throw new NotFoundError("User not found");
    }

    if (user.role === "doctor" && !user.isVerified) {
      logger.warn("Unverified doctor refresh attempt", {
        userId: user._id,
        ip: req.ip,
      });
      throw new ForbiddenError("Doctor account not verified");
    }

    const accessToken = jwt.sign(
      {
        id: user._id,
        externalId: user.externalId,
        role: user.role,
        hospitalId: user.hospitalId,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    logger.info("Access token refreshed", {
      userId: user._id,
      externalId: user.externalId,
      email: user.email,
      ip: req.ip,
    });

    res.json({ message: "Token refreshed", accessToken });
  } catch (error) {
    next(error);
  }
};

export {
  register,
  login,
  logout,
  requestPasswordReset,
  resetPassword,
  refreshToken,
};
