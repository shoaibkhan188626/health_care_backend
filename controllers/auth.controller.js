import User from "../models/user.js";
import Joi from "joi";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import logger from "../config/logger.js";
import { v2 as cloudinary } from "cloudinary";
import multer from "multer";
import { Readable } from "stream";
import { validate } from "../utils/validate.js";
import {
  ValidationError,
  UnauthorizedError,
  NotFoundError,
  ForbiddenError,
} from "../utils/error.js";
import { generateToken, hashToken } from "../utils/crypto.js";
import httpClient from "../utils/httpClient.js";
import mongoose from "mongoose";

// Configure Cloudinary
dotenv.config();
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});

// Multer for in-memory storage
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ["image/jpeg", "image/png", "application/pdf"];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(
        new ValidationError("Only JPEG, PNG, and PDF files are allowed")
      );
    }
    cb(null, true);
  },
});

// Validation schemas
const registerSchema = Joi.object({
  name: Joi.string().min(2).max(100).required().messages({
    "string.min": "Name must be at least 2 characters",
    "string.max": "Name cannot exceed 100 characters",
    "any.required": "Name is required",
  }),
  email: Joi.string().email().required().messages({
    "string.email": "Invalid email format",
    "any.required": "Email is required",
  }),
  phone: Joi.string()
    .pattern(/^[6-9]\d{9}$/)
    .required()
    .messages({
      "string.pattern.base":
        "Invalid Indian mobile number (must start with 6-9 and be 10 digits)",
      "any.required": "Phone number is required",
    }),
  password: Joi.string().min(8).required().messages({
    "string.min": "Password must be at least 8 characters",
    "any.required": "Password is required",
  }),
  role: Joi.string()
    .valid("patient", "doctor", "lab", "pharmacy", "admin")
    .default("patient"),
  hospitalId: Joi.string()
    .when("role", {
      is: Joi.string().valid("doctor", "lab", "pharmacy", "admin"),
      then: Joi.string()
        .required()
        .messages({
          "any.required": "Hospital ID is required for non-patients",
        }),
      otherwise: Joi.forbidden(),
    })
    .custom((value, helpers) => {
      if (value && !mongoose.isValidObjectId(value)) {
        return helpers.error("any.invalid", { message: "Invalid hospital ID" });
      }
      return value;
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

const loginSchema = Joi.object({
  email: Joi.string().email().required().messages({
    "string.email": "Invalid email format",
    "any.required": "Email is required",
  }),
  password: Joi.string().required().messages({
    "any.required": "Password is required",
  }),
});

const passwordResetSchema = Joi.object({
  email: Joi.string().email().required().messages({
    "string.email": "Invalid email format",
    "any.required": "Email is required",
  }),
});

const resetPasswordSchema = Joi.object({
  token: Joi.string().required().messages({
    "any.required": "Reset token is required",
  }),
  password: Joi.string().min(8).required().messages({
    "string.min": "Password must be at least 8 characters",
    "any.required": "Password is required",
  }),
});

const refreshTokenSchema = Joi.object({
  refreshToken: Joi.string().required().messages({
    "any.required": "Refresh token is required",
  }),
});

const verifyKycSchema = Joi.object({
  userId: Joi.string()
    .required()
    .custom((value, helpers) => {
      if (!mongoose.isValidObjectId(value)) {
        return helpers.error("any.invalid", { message: "Invalid user ID" });
      }
      return value;
    }),
  status: Joi.string().valid("verified", "rejected").required(),
  rejectionReason: Joi.string().max(500).when("status", {
    is: "rejected",
    then: Joi.required(),
    otherwise: Joi.forbidden(),
  }),
});

// Helper function to upload to Cloudinary
const uploadToCloudinary = (file, userId) => {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      {
        folder: `healthcare/kyc/${userId}`,
        resource_type: "auto",
        access_mode: "authenticated",
      },
      (error, result) => {
        if (error) {
          logger.error("Cloudinary upload failed", {
            error: error.message,
            userId,
          });
          return reject(new AppError("Failed to upload to Cloudinary", 500));
        }
        resolve(result.secure_url);
      }
    );
    Readable.from(file.buffer).pipe(stream);
  });
};

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

// Upload KYC documents
export const uploadKycDocuments = async (req, res, next) => {
  try {
    upload.fields([
      { name: "aadhar", maxCount: 1 },
      { name: "pan", maxCount: 1 },
      { name: "license", maxCount: 1 },
    ])(req, res, async (err) => {
      if (err) {
        logger.warn("KYC upload error", {
          error: err.message,
          userId: req.user.id,
          ip: req.ip,
        });
        return next(new ValidationError(err.message));
      }

      const user = await User.findById(req.user.id);
      if (user.role !== "doctor") {
        logger.warn("Non-doctor attempted KYC upload", {
          userId: user._id,
          role: user.role,
          ip: req.ip,
        });
        throw new ForbiddenError("Only doctors can upload KYC documents");
      }

      const { aadhar, pan, license } = req.files;

      try {
        if (aadhar) {
          const url = await uploadToCloudinary(aadhar[0], user._id);
          user.documents.set("aadhar", url);
        }
        if (pan) {
          const url = await uploadToCloudinary(pan[0], user._id);
          user.documents.set("pan", url);
        }
        if (license) {
          const url = await uploadToCloudinary(license[0], user._id);
          user.documents.set("license", url);
        }
      } catch (err) {
        return next(err);
      }

      user.kyc.status = "pending";
      await user.save();

      logger.info("KYC documents uploaded", {
        userId: user._id,
        externalId: user.externalId,
        email: user.email,
        ip: req.ip,
      });

      try {
        await httpClient.post(
          `${process.env.NOTIFICATION_SERVICE_URL}/api/notifications`,
          {
            userId: user.externalId,
            type: "system",
            message: `KYC documents uploaded by ${user.name} (Doctor) awaiting verification.`,
          }
        );
      } catch (err) {
        logger.warn("Failed to notify admin of KYC upload", {
          userId: user._id,
          error: err.message,
        });
      }

      res.json({
        message: "KYC documents uploaded successfully, awaiting verification",
      });
    });
  } catch (error) {
    next(error);
  }
};

// Verify KYC
export const verifyKyc = async (req, res, next) => {
  try {
    validate(verifyKycSchema, req.body, req);

    if (req.user.role !== "admin") {
      logger.warn("Non-admin attempted KYC verification", {
        userId: req.user.id,
        role: req.user.role,
        ip: req.ip,
      });
      throw new ForbiddenError("Only admins can verify KYC");
    }

    const { userId, status, rejectionReason } = req.body;
    const user = await User.findById(userId);
    if (!user || user.role !== "doctor") {
      logger.warn("Doctor not found for KYC verification", {
        userId,
        ip: req.ip,
      });
      throw new NotFoundError("Doctor not found");
    }

    user.kyc.status = status;
    user.kyc.verifiedBy = req.user.id;
    user.kyc.verifiedAt = status === "verified" ? new Date() : null;
    user.kyc.rejectionReason = status === "rejected" ? rejectionReason : null;
    user.isVerified = status === "verified";
    await user.save();

    try {
      await httpClient.post(
        `${process.env.NOTIFICATION_SERVICE_URL}/api/notifications`,
        {
          userId: user.externalId,
          type: "system",
          message: `Your KYC has been ${status}. ${status === "rejected" ? `Reason: ${rejectionReason}` : ""}`,
        }
      );
      logger.info("KYC verification completed", {
        userId: user._id,
        externalId: user.externalId,
        status,
        ip: req.ip,
      });
    } catch (err) {
      logger.warn("Failed to notify doctor of KYC status", {
        userId: user._id,
        error: err.message,
      });
    }

    res.json({ message: `KYC ${status} successfully` });
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
  uploadKycDocuments,
  verifyKyc,
};
