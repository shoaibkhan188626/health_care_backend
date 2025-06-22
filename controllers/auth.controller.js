import User from "../models/user.js";
import Joi from "joi";
import dotenv from "dotenv";
import logger from "../config/logger.js";
import crypto from "crypto";
import axios from "axios";
import { v2 as cloudinary } from "cloudinary";
import multer from "multer";
import { Readable } from "stream";
import jwt from "jsonwebtoken";

dotenv.config();

//cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_SECRET_KEY,
  secure: true,
});

//multer for in-memory storage(before cloudinary upload)
const storage = multer.memoryStorage();
const upload = multer({
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ["image/jpeg", "image/png", "application/pdf"];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error("Only JPEG, PNG, and PDF file are allowed"));
    }
    cb(null, true);
  },
});

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
      then: Joi.string().required().messages({
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

//helper function to upload to cloudinary
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
          return reject(error);
        }
        resolve(result.secure_url);
      }
    );
    Readable.from(file.buffer).pipe(stream);
  });
};

export const register = async (req, res) => {
  try {
    const { error } = registerSchema.validate(req.body, { abortEarly: false });
    if (error) {
      logger.warn("Validation failed on regiester", {
        errors: error.details,
        ip: req.ip,
      });
      return res.status(400).json({
        message: "validation failed",
        errors: error.details.map((err) => err.message),
      });
    }

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
      logger.warn("User already exist", { email, phone, ip: req.ip });
      return res.status(400).json({ message: "Email or phone already exists" });
    }

    //validate hospitalID with hospital service
    if (hospitalId) {
      try {
        const hospitalResponse = await axios.get(
          `${process.env.HOSPITAL_SERVICE_URL}/api/hospitals/${hospitalId}`,
          { headers: { "X-Service-Key": process.env } }
        );
        if (!hospitalResponse.data.hospital) {
          logger.warn("Invalid hospital ID", { hospitalId, ip: req.ip });
          return res.status(400).json({ message: "Invalid hospital ID" });
        }
      } catch (error) {
        logger.error("Hospital service error", {
          error: error.message,
          hospitalId,
          ip: req.ip,
        });
        return res
          .status(503)
          .json({ message: "unable to validate hospital ID" });
      }
    }

    //create user
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

    //generate tokens

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

    //notify notification service (placeholder)
    try {
      await axios.post(
        `${process.env.NOTIFICATION_SERVICE_URL}/api/notifications`,
        {
          userId: user.externalId,
          type: "system",
          message: `Welcome to the healthcare ecosystem, ${name}!`,
        },
        { headers: { "X-Service-Key": process.env.SERVICE_KEY } }
      );
    } catch (error) {
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
    logger.error("Register error", { error: error.message, ip: req.ip });
    res.status(500).json({ message: "server error", error: error.message });
  }
};

//login user
export const login = async (req, res) => {
  try {
    const { error } = loginSchema.validate(req.body, { abortEarly: false });
    if (error) {
      logger.warn("validation failed on login", {
        errors: error.details,
        ip: req.ip,
      });
      return res.status(400).json({
        message: "validation failed",
        errors: error.details.map((err) => err.message),
      });
    }

    const { email, password } = req.body;

    //find user
    const user = await User.findOne({ email }).select("+password");
    if (!user || !(await user.comparePassword(password))) {
      logger.warn("invalid credentials", { email, ip: req.ip });
      return res.status(401).json({ message: "invalid email or password" });
    }

    if (user.deleted) {
      logger.warn("Attempte to login with deleted account", {
        email,
        ip: req.ip,
      });
      return res.status(401).json({ message: "Account is de-activated" });
    }

    if (user.role === "doctor" && !user.isVerified) {
      logger.warn("unverified doctor login attempt", { email, ip: req.ip });
      return res
        .status(403)
        .json({ message: "Doctor account is not verified. Complete KYC" });
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
      userOd: user._id,
      externalId: user.externalId,
      role: user.role,
      email,
      ip: req.ip,
    });

    res.json({
      message: "Login Successfull",
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
    logger.log("login error", { error: error.message, ip: req.ip });
    res.status(500).json({ message: "Server error", error: error.message });
  }
};
