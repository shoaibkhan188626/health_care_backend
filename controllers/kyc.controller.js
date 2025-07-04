import User from "../models/user.js";
import { validate } from "../utils/validate.js";
import {
  ValidationError,
  ForbiddenError,
  NotFoundError,
  AppError,
} from "../utils/error.js";
import logger from "../config/logger.js";
import { v2 as cloudinary } from "cloudinary";
import multer from "multer";
import httpClient from "../utils/httpclient.js";
import Joi from "joi";
import mongoose from "mongoose";
import pkg from 'supertest/lib/test.js';


const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ["image/jpeg", "image/png", "application/pdf"];
    if (!allowedTypes) {
      return cb(new ValidationError("Only JPEG,PNG and PDF file are allowed"));
    }
    cb(null, true);
  },
});

const verifyKycSchema = Joi.object({
  userId: Joi.string()
    .required()
    .custom((value, helpers) => {
      if (!mongoose.isValidObjectId(value)) {
        return helpers.error("any.invalid", { message: "invalid user ID" });
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
          return reject(new AppError("Failed to upload Cloudinary", 500));
        }
        resolve(result.secure_url);
      },
    );
    Readable.from(file.buffer).pipe(stream);
  });
};

export const uploadKycDocuments = async (req, res, next) => {
  try {
    upload.fields([
      { name: "adhar", maxCount: 1 },
      { name: "pan", maxCount: 1 },
      { name: "license", maxCount: 1 },
    ])(req, res, async (err) => {
      if (err) {
        logger.warn("Kyc upload error", {
          error: err.message,
          userId: req.user.id,
          ip: req.ip,
        });
        return next(new ValidationError(err.message));
      }
      const user = await User.findById(req.user.id);
      if (user.role !== "doctor") {
        logger.warn("Non- doctors attempted KYC upload", {
          userId: user._id,
          role: user.role,
          ip: req.ip,
        });
        throw new ForbiddenError("Only doctors can upload KYC documents");
      }
      const { adhar, pan, license } = req.files;
      try {
        if (adhar) {
          const url = await uploadToCloudinary(adhar[0], user._id);
          user.documents.set("adhar", url);
        }
        if (pan) {
          const url = await uploadToCloudinary(pan[0], user._id);
          user.documents.set("pan", url);
        }
        if (license) {
          const url = await uploadToCloudinary(license[0], user._id);
          user.documents.set("license", url);
        }
      } catch (error) {
        return next(error);
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
            type: `KYC documents uploaded by ${user.name}(Doctor) awaiting verification`,
          },
        );
      } catch (error) {
        logger.warn("Failed to notify admin of KYC upload", {
          userId: user._id,
          error: error.message,
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

export const verifyKyc = async (req, res, next) => {
  try {
    validate(verifyKycSchema, req.body, req);

    if (req.user.role !== "admin") {
      logger.warn("Non-admin attempted KYC verification", {
        userId: req.user.id,
        role: req.user.role,
        ip: req.ip,
      });
      throw new ForbiddenError("Only admins can verify kyc");
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
          message: `your KYC has been ${status}. ${status === "rejected" ? `Reason:${rejectionReason}` : ""}`,
        },
      );
      logger.info("KYC verification completed", {
        userId: user._id,
        externalId: user.externalId,
        status,
        ip: req.ip,
      });
    } catch (error) {
      logger.warn("Failed to notify doctor of KYC status", {
        userId: user._id,
        error: error.message,
      });
    }
    res.json({ message: `KYC ${status} successfully` });
  } catch (error) {
    next(error);
  }
};
