import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import validator from "validator";

const userSchema = new mongoose.Schema(
  {
    externalId: {
      type: String,
      unique: true,
      default: () => new mongoose.Types.ObjectId().toString(),
      index: true,
    },
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
      minlength: [2, "Name must be at least 2 characters"],
      maxlength: [100, "Name cannot exceed 100 characters"],
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      trim: true,
      lowercase: true,
      validate: [validator.isEmail, "Invalid email format"],
      index: true,
    },
    phone: {
      type: String,
      required: [true, "Phone number is required"],
      unique: true,
      trim: true,
      validate: {
        validator: (v) => /^[6-9]\d{9}$/.test(v),
        message:
          "Invalid Indian mobile number (must start with 6-9 and be 10 digits)",
      },
      index: true,
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [8, "Password must be at least 8 characters"],
      select: false,
    },
    role: {
      type: String,
      enum: ["patient", "doctor", "lab", "pharmacy", "admin"],
      default: "patient",
      index: true,
    },
    hospitalId: {
      type: String,
      required: function () {
        return this.role !== "patient";
      },
      validate: {
        validator: (v) => !v || mongoose.isValidObjectId(v),
        message: "Invalid hospital ID",
      },
      index: true,
    },
    address: {
      street: { type: String, trim: true, maxlength: 200 },
      city: { type: String, trim: true, maxlength: 100 },
      state: { type: String, trim: true, maxlength: 100 },
      pincode: {
        type: String,
        trim: true,
        validate: {
          validator: (v) => !v || /^\d{6}$/.test(v),
          message: "Invalid 6-digit pincode",
        },
      },
    },
    location: {
      type: {
        type: String,
        enum: ["Point"],
        default: "Point",
      },
      coordinates: {
        type: [Number], // [longitude, latitude]
        default: [0, 0],
      },
    },
    documents: {
      type: Map,
      of: {
        type: String,
        validate: {
          validator: (v) =>
            v === null || validator.isURL(v) || validator.isMongoId(v),
          message: "Document must be a valid URL or ObjectId",
        },
      },
      default: () =>
        new Map([
          ["aadhar", null],
          ["pan", null],
          ["license", null],
        ]),
    },
    kyc: {
      status: {
        type: String,
        enum: ["pending", "verified", "rejected"],
        default: "pending",
      },
      verifiedBy: {
        type: String,
        validate: {
          validator: (v) => !v || mongoose.isValidObjectId(v),
          message: "Invalid verifiedBy ID",
        },
      },
      verifiedAt: Date,
      rejectionReason: {
        type: String,
        maxlength: 500,
      },
    },
    isVerified: {
      type: Boolean,
      default: function () {
        return this.role !== "doctor";
      },
    },
    notifications: {
      type: [
        {
          type: {
            type: String,
            enum: ["appointment", "lab", "prescription", "system"],
            required: true,
          },
          message: {
            type: String,
            required: true,
            maxlength: 500,
          },
          read: {
            type: Boolean,
            default: false,
          },
          createdAt: {
            type: Date,
            default: Date.now,
          },
        },
      ],
      default: [],
    },
    lastLogin: Date,
    passwordChangedAt: Date,
    passwordResetToken: {
      type: String,
      select: false,
    },
    passwordResetExpires: {
      type: Date,
      select: false,
    },
    deleted: {
      type: Boolean,
      default: false,
      index: true,
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Indexes
userSchema.index({ location: "2dsphere" });
userSchema.index({ "kyc.status": 1 });
userSchema.index({ createdAt: -1 });

// Pre-save hook for password hashing
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  this.passwordChangedAt = new Date();
  next();
});

// Pre-update hook for password updates
userSchema.pre(/^(updateOne|findOneAndUpdate)/, async function (next) {
  const update = this.getUpdate();
  if (update.password) {
    update.password = await bcrypt.hash(update.email, 12);
    update.passwordChangedAt = new Date();
  }
  next();
});

// Compare password
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Check if password changed after JWT issuance
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

export default mongoose.model("User", userSchema);
