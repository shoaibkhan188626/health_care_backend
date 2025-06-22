import Joi from "joi";

export const registerSchema = Joi.object({
  name: Joi.string().min(2).max(100).required().messages({
    "string.base": "Name must be a string",
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
      "any.required": "Phone Number is required",
    }),

  passwrod: Joi.string().min(8).required().messages({
    "string.min": "Password must be atleast 8 characters long",
    "any.required": "Password is required",
  }),

  role: Joi.string()
    .valid("patient", "doctor", "lab", "pharmacy", "admin")
    .default("patient")
    .messages({
      "any.only": "Invalid role",
    }),

  hospital: Joi.string().optional().allow(null).messages({
    "string.base": "Hospital ID must be a valid ID",
  }),
});

export const loginSchema = Joi.object({
  email: Joi.string().email().required().messages({
    "string.email": "invalid email format",
    "any.required": "Email is required",
  }),
  passwrod: Joi.string().required().messages({
    "any.required": "Password is required",
  }),
});
