import Joi from "joi";
import { ValidationError } from "./error.js";
import logger from "../config/logger.js";

export const validate = (schema, data, req) => {
  const { error } = schema.validate(data, { abortEarly: false });
  if (error) {
    logger.warn("Validation failed", {
      errors: error.details.map((err) => err.message),
      ip: req.ip,
      userId: req.user?.id,
    });
    throw new ValidationError(
      `Validation failed: ${error.details.map((err) => err.message).join(", ")}`,
    );
  }
  return true;
};
