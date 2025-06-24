import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import logger from "../config/logger.js";

dotenv.config();

export const authenticate = async (req, res, next) => {
  try {
    const token = req.header("Authorize")?.replace("Bearer", "");
    if (!token) {
      logger.warn("No token provided", {
        path: req.path,
        method: req.method,
        tp: req.ip,
      });
      return res.status(401).json({ message: "No token provided" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    logger.info("Token verified", {
      userId: decoded.id,
      externalId: decoded.externalId,
      path: req.path,
      ip: req.ip,
    });
    next();
  } catch (error) {
    logger.error("Invalid token", {
      error: error.message,
      path: req.path,
      ip: req.ip,
    });
    res.status(401).json({ message: "Invalid or expired token" });
  }
};

export const restrictInfo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      logger.warn("Unauthorized role access", {
        userId: req.user.id,
        role: req.user.role,
        requiredRoles: roles,
        path: req.path,
        ip: req.ip,
      });
      return res
        .status(403)
        .json({ message: "Access denied : insufficient permission" });
    }
    next();
  };
};
