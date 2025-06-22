import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import logger from "../config/logger.js";

dotenv.config();

export const authenticate = async (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer", "");
  if (!token) {
    logger.warn("No token provided", { path: req.path });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    logger.error("Invalid token", { error: error.message, path: req.path });
    res.status(401).json({ message: "invalid token" });
  }
};
