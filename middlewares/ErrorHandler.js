import logger from "../config/logger.js";

export const errorHandler = (err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || "Internal server error";

  logger.error("Error occured", {
    error: message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    userId: req.user?.id,
    externalId: req.user?.externalId,
    ip: req.ip,
  });
  res.status(statusCode).json({
    message,
    ...(process.env.NODE_ENV !== "production" && { stack: err.stack }),
  });
};
