import cron from "node-cron";
import User from "../models/user.js";
import logger from "../config/logger.js";

export const cleanupExpiredTokens = () => {
  cron.schedule("0 0 * * * *", async () => {
    try {
      const result = await User.updateMany(
        { passwordResetExpires: { $lt: Date.now() } },
        { $unset: { passwordResetToken: "", passwordResetExpires: "" } }
      );
      logger.info("Cleaned up expired password reset token", {
        modifiedCount: result.modifiedCount,
      });
    } catch (error) {
      logger.error("Cleanup job failed", { error: error.message });
    }
  });
};
