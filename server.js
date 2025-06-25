import app from "./app.js";
import { connectDB } from "./config/database.js";
import logger from "./config/logger.js";
import { cleanupExpiredTokens } from "./jobs/cleanup.js";

const PORT = process.env.PORT || 5001;
connectDB();
cleanupExpiredTokens();
app.listen(PORT, () => {
  logger.info(`User service running on port ${PORT}`);
});
