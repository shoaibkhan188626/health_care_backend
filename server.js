import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { connectDB } from "./config/database.js";
import logger from "./config/logger.js";
import authRoutes from "./routes/auth.routes.js";
import { errorHandler } from "./middlewares/ErrorHandler.js";
import { requestLogger } from "./config/logger.js";

const app = express();

app.use(helmet());
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Too many requests please try again",
  })
);

app.use(express.json());
app.use(requestLogger);

connectDB();

app.use("/api/auth", authRoutes);

//health check
app.get("/health", (req, res) =>
  res.json({ status: "ok", service: "user-service" })
);

app.use(errorHandler);

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  logger.info(`USer Service is running on port ${PORT}`);
});
