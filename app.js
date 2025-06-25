import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { errorHandler } from "./middlewares/ErrorHandler.js";
import { requestLogger } from "./config/logger.js";
import authRoutes from "./routes/auth.routes.js";
import kycRoutes from "./routes/kyc.routes.js";
import userRoutes from "./routes/user.routes.js";

const app = express();

app.use(helmet());

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "too many request please try again later",
  }),
);

app.use(express.json());
app.use(requestLogger);

app.use("/api/auth", authRoutes);
app.use("/api/kyc", kycRoutes);
app.use("/api/users", userRoutes);

app.get("/health", (req, res) =>
  res.json({ status: "ok", service: "user-service" }),
);

app.use(errorHandler);
export default app;
