import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { connectDB } from "./config/database.js";
import logger from "./config/logger.js";


const app = express();
app.use(express.json());
connectDB();
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`server running on port ${PORT}`));
