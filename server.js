import express from "express";
import { connectDB } from "./config/database.js";

const app = express();
app.use(express.json());
connectDB();
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`server running on port ${PORT}`));
