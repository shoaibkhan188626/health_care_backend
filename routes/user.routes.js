import express from "express";
import {
  getProfile,
  updateProfile,
  deleteProfile,
} from "../controllers/user.controller.js";
import { authenticate } from "../middlewares/auth.middleware.js";

const router = express.Router();

router.get("/profile", authenticate, getProfile);
router.patch("/profile", authenticate, updateProfile);
router.delete("/profile", authenticate, deleteProfile);
export default router;
