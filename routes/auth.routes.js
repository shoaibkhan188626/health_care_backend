import express from "express";
import {
  register,
  login,
  logout,
  requestPasswordReset,
  resetPassword,
  refreshToken,
} from "../controllers/auth.controller.js";

import { authenticate, restrictInfo } from "../middlewares/auth.middleware.js";

const router = express.Router();

router.post("/register", register);
router.post("/", login);
router.post("/", authenticate, logout);
router.post("/password-reset", requestPasswordReset);
router.post("/", resetPassword);
router.post("/refresh", refreshToken);



export default router;
