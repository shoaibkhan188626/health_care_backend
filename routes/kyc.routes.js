import express from "express";
import {
  uploadKycDocuments,
  verifyKyc,
} from "../controllers/kyc.controller.js";
import { authenticate, restrictInfo } from "../middlewares/auth.middleware.js";

const router = express.Router();

router.post("/upload", authenticate, uploadKycDocuments);
router.post("/verify", authenticate, restrictInfo("admin"), verifyKyc);
export default router;
