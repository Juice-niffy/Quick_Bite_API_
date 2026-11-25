import express from "express";
import {
  register,
  verifyEmail,
  login,
  forgetPassword,
  resetPassword,
} from "../controllers/AuthController.js";

const router = express.Router();

//http://localhost:5000/api/v1/auth/register
router.post("/register", register);

router.get("/verify-email", verifyEmail);
/*router.get("/verifyEmail", verifyEmail);*/

//http://localhost:5000/api/v1/auth/login
router.post("/login", login);

//http://localhost:5000/api/v1/auth/forget-password
router.post("/forgetPassword", forgetPassword);

//http://localhost:5000/api/v1/auth/reset-password
router.post("/reset-password", resetPassword);

export default router;
