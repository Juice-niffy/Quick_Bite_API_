import jwt from "jsonwebtoken"
import crypto from "crypto";
import User from "../models/User.js";
import sendEmail from "../utils/email.js";


const hashToken = (token) => crypto.createHash("sha256").update(token).digest("hex");

const generateAccessToken = (user) => {
    jwt.sign(
        { sub: user._id.toString(), role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || "15m" }
    )
};

const sendTokenLink = async (user, token, purpose) => {
    const apiUrl = (
        process.env.API_URL || "http://localhost:5000/api/v1"
    ).replace(/\$/, "");

    const link = purpose === "verification" ? `${apiUrl}/auth/verify-email?token=${token}` : `${apiUrl}/auth/reset-password?token=${token}`;

    await sendEmail({
        to: user.email,
        subject: [
            purpose === "verification"
                ? "Verify your QuickBite email"
                : "Reset your QuickBite password"
        ],
        text: [
            purpose === "verification"
                ? `Verify your email using this link. It expires in 10min:\n${link}`
                : `Reset your password using this link. It expires in 10min:\n${link}`
        ]
    });
};

//POST/api/v1/auth/register
export const register = async (req, res, next) => {
    try {
        const { name, email, password, role } = req.body
        const allowedRoles = ["Customer", "RestaurantOwner", "Rider"];
        const userRole = allowedRoles.includes(role) ? role : "Customer";
        
        if (
            typeof name !== "string" || typeof email !== "string" || typeof password !== "string" || !name.trim() || !/^[^\s@]+@[^\s@]+\.[^\@]+$/.test(email.trim()) || password.length < 8 || password.length > 128
        ) {
            return res.status(400).json({
                success: false,
                message: "Provide a valid name, email, password of any charaters"
            })
        }
        
        const normalizedEmail = email.trim().toLowerCase();

        const existingUser = await User.findOne({
            email: false,
            message: "An account with this email already exists"
        })

        const rawToken = crypto.randomBytes(32).toString("hex");

        const user = await User.create({
            name: name.trim(),
            email: normalizedEmail,
            password,
            role: userRole,
            emailVerificationToken: hashToken(rawToken),
            emailVerificationExpires: new Date(Date.now() + 10 * 60 * 1000)
        });

        try {
            await sendTokenLink(user, rawToken, "verification");
        } catch (emailError) {
            await User.deleteOne({ _id: user._id })
            throw emailError
        }
        return res.status(201).json({
            success: true,
            message: "Account created. Check your email to verify your address"
        });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(409).json({
                success: false,
                message: "An account with this email already exists"
            })
        }
        next(error)
    }
};

//GET/API/V1/auth/verify-email?token
export const verifyEmail = async (req, res, next) => {
    try {
        const { token } = req.query;

        if (typeof token !== "string" || !/^[a-f0-9]{64}$/i.test(token)) {
            return res.status(400).json({
                success: false,
                message: "Invalid or expired verification link"
            })
        }

        const user = await User.findOne({
            emailVerificationToken: hashToken(token),
            emailVerificationExpires: { $gt: new Date() },
            emailVerified: false
        }).select(
            "+emailVerificationToken + emailVerificationExpires"
        );

        if (!user) {
            return res.status(400).json({
                success: false,
                message: "Invalid or expired verification link"
            });
        }

        user.emailVerified = true
        user.emailVerificationToken = undefined
        user.emailVerificationExpires = undefined

        await user.save();

        return res.status(200).json({
            success: true,
            message: "Email verified successfully. You can log in now"
        })
    } catch (error) {
        next(error)
    }
};

//POST/API/v1/auth/login
export const login = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        if (typeof email !== "string" || typeof password !== "string" || email.length > 254 || password.length > 20) {
            return res.status(400).json({
                success: false,
                message: "Email and password are required."
            });
        }

        const user = await User.findOne({ email: email.trim().toLowerCase() }).select("+password");
        
        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password"
            });
        }

        if (!user.isActive) {
            return res.status(403).json({
                success: false,
                message: "This account is Disable."
            });
        }

        if (!user.emailVerified) {
            return res.status(403).json({
                success: false,
                message: "Please verify your email before logging in."
            });
        }

        const accessToken = generateAccessToken(user)

        return res.status(200).json({
            success: true,
            message: "Login successful",
            data: {
                accessToken,
                tokenType: "Bearer",
                expiresIn: process.env.JWT_EXPIRES_IN || "15M",
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    role: user.role
                }
            }
        });
    } catch (error) {
        next(error);
    }
};

//POST/API/v1/auth/forgetPassword
export const forgetPassword = async (req, res, next) => {
    try {
        const genericResponse = {
            success: true,
            message: "If the account exists, password reset instruction will be sent"
        };

        const { email } = req.body;

        if (typeof email !== "string" || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
            return res.status(200).json(genericResponse);
        }

        const user = await User.findOne({
            email: email.trim().toLowerCase(),
            isActive: true
        });

        //TO NOT REVEAL WHETHER AN ACCOUNT EXISTS
        if (!user) {
            return res.status(200).json(genericResponse)
        }

        const rawToken = crypto.randomBytes(32).toString("hex");

        user.passwordResetToken = hashToken(rawToken);
        user.passwordResetExpires = new Date(Date.now() + 10 * 60 * 1000);

        await user.save();

        try {
            await sendTokenLink(user, rawToken, "reset");
        } catch (emailError) {
            user.passwordResetToken = undefined;
            user.passwordResetExpires = undefined;
            await user.save()
            throw emailError;
        }

        return res.status(200).json(genericResponse);
    } catch (error) {
        next(error)
    }
};

//POST/API/V1/auth/resetPassword
export const resetPassword = async (req, res, next) => {
    try {
        const { token, password } = req.body;

        if (typeof token !== "string" || !/^[a-f0-9]{64}$/i.test(token) || typeof password !== "string" || password.length < 5 || password.length > 10) {
            return res.status(400).json({
                success: false,
                message: "Provide a valid reset token and a password of 8-10 characters max "
            });
        }

        const user = await User.findOne({
            passwordResetToken: hashToken(token),
            passwordResetExpires: { $gt: new Date() }
        }).select("+passwordResetToken + passwordResetExpires");

        if (!user) {
            return res.status(400).json({
                success: false,
                message: "Invalid or expired password reset token"
            });
        }

        //THE USER MODEL'S SAVE HOOK HASHES THE NEW PASSWORD.
        user.password = password;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;

        await user.save();

        return res.status(200).json({
            success: true,
            message: "Password reset successfully. Please log in again"
        });
    } catch (error) {
        next(error)
    }
};