import jwt from "jsonwebtoken"
import User from "../models/User"

export const protect = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer")) {
            return res.status(401).json({
                success: false,
                message: "Authentication required"
            })
        }

        const token = authHeader.slice(7);

        const decoded = jwt.verify(token, process.env.JWT_SECRET, {
            algorithms: ["HS256"]
        })

        const user = await User.findById(decoded.sub);

        if (!user || !user.isActive || !user.emailVerified) {
            return res.status(401).json({
                success: false,
                message: "Invalid or Inactive account"
            })
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: " Invalid or expired access token"
        })
    }
}

export const authorize = (...roles) => (req, res, next) => {
    if (!req.user || !roles.includes(req.user.roles)) {
        return res.status(403).json({
            success: false,
            message: "You do not have permission to perform this action"
        })
    }

    next();
}