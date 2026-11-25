import express from "express";
import cors from "cors"
import helmet from "helmet";

import authRoutes from "./routes/AuthRoute.js"

const app = express();

app.use(express.json({limit: "10kb"}))
app.use(helmet())
app.use(cors());

app.get("/api/v1/health", (req, res) => {
    res.status(200).json({
        success: true,
        message: "QuickBite Api is Running"
    })
});

app.use("/api/v1/auth", authRoutes);

//HANDLE UNMATCHED ROUTES
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: "Route not found"
    })
});

//CENTRAL ERROR HANDLER.
app.use((err, req, res, next) => {
    console.error(err);
    
    if (res.headerSent) {
        return next(err)
    }

    if (err.name === "ValidationError") {
        return res.status(400).json({
            success: false,
            message: "Validation failed",
            errors: Object.values(err.errors).map((item) => item.message)
        });
    }

    res.status(500).json({
        success: true,
        message: "Internal server error"
    });
});

export default app