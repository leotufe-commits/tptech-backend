import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.routes.js";
dotenv.config();
const app = express();
/* =====================
   Body parser
===================== */
app.use(express.json());
/* =====================
   CORS
===================== */
const allowedOrigins = [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "https://tptech-frontend.onrender.com",
];
app.use(cors({
    origin: (origin, callback) => {
        // Permite requests sin origin (Postman, curl, server-to-server)
        if (!origin)
            return callback(null, true);
        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        return callback(new Error(`CORS bloqueado para origin: ${origin}`));
    },
    credentials: true,
}));
/* =====================
   Health check
===================== */
app.get("/health", (_req, res) => {
    res.status(200).json({ ok: true, service: "tptech-backend" });
});
/* =====================
   Routes
===================== */
app.use("/auth", authRoutes);
/* =====================
   Root
===================== */
app.get("/", (_req, res) => {
    res.status(200).send("TPTech Backend OK 🚀");
});
/* =====================
   Server listen (Render)
===================== */
const PORT = Number(process.env.PORT) || 3001;
app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Backend running on port ${PORT}`);
});
