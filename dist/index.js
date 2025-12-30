import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.routes.js";
dotenv.config();
const app = express();
/**
 * CORS:
 * - En local permite localhost:5173/5174
 * - En producción usa CORS_ORIGIN (por ejemplo: https://tu-frontend.vercel.app)
 * - Si querés más de un dominio en producción: separalos con coma
 *   CORS_ORIGIN="https://a.com,https://b.com"
 */
const allowedOrigins = process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(",").map((s) => s.trim())
    : [
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ];
app.use(cors({
    origin: allowedOrigins,
    credentials: true,
}));
app.use(express.json());
// Rutas
app.use("/auth", authRoutes);
app.get("/", (req, res) => {
    res.send("TPTech Backend OK 🚀");
});
const PORT = Number(process.env.PORT) || 3001;
app.listen(PORT, () => {
    console.log(`Backend corriendo en http://localhost:${PORT}`);
});
