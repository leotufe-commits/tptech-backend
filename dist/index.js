import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.routes.js";
import movimientosRoutes from "./routes/movimientos.routes.js";
dotenv.config();
const app = express();
/* =====================
   Proxy (Render)
===================== */
app.set("trust proxy", 1);
/* =====================
   Body parser
===================== */
app.use(express.json({ limit: "1mb" }));
/* =====================
   CORS
===================== */
// Tip: podés setear esto en Render como:
// CORS_ORIGIN=https://tptech-frontend.onrender.com,http://localhost:5173,http://localhost:5174
const envOrigins = (process.env.CORS_ORIGIN || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
const allowedOrigins = [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "https://tptech-frontend.onrender.com",
    ...envOrigins,
];
app.use(cors({
    origin: (origin, callback) => {
        // requests server-to-server / healthchecks sin origin
        if (!origin)
            return callback(null, true);
        if (allowedOrigins.includes(origin))
            return callback(null, true);
        return callback(new Error(`CORS bloqueado para origin: ${origin}`));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
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
app.use("/movimientos", movimientosRoutes);
/* =====================
   Root
===================== */
app.get("/", (_req, res) => {
    res.status(200).send("TPTech Backend OK 🚀");
});
/* =====================
   Error handler (JSON)
===================== */
app.use((err, _req, res, _next) => {
    console.error("🔥 APP ERROR:", err);
    const msg = err?.message || "Error interno.";
    // Si viene de CORS lo devolvemos claro
    const status = msg.startsWith("CORS bloqueado") ? 403 : 500;
    return res.status(status).json({ message: msg });
});
/* =====================
   Server listen
===================== */
const PORT = Number(process.env.PORT) || 3001;
app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Backend running on port ${PORT}`);
});
//# sourceMappingURL=index.js.map