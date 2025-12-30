"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const dotenv_1 = __importDefault(require("dotenv"));
const auth_routes_1 = __importDefault(require("./routes/auth.routes"));
dotenv_1.default.config();
const app = (0, express_1.default)();
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
app.use((0, cors_1.default)({
    origin: allowedOrigins,
    credentials: true,
}));
app.use(express_1.default.json());
// Rutas
app.use("/auth", auth_routes_1.default);
app.get("/", (req, res) => {
    res.send("TPTech Backend OK 🚀");
});
const PORT = Number(process.env.PORT) || 3001;
app.listen(PORT, () => {
    console.log(`Backend corriendo en http://localhost:${PORT}`);
});
