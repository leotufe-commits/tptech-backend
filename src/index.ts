import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.routes.js";

dotenv.config();

const app = express();

/** Body JSON */
app.use(express.json());

/**
 * CORS
 * - En local permite localhost:5173/5174
 * - En prod usa CORS_ORIGIN (puede ser 1 o varios separados por coma)
 *   CORS_ORIGIN="https://tptech-web.onrender.com,https://otro-dominio.com"
 */
const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(",").map((s) => s.trim())
  : [
      "http://localhost:5174",
      "http://127.0.0.1:5174",
      "http://localhost:5173",
      "http://127.0.0.1:5173",
    ];

app.use(
  cors({
    origin: (origin, callback) => {
      // Permitir requests sin origin (Postman/curl/server-to-server)
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) return callback(null, true);

      return callback(new Error(`CORS bloqueado para origin: ${origin}`));
    },
    credentials: true,
  })
);

/** Health simple para probar que el server responde */
app.get("/health", (_req, res) => {
  res.status(200).json({ ok: true, service: "tptech-backend" });
});

/** Rutas */
app.use("/auth", authRoutes);

/** Root */
app.get("/", (_req, res) => {
  res.status(200).send("TPTech Backend OK 🚀");
});

/** Listen (IMPORTANTE para Render) */
const PORT = Number(process.env.PORT) || 3001;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Listening on port ${PORT}`);
});
