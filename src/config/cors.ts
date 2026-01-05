// src/config/cors.ts
import cors, { type CorsOptions } from "cors";

function parseEnvOrigins(raw: string | undefined) {
  return (raw || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

export function buildCorsMiddleware() {
  const envOrigins = parseEnvOrigins(process.env.CORS_ORIGIN);

  const allowedOrigins = new Set<string>([
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "https://tptech-frontend.onrender.com",
    ...envOrigins,
  ]);

  const options: CorsOptions = {
    origin: (origin, callback) => {
      // server-to-server / healthchecks sin origin
      if (!origin) return callback(null, true);

      if (allowedOrigins.has(origin)) return callback(null, true);

      return callback(new Error(`CORS bloqueado para origin: ${origin}`));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  };

  return cors(options);
}
