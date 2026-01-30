// tptech-backend/src/config/cors.ts
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
      // same-origin / server-to-server / curl
      if (!origin) return callback(null, true);

      if (allowedOrigins.has(origin)) return callback(null, true);

      // ✅ devolver error explícito (facilita debug en prod)
      return callback(new Error(`CORS bloqueado para origin: ${origin}`));
    },

    // ✅ clave para cookies httpOnly en cross-site
    credentials: true,

    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],

    // ✅ más tolerante (evita preflights inesperados que pueden fallar en algunos proxies)
    allowedHeaders: ["Content-Type", "Authorization", "Accept", "Origin", "X-Requested-With"],

    optionsSuccessStatus: 204,
  };

  return cors(options);
}
