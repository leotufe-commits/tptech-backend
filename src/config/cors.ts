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

      // ✅ debug real en logs
      console.error("❌ CORS bloqueado para origin:", origin, "allowed:", Array.from(allowedOrigins));
      return callback(new Error(`CORS bloqueado para origin: ${origin}`));
    },

    // ✅ clave para cookies httpOnly
    credentials: true,

    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],

    // ✅ mejor NO fijarlo para evitar preflights que fallen por headers extras
    // allowedHeaders: ["Content-Type", "Authorization", "Accept", "Origin", "X-Requested-With"],

    optionsSuccessStatus: 204,
  };

  return cors(options);
}
