// tptech-backend/src/app.ts
import express from "express";
import cookieParser from "cookie-parser";
import path from "node:path";

import routes from "./routes/index.js";
import { requestContextMiddleware } from "./lib/prisma.js";
import { perfLogger } from "./middlewares/perfLogger.js";
import { errorHandler } from "./middlewares/errorHandler.js";
import { buildCorsMiddleware } from "./config/cors.js";
import { buildHelmetMiddleware, buildRateLimitMiddleware } from "./config/security.js";

export function createApp() {
  const app = express();

  /* =====================
     Proxy (Render)
     ✅ antes de todo lo que use req.protocol / secure cookies
  ===================== */
  app.set("trust proxy", 1);

  /* =====================
     Seguridad básica
  ===================== */
  app.disable("x-powered-by");
  app.use(buildHelmetMiddleware());

  /* =====================
     CORS (con credentials)
     ✅ bien arriba para que preflights respondan siempre con headers
     ✅ REUTILIZAR la misma instancia (no llamar 2 veces buildCorsMiddleware)
  ===================== */
  const corsMw = buildCorsMiddleware();
  app.use(corsMw);

  // ✅ FIX: "*" rompe en path-to-regexp nuevo
  // Usá regex para matchear todo
  app.options(/.*/, corsMw);

  /* =====================
     Parsers
  ===================== */
  app.use(express.json({ limit: "1mb" }));
  app.use(express.urlencoded({ extended: true, limit: "1mb" }));
  app.use(cookieParser());

  /* =====================
     Request Context (ALS)
     ⚠️ antes de rutas
  ===================== */
  app.use(requestContextMiddleware);

  /* =====================
     PERF logger (auditoría)
  ===================== */
  app.use(perfLogger({ slowMs: 700 }));

  /* =====================
     Static: uploads
  ===================== */
  const UPLOADS_DIR = path.join(process.cwd(), "uploads");

  app.use(
    "/uploads",
    express.static(UPLOADS_DIR, {
      index: false,
      fallthrough: false,
      setHeaders(res) {
        res.setHeader("Cache-Control", "public, max-age=3600");
      },
    })
  );

  /* =====================
     Health check
  ===================== */
  app.get("/health", (_req, res) => {
    res.status(200).json({ ok: true, service: "tptech-backend" });
  });

  /* =====================
     Rate limit global
     (si querés bypass OPTIONS, lo hacemos desde el rate limiter, no con un app.use vacío)
  ===================== */
  app.use(buildRateLimitMiddleware());

  /* =====================
     Routes
  ===================== */
  app.use(routes);

  /* =====================
     Root
  ===================== */
  app.get("/", (_req, res) => {
    res.status(200).send("TPTech Backend OK 🚀");
  });

  /* =====================
     Error handler
  ===================== */
  app.use(errorHandler);

  return app;
}
