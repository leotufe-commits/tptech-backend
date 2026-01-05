// src/app.ts
import express from "express";

import routes from "./routes/index.js";
import { requestContextMiddleware } from "./lib/prisma.js";
import { errorHandler } from "./middlewares/errorHandler.js";
import { buildCorsMiddleware } from "./config/cors.js";
import { buildHelmetMiddleware, buildRateLimitMiddleware } from "./config/security.js";

export function createApp() {
  const app = express();

  /* =====================
     Seguridad básica (headers)
  ===================== */
  app.disable("x-powered-by");
  app.use(buildHelmetMiddleware());

  /* =====================
     Proxy (Render)
  ===================== */
  app.set("trust proxy", 1);

  /* =====================
     Body parser
  ===================== */
  app.use(express.json({ limit: "1mb" }));

  /* =====================
     Request Context (ALS)
     ⚠️ debe ir ANTES de rutas
  ===================== */
  app.use(requestContextMiddleware);

  /* =====================
     CORS
  ===================== */
  app.use(buildCorsMiddleware());

  /* =====================
     Health check (sin rate limit)
  ===================== */
  app.get("/health", (_req, res) => {
    res.status(200).json({ ok: true, service: "tptech-backend" });
  });

  /* =====================
     Rate limit global
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
     Error handler (JSON)
  ===================== */
  app.use(errorHandler);

  return app;
}
