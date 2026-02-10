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

  // ✅ Importante para cookies + proxy
  app.set("trust proxy", 1);

  app.disable("x-powered-by");
  app.use(buildHelmetMiddleware());

  // CORS con credentials
  const corsMw = buildCorsMiddleware();
  app.use(corsMw);
  app.options(/.*/, corsMw);

  // Parsers
  app.use(express.json({ limit: "1mb" }));
  app.use(express.urlencoded({ extended: true, limit: "1mb" }));
  app.use(cookieParser());

  // Prisma ALS
  app.use(requestContextMiddleware);

  // Perf
  app.use(perfLogger({ slowMs: 700 }));

  // Static uploads
  const UPLOADS_DIR = path.join(process.cwd(), "uploads");
  const uploadsStatic = express.static(UPLOADS_DIR, {
    index: false,
    fallthrough: false,
    setHeaders(res) {
      res.setHeader("Cache-Control", "public, max-age=3600");
    },
  });

  // ✅ Servir uploads en /uploads (directo backend) y /api/uploads (para proxy Vite)
  app.use("/uploads", uploadsStatic);
  app.use("/api/uploads", uploadsStatic);

  // Health (también bajo /api)
  app.get("/api/health", (_req, res) => {
    res.status(200).json({ ok: true, service: "tptech-backend" });
  });

  // Rate limit global
  app.use(buildRateLimitMiddleware());

  // 🔑🔑🔑 RUTAS BAJO /api 🔑🔑🔑
  app.use("/api", routes);

  // Root
  app.get("/", (_req, res) => {
    res.status(200).send("TPTech Backend OK 🚀");
  });

  // Error handler
  app.use(errorHandler);

  return app;
}
