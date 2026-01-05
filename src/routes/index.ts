import { Router } from "express";
import authRoutes from "../modules/auth/auth.routes.js";
import movimientosRoutes from "../modules/movimientos/movimientos.routes.js";
import { requireAuth } from "../middlewares/requireAuth.js";

const router = Router();

/* =====================
   Rutas públicas
===================== */
router.use("/auth", authRoutes);

/* =====================
   Rutas privadas
===================== */
router.use("/movimientos", requireAuth, movimientosRoutes);

export default router;
