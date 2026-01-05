import { Router } from "express";
import usersRoutes from "./users.routes";
import rolesRoutes from "./roles.routes";
import requireTenant from "../middlewares/requireTenant";

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
