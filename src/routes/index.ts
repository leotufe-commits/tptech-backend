// src/routes/index.ts
import { Router } from "express";

import authRoutes from "../modules/auth/auth.routes.js";
import movimientosRoutes from "../modules/movimientos/movimientos.routes.js";
import rolesRoutes from "./roles.routes.js";

const router = Router();

router.use("/auth", authRoutes);
router.use("/movimientos", movimientosRoutes);
router.use("/roles", rolesRoutes);

export default router;
