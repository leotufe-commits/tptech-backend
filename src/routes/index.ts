// src/routes/index.ts
import { Router } from "express";

import { requireAuth } from "../middlewares/requireAuth.js";

import authRoutes from "../modules/auth/auth.routes.js";
import movimientosRoutes from "../modules/movimientos/movimientos.routes.js";
import rolesRoutes from "./roles.routes.js";

const router = Router();

/**
 * Público (solo auth)
 */
router.use("/auth", authRoutes);

/**
 * Privado (secure-by-default)
 * Todo lo que sea negocio va acá adentro.
 */
const privateRouter = Router();
privateRouter.use(requireAuth);

privateRouter.use("/movimientos", movimientosRoutes);
privateRouter.use("/roles", rolesRoutes);

router.use(privateRouter);

export default router;
