import { Router } from "express";

import { requireAuth } from "../middlewares/requireAuth.js";

import authRoutes from "../modules/auth/auth.routes.js";
import movimientosRoutes from "../modules/movimientos/movimientos.routes.js";
import rolesRoutes from "./roles.routes.js";
import permissionsRoutes from "./permissions.routes.js"; // si existe en tu proyecto

const router = Router();

/**
 * Público
 */
router.use("/auth", authRoutes);

/**
 * Privado
 */
const privateRouter = Router();
privateRouter.use(requireAuth);

privateRouter.use("/movimientos", movimientosRoutes);
privateRouter.use("/roles", rolesRoutes);

// si tenés endpoint /permissions (tu front lo usa)
privateRouter.use("/permissions", permissionsRoutes);

router.use(privateRouter);

export default router;
