import { Router } from "express";

import { requireAuth } from "../middlewares/requireAuth.js";

import authRoutes from "../modules/auth/auth.routes.js";
import movimientosRoutes from "../modules/movimientos/movimientos.routes.js";
import rolesRoutes from "./roles.routes.js";
import permissionsRoutes from "./permissions.routes.js";
import usersRoutes from "./users.routes.js"; // ✅ IMPORTANTE

const router = Router();

/**
 * =====================
 * Público
 * =====================
 */
router.use("/auth", authRoutes);

/**
 * =====================
 * Privado (requiere login)
 * =====================
 */
const privateRouter = Router();
privateRouter.use(requireAuth);

// 🔹 Usuarios (LO QUE FALTABA)
privateRouter.use("/users", usersRoutes);

// 🔹 Otros módulos
privateRouter.use("/movimientos", movimientosRoutes);
privateRouter.use("/roles", rolesRoutes);
privateRouter.use("/permissions", permissionsRoutes);

router.use(privateRouter);

export default router;
