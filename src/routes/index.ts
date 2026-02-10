import { Router } from "express";
import { requireAuth } from "../middlewares/requireAuth.js";

// módulos
import authRoutes from "../modules/auth/auth.routes.js";
import movimientosRoutes from "../modules/movimientos/movimientos.routes.js";
import usersRoutes from "../modules/users/users.routes.js";

// legacy
import companyRoutes from "./company.routes.js";
import rolesRoutes from "./roles.routes.js";
import permissionsRoutes from "./permissions.routes.js";
import catalogsRoutes from "./catalogs.routes.js";

const router = Router();

/* =====================
   PÚBLICO
===================== */
router.use("/auth", authRoutes);

/* =====================
   PRIVADO
===================== */
router.use("/movimientos", requireAuth, movimientosRoutes);
router.use("/users", requireAuth, usersRoutes);
router.use("/company", requireAuth, companyRoutes);
router.use("/company/catalogs", requireAuth, catalogsRoutes);
router.use("/roles", requireAuth, rolesRoutes);
router.use("/permissions", requireAuth, permissionsRoutes);

export default router;
