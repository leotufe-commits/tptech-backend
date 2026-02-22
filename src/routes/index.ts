// tptech-backend/src/routes/index.ts
import { Router } from "express";
import { requireAuth } from "../middlewares/requireAuth.js";

// auth
import authRoutes from "../modules/auth/auth.routes.js";

// módulos
import movimientosRoutes from "../modules/movimientos/movimientos.routes.js";
import usersRoutes from "../modules/users/users.routes.js";
import valuationRoutes from "../modules/valuation/valuation.routes.js";

// storage
import storageRoutes from "../lib/storage/storage.routes.js";

// legacy
import companyRoutes from "./company.routes.js";
import rolesRoutes from "./roles.routes.js";
import permissionsRoutes from "./permissions.routes.js";

const router = Router();

/* =====================
   PÚBLICO
===================== */
router.use("/auth", authRoutes);

/* =====================
   STORAGE
===================== */
router.use("/storage", storageRoutes);

/* =====================
   PRIVADO
===================== */
router.use("/movimientos", requireAuth, movimientosRoutes);
router.use("/users", requireAuth, usersRoutes);
router.use("/company", requireAuth, companyRoutes);
router.use("/roles", requireAuth, rolesRoutes);
router.use("/permissions", requireAuth, permissionsRoutes);

// valuation ya aplica requireAuth internamente
router.use("/valuation", valuationRoutes);

export default router;