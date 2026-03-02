// tptech-backend/src/routes/index.ts
import { Router } from "express";
import { requireAuth } from "../middlewares/requireAuth.js";

/* =====================
   AUTH (público)
===================== */
import authRoutes from "../modules/auth/auth.routes.js";

/* =====================
   MÓDULOS
===================== */
import movimientosRoutes from "../modules/movimientos/movimientos.routes.js";
import usersRoutes from "../modules/users/users.routes.js";
import valuationRoutes from "../modules/valuation/valuation.routes.js";
import companyRoutes from "../modules/company/company.routes.js";
import rolesRoutes from "../modules/roles/roles.routes.js";
import storageRoutes from "../modules/storage/storage.routes.js";
import catalogsRoutes from "../modules/catalogs/catalogs.routes.js";
import permissionsRoutes from "../modules/permissions/permissions.routes.js";

/* =====================
   ✅ DASHBOARD
===================== */
import dashboardRoutes from "../modules/dashboard/dashboard.routes.js";

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

/**
 * Catalogs
 * Base: /company/catalogs
 */
router.use("/company/catalogs", requireAuth, catalogsRoutes);

/**
 * Permissions
 * Base: /permissions
 */
router.use("/permissions", requireAuth, permissionsRoutes);

// valuation ya aplica requireAuth internamente
router.use("/valuation", valuationRoutes);

/* =====================
   ✅ DASHBOARD (privado)
   Base: /dashboard
===================== */
router.use("/dashboard", requireAuth, dashboardRoutes);

export default router;