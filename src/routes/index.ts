// tptech-backend/src/routes/index.ts
import { Router } from "express";
import { requireAuth } from "../middlewares/requireAuth.js";

// ✅ auth
import authRoutes from "../modules/auth/auth.routes.js";

// ✅ módulos
import movimientosRoutes from "../modules/movimientos/movimientos.routes.js";
import usersRoutes from "../modules/users/users.routes.js";

// ✅ storage (tolerante a default/named)
import * as storageRoutesMod from "../lib/storage/storage.routes.js";

// ✅ legacy
import companyRoutes from "./company.routes.js";
import rolesRoutes from "./roles.routes.js";
import permissionsRoutes from "./permissions.routes.js";

const router = Router();

const storageRoutes: any =
  (storageRoutesMod as any).default ??
  (storageRoutesMod as any).router ??
  (storageRoutesMod as any).storageRoutes ??
  storageRoutesMod;

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

export default router;
