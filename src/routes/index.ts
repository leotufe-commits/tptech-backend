// tptech-backend/src/routes/index.ts
import { Router } from "express";

import { requireAuth } from "../middlewares/requireAuth.js";

// ✅ módulos
import authRoutes from "../modules/auth/auth.routes.js";
import movimientosRoutes from "../modules/movimientos/movimientos.routes.js";
import usersRoutes from "../modules/users/users.routes.js";

// ✅ rutas “legacy/flat” que siguen en /routes
import companyRoutes from "./company.routes.js";
import rolesRoutes from "./roles.routes.js";
import permissionsRoutes from "./permissions.routes.js";

const router = Router();

/* =====================
   PÚBLICO
   - auth.routes.ts maneja público/privado internamente
===================== */
router.use("/auth", authRoutes);

/* =====================
   PRIVADO (requiere sesión)
===================== */
router.use("/movimientos", requireAuth, movimientosRoutes);
router.use("/users", requireAuth, usersRoutes);
router.use("/company", requireAuth, companyRoutes);
router.use("/roles", requireAuth, rolesRoutes);
router.use("/permissions", requireAuth, permissionsRoutes);

export default router;
