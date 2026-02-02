// tptech-backend/src/routes/index.ts
import { Router } from "express";

import { requireAuth } from "../middlewares/requireAuth.js";

import authRoutes from "../modules/auth/auth.routes.js";
import movimientosRoutes from "../modules/movimientos/movimientos.routes.js";

// Users ya está en modules ✅
import usersRoutes from "../modules/users/users.routes.js";

// Company (configuración joyería)
import companyRoutes from "./company.routes.js";

// Roles / Permissions
import rolesRoutes from "./roles.routes.js";
import permissionsRoutes from "./permissions.routes.js";

const router = Router();

/* =====================
   Público
   ✅ authRoutes ya maneja públic/privado internamente
===================== */
router.use("/auth", authRoutes);

/* =====================
   Privado (requiere login)
===================== */
const privateRouter = Router();
privateRouter.use(requireAuth);

// 🔹 Usuarios
privateRouter.use("/users", usersRoutes);

// 🔹 Configuración joyería
privateRouter.use("/company", companyRoutes);

// 🔹 Otros módulos
privateRouter.use("/movimientos", movimientosRoutes);
privateRouter.use("/roles", rolesRoutes);
privateRouter.use("/permissions", permissionsRoutes);

router.use(privateRouter);

export default router;
