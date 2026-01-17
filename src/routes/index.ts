// tptech-backend/src/routes/index.ts
import { Router } from "express";

import { requireAuth } from "../middlewares/requireAuth.js";

import authRoutes from "../modules/auth/auth.routes.js";
import movimientosRoutes from "../modules/movimientos/movimientos.routes.js";

// Users ya está en modules ✅
import usersRoutes from "../modules/users/users.routes.js";

// Roles/Permissions todavía están en /routes (ok por ahora)
import rolesRoutes from "./roles.routes.js";
import permissionsRoutes from "./permissions.routes.js";

const router = Router();

/* =====================
   Público
===================== */
router.use("/auth", authRoutes);

/* =====================
   Privado (requiere login)
===================== */
const privateRouter = Router();
privateRouter.use(requireAuth);

// 🔹 Usuarios
privateRouter.use("/users", usersRoutes);

// 🔹 Otros módulos
privateRouter.use("/movimientos", movimientosRoutes);
privateRouter.use("/roles", rolesRoutes);
privateRouter.use("/permissions", permissionsRoutes);

router.use(privateRouter);

export default router;
