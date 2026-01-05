// src/routes/index.ts
import { Router } from "express";

import authRoutes from "./auth.routes.js";
import movimientosRoutes from "./movimientos.routes.js";

// Si existen:
import usersRoutes from "./users.routes.js";
import rolesRoutes from "./roles.routes.js";

const router = Router();

router.use("/auth", authRoutes);
router.use("/movimientos", movimientosRoutes);

// Si existen:
router.use("/users", usersRoutes);
router.use("/roles", rolesRoutes);

export default router;
