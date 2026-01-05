// src/routes/index.ts
import { Router } from "express";

import authRoutes from "./auth.routes.js";
import movimientosRoutes from "./movimientos.routes.js";

const router = Router();

router.use("/auth", authRoutes);
router.use("/movimientos", movimientosRoutes);

// ⚠️ Más adelante cuando existan estos routers, los agregamos:
// import usersRoutes from "./users.routes.js";
// import rolesRoutes from "./roles.routes.js";
// router.use("/users", usersRoutes);
// router.use("/roles", rolesRoutes);

export default router;
