import { Router } from "express";

import authRoutes from "./auth.routes.js";
import movimientosRoutes from "./movimientos.routes.js";
import usersRoutes from "./users.routes.js";
import rolesRoutes from "./roles.routes.js";

import { requireAuth } from "../middlewares/requireAuth.js";
import { requireTenant } from "../middlewares/requireTenant.js";

const router = Router();

/* Public */
router.use("/auth", authRoutes);

/* Protected (auth + tenant) */
const protectedRouter = Router();
protectedRouter.use(requireAuth, requireTenant);

protectedRouter.use("/users", usersRoutes);
protectedRouter.use("/roles", rolesRoutes);
protectedRouter.use("/movimientos", movimientosRoutes);

router.use(protectedRouter);

export default router;
