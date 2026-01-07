// tptech-backend/src/routes/index.ts
import { Router } from "express";

import { requireAuth } from "../middlewares/requireAuth.js";

import authRoutes from "../modules/auth/auth.routes.js";
import movimientosRoutes from "../modules/movimientos/movimientos.routes.js";

import usersRoutes from "../modules/users/users.routes.js";

// rutas centralizadas
import rolesRoutes from "./roles.routes.js";
import permissionsRoutes from "./permissions.routes.js";

const router = Router();

/** Público */
router.use("/auth", authRoutes);

/** Privado */
const privateRouter = Router();
privateRouter.use(requireAuth);

privateRouter.use("/movimientos", movimientosRoutes);
privateRouter.use("/users", usersRoutes);
privateRouter.use("/roles", rolesRoutes);
privateRouter.use("/permissions", permissionsRoutes);

router.use(privateRouter);

export default router;
