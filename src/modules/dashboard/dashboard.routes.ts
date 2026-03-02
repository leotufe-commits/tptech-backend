import { Router } from "express";
import dashboardSummary from "./dashboard.controller.js";

const router = Router();

/**
 * Base: /dashboard
 * GET /dashboard/summary?range=30d
 */
router.get("/summary", dashboardSummary);

export default router;