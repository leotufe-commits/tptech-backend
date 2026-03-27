import { Router } from "express";
import dashboardSummary, { profitSummary } from "./dashboard.controller.js";

const router = Router();

// GET /dashboard/summary?range=30d
router.get("/summary", dashboardSummary);

// GET /dashboard/profit?from=YYYY-MM-DD&to=YYYY-MM-DD&groupBy=day|week|month
router.get("/profit", profitSummary);

export default router;