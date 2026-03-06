import type { Request, Response } from "express";
import { getDashboardSummary } from "./dashboard.service.js";

type DashboardRange = "7d" | "30d" | "90d" | "1y";

function parseRange(v: any): DashboardRange {
  const x = String(v || "30d");
  if (x === "7d" || x === "30d" || x === "90d" || x === "1y") return x;
  return "30d";
}

export default async function dashboardSummary(req: Request, res: Response) {
  const user = (req as any).user;
  const jewelryId = user?.jewelryId;

  if (!jewelryId) return res.status(401).json({ ok: false, message: "Unauthorized" });

  const range = parseRange(req.query.range);
  const data = await getDashboardSummary({ jewelryId, range });

  return res.json({ ok: true, data });
}