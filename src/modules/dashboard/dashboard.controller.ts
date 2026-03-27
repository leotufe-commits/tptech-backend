import type { Request, Response } from "express";
import { getDashboardSummary, getProfitSummary, type ProfitGroupBy } from "./dashboard.service.js";

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

// ─── Profit summary ─────────────────────────────────────────────────────────

function parseDateParam(v: any, fallback: Date): Date {
  if (!v) return fallback;
  const d = new Date(String(v));
  return isNaN(d.getTime()) ? fallback : d;
}

function parseGroupBy(v: any): ProfitGroupBy {
  if (v === "day" || v === "week" || v === "month") return v;
  return "day";
}

export async function profitSummary(req: Request, res: Response) {
  const user = (req as any).user;
  const jewelryId = user?.jewelryId;
  if (!jewelryId) return res.status(401).json({ ok: false, message: "Unauthorized" });

  try {
    const now = new Date();
    const defaultFrom = new Date(now);
    defaultFrom.setDate(defaultFrom.getDate() - 29);
    defaultFrom.setHours(0, 0, 0, 0);

    const from    = parseDateParam(req.query.from, defaultFrom);
    const to      = parseDateParam(req.query.to,   now);
    const groupBy = parseGroupBy(req.query.groupBy);

    const data = await getProfitSummary({ jewelryId, from, to, groupBy });
    return res.json({ ok: true, data });
  } catch (err: any) {
    return res.status(err?.status ?? 500).json({ ok: false, message: err?.message ?? "Error interno" });
  }
}