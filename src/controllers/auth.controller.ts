import type { Request, Response } from "express";

export async function health(req: Request, res: Response) {
  return res.json({ ok: true });
}
