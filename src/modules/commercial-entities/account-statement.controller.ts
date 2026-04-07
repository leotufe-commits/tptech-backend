// src/modules/commercial-entities/account-statement.controller.ts

import type { Response } from "express";
import { getAccountStatement } from "./account-statement.service.js";
import { sendAccountStatementEmail } from "./account-statement.mailer.js";

function s(v: any) { return String(v ?? "").trim(); }
function assert(cond: any, msg: string) {
  if (!cond) { const err: any = new Error(msg); err.status = 400; throw err; }
}

// ---------------------------------------------------------------------------
// GET /:id/account-statement?from=YYYY-MM-DD&to=YYYY-MM-DD
// ---------------------------------------------------------------------------
export async function getStatement(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");

  const from = s(req.query?.from) || undefined;
  const to   = s(req.query?.to)   || undefined;

  const statement = await getAccountStatement(id, req.user.jewelryId, {
    fromDate: from,
    toDate:   to,
  });

  return res.json(statement);
}

// ---------------------------------------------------------------------------
// POST /:id/account-statement/email
// body: { from?: string; to?: string; recipientEmail: string }
// ---------------------------------------------------------------------------
export async function emailStatement(req: any, res: Response) {
  const id = s(req.params?.id);
  assert(req.user?.jewelryId, "Tenant inválido.");
  assert(id, "Id inválido.");

  const recipientEmail = s(req.body?.recipientEmail);
  assert(recipientEmail, "recipientEmail es requerido.");
  assert(
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recipientEmail),
    "recipientEmail no es un email válido.",
  );

  const from = s(req.body?.from) || undefined;
  const to   = s(req.body?.to)   || undefined;

  const statement = await getAccountStatement(id, req.user.jewelryId, {
    fromDate: from,
    toDate:   to,
  });

  await sendAccountStatementEmail(recipientEmail, statement);

  return res.json({ ok: true, message: "Extracto enviado correctamente." });
}
