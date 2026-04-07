// src/modules/commercial-entities/account-statement.mailer.ts
// Envía el extracto de cuenta corriente por email.

import { sendMail } from "../../lib/mail.service.js";
import type { AccountStatement, StatementBalance, StatementMovement } from "./account-statement.service.js";

// ---------------------------------------------------------------------------
// Helpers de formato
// ---------------------------------------------------------------------------

function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString("es-AR", {
      day:   "2-digit",
      month: "2-digit",
      year:  "numeric",
    });
  } catch {
    return iso;
  }
}

function fmtNumber(n: number, decimals = 2): string {
  return n.toLocaleString("es-AR", {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  });
}

function colorAmount(value: number): string {
  return value < 0 ? "color:#dc2626;" : "color:#111827;";
}

// ---------------------------------------------------------------------------
// Secciones HTML
// ---------------------------------------------------------------------------

function renderBalanceTable(balance: StatementBalance, title: string): string {
  const hasMetals  = Object.keys(balance.metal).length > 0;
  const hasHechura = Object.keys(balance.hechura).length > 0;

  if (!hasMetals && !hasHechura) {
    return `
      <h3 style="margin:24px 0 8px;font-size:14px;font-weight:600;color:#374151;">${title}</h3>
      <p style="color:#6b7280;font-size:13px;margin:0;">Sin movimientos.</p>`;
  }

  let rows = "";

  for (const [metalId, grams] of Object.entries(balance.metal)) {
    const style = colorAmount(grams);
    rows += `
      <tr>
        <td style="padding:8px 12px;border-bottom:1px solid #f3f4f6;font-size:13px;color:#374151;">Metal</td>
        <td style="padding:8px 12px;border-bottom:1px solid #f3f4f6;font-size:13px;color:#374151;">${metalId}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #f3f4f6;font-size:13px;text-align:right;${style}">${fmtNumber(grams, 4)} g</td>
      </tr>`;
  }

  for (const [currency, amount] of Object.entries(balance.hechura)) {
    const style = colorAmount(amount);
    const label = amount < 0
      ? `<span style="color:#16a34a;font-size:11px;font-weight:600;"> (saldo a favor)</span>`
      : "";
    rows += `
      <tr>
        <td style="padding:8px 12px;border-bottom:1px solid #f3f4f6;font-size:13px;color:#374151;">Hechura</td>
        <td style="padding:8px 12px;border-bottom:1px solid #f3f4f6;font-size:13px;color:#374151;">${currency}</td>
        <td style="padding:8px 12px;border-bottom:1px solid #f3f4f6;font-size:13px;text-align:right;${style}">${fmtNumber(amount)}${label}</td>
      </tr>`;
  }

  return `
    <h3 style="margin:24px 0 8px;font-size:14px;font-weight:600;color:#374151;">${title}</h3>
    <table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;">
      <thead>
        <tr style="background:#f9fafb;">
          <th style="padding:8px 12px;text-align:left;font-size:12px;font-weight:600;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;">Tipo</th>
          <th style="padding:8px 12px;text-align:left;font-size:12px;font-weight:600;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;">Referencia</th>
          <th style="padding:8px 12px;text-align:right;font-size:12px;font-weight:600;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;">Saldo</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function renderMovementsTable(movements: StatementMovement[]): string {
  if (movements.length === 0) {
    return `
      <h3 style="margin:24px 0 8px;font-size:14px;font-weight:600;color:#374151;">Movimientos del período</h3>
      <p style="color:#6b7280;font-size:13px;margin:0;">Sin movimientos en el período seleccionado.</p>`;
  }

  let rows = "";
  for (const m of movements) {
    const voidedStyle = m.isVoided ? "text-decoration:line-through;color:#9ca3af;" : "";
    const voidedTag   = m.isVoided
      ? `<span style="display:inline-block;background:#fee2e2;color:#dc2626;font-size:10px;font-weight:600;padding:1px 6px;border-radius:4px;margin-left:6px;">ANULADO</span>`
      : "";

    // Metal delta resumen
    const metalParts = Object.entries(m.metalDelta)
      .map(([id, g]) => `${id}: ${fmtNumber(g, 4)}g`)
      .join(", ");
    const hechuraParts = Object.entries(m.hechuraDelta)
      .map(([cur, amt]) => {
        const style = colorAmount(amt);
        return `<span style="${style}">${cur} ${fmtNumber(amt)}</span>`;
      })
      .join(", ");

    rows += `
      <tr style="border-bottom:1px solid #f3f4f6;">
        <td style="padding:8px 12px;font-size:12px;color:#6b7280;white-space:nowrap;">${fmtDate(m.date)}</td>
        <td style="padding:8px 12px;font-size:13px;${voidedStyle}">${m.typeLabel}${voidedTag}</td>
        <td style="padding:8px 12px;font-size:12px;color:#374151;">${m.reference || "—"}</td>
        <td style="padding:8px 12px;font-size:12px;color:#6b7280;">${m.description || "—"}</td>
        <td style="padding:8px 12px;font-size:12px;color:#374151;">${metalParts || "—"}</td>
        <td style="padding:8px 12px;font-size:12px;">${hechuraParts || "—"}</td>
      </tr>`;
  }

  return `
    <h3 style="margin:24px 0 8px;font-size:14px;font-weight:600;color:#374151;">Movimientos del período</h3>
    <div style="overflow-x:auto;">
    <table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;min-width:600px;">
      <thead>
        <tr style="background:#f9fafb;">
          <th style="padding:8px 12px;text-align:left;font-size:12px;font-weight:600;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;">Fecha</th>
          <th style="padding:8px 12px;text-align:left;font-size:12px;font-weight:600;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;">Tipo</th>
          <th style="padding:8px 12px;text-align:left;font-size:12px;font-weight:600;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;">Referencia</th>
          <th style="padding:8px 12px;text-align:left;font-size:12px;font-weight:600;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;">Descripción</th>
          <th style="padding:8px 12px;text-align:left;font-size:12px;font-weight:600;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;">Metal</th>
          <th style="padding:8px 12px;text-align:left;font-size:12px;font-weight:600;color:#6b7280;text-transform:uppercase;letter-spacing:.05em;">Hechura</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
    </div>`;
}

// ---------------------------------------------------------------------------
// buildStatementHtml
// ---------------------------------------------------------------------------

function buildStatementHtml(statement: AccountStatement, tenantName?: string): string {
  const { entity, period } = statement;

  const periodStr = [period.from, period.to]
    .filter((d): d is string => Boolean(d))
    .map(fmtDate)
    .join(" al ") || "Todo el historial";

  const generatedStr = fmtDate(period.generatedAt);

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Extracto de cuenta – ${entity.displayName}</title>
</head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <div style="max-width:680px;margin:0 auto;padding:24px 16px;">

    <!-- Header -->
    <div style="background:#1f2937;border-radius:12px 12px 0 0;padding:28px 32px;">
      <p style="margin:0 0 4px;font-size:12px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:#9ca3af;">${tenantName || "TPTech"}</p>
      <h1 style="margin:0 0 8px;font-size:22px;font-weight:700;color:#f9fafb;">Extracto de cuenta</h1>
      <p style="margin:0;font-size:16px;color:#d1d5db;">${entity.displayName}</p>
    </div>

    <!-- Meta -->
    <div style="background:#fff;border-left:1px solid #e5e7eb;border-right:1px solid #e5e7eb;padding:16px 32px;">
      <table style="width:100%;border-collapse:collapse;">
        <tr>
          <td style="padding:4px 0;font-size:13px;color:#6b7280;width:140px;">Código</td>
          <td style="padding:4px 0;font-size:13px;color:#111827;">${entity.code}</td>
          <td style="padding:4px 0;font-size:13px;color:#6b7280;width:140px;">Documento</td>
          <td style="padding:4px 0;font-size:13px;color:#111827;">${entity.documentNumber || "—"}</td>
        </tr>
        <tr>
          <td style="padding:4px 0;font-size:13px;color:#6b7280;">Email</td>
          <td style="padding:4px 0;font-size:13px;color:#111827;">${entity.email || "—"}</td>
          <td style="padding:4px 0;font-size:13px;color:#6b7280;">Período</td>
          <td style="padding:4px 0;font-size:13px;color:#111827;">${periodStr}</td>
        </tr>
        <tr>
          <td style="padding:4px 0;font-size:13px;color:#6b7280;">Generado</td>
          <td style="padding:4px 0;font-size:13px;color:#111827;" colspan="3">${generatedStr}</td>
        </tr>
      </table>
    </div>

    <!-- Body -->
    <div style="background:#fff;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 12px 12px;padding:24px 32px;">

      ${renderBalanceTable(statement.openingBalance, "Saldo inicial")}
      ${renderMovementsTable(statement.movements)}
      ${renderBalanceTable(statement.closingBalance, "Saldo final")}

      <!-- Footer -->
      <p style="margin:32px 0 0;font-size:11px;color:#9ca3af;text-align:center;">
        Este extracto fue generado automáticamente por ${tenantName || "TPTech"} el ${generatedStr}.
      </p>
    </div>

  </div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// sendAccountStatementEmail
// ---------------------------------------------------------------------------

export async function sendAccountStatementEmail(
  to: string,
  statement: AccountStatement,
  tenantName?: string,
): Promise<void> {
  const subject = `Extracto de cuenta – ${statement.entity.displayName}`;
  const html = buildStatementHtml(statement, tenantName);

  // Texto plano básico
  const periodStr = [statement.period.from, statement.period.to]
    .filter((d): d is string => Boolean(d))
    .map(fmtDate)
    .join(" al ") || "Todo el historial";

  const text = [
    subject,
    `Entidad: ${statement.entity.displayName} (${statement.entity.code})`,
    `Período: ${periodStr}`,
    `Movimientos: ${statement.movements.length}`,
    `Generado: ${fmtDate(statement.period.generatedAt)}`,
  ].join("\n");

  await sendMail({ to, subject, html, text });
}
