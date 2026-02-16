// tptech-backend/src/lib/mail.service.ts
import type { Request, Response } from "express";
import crypto from "node:crypto";

// ✅ ESM + node16/nodenext: imports relativos con extensión .js
import { postmarkSendMail } from "./mail.provider.postmark.js";

export type SendMailOptions = {
  to: string;
  subject: string;
  html: string;
  text?: string;
  from?: string;
};

const MAIL_MODE = String(process.env.MAIL_MODE || "preview").toLowerCase(); // preview | console | production

const previewStore = new Map<
  string,
  { subject: string; html: string; text?: string; to: string; from?: string; createdAt: number }
>();

export async function sendMail(options: SendMailOptions) {
  const { to, subject, html, text, from } = options;

  if (MAIL_MODE === "preview") {
    const id = crypto.randomUUID();
    previewStore.set(id, { subject, html, text, to, from, createdAt: Date.now() });

    console.log("📧 [MAIL PREVIEW] Subject:", subject);
    console.log("👉 Preview URL:", `/dev/mail/${id}`);
    return { previewId: id };
  }

  if (MAIL_MODE === "console") {
    console.log("📧 [MAIL CONSOLE]");
    console.log({ to, from, subject });
    console.log(text || "");
    return;
  }

  if (MAIL_MODE === "production") {
    // ✅ Postmark real (cuando tengas token)
    await postmarkSendMail({
      to,
      from: from || process.env.MAIL_FROM || "no-reply@tptech.local",
      subject,
      html,
      text,
    });
    return;
  }

  // fallback
  console.log("⚠️ [MAIL] MAIL_MODE inválido, usando console");
  console.log({ to, from, subject });
  console.log(text || "");
}

export function registerMailPreviewRoute(app: any) {
  app.get("/dev/mail/:id", (req: Request, res: Response) => {
    const id = String(req.params.id || "");
    const mail = previewStore.get(id);

    if (!mail) return res.status(404).send("Preview not found.");

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.send(`
      <div style="font-family: ui-sans-serif, system-ui; padding:16px; max-width: 900px; margin: 0 auto;">
        <h2 style="margin:0 0 12px 0;">📧 Mail Preview</h2>
        <div style="padding:12px; border:1px solid #e5e7eb; border-radius:12px; margin-bottom:12px;">
          <div><strong>To:</strong> ${escapeHtml(mail.to)}</div>
          <div><strong>From:</strong> ${escapeHtml(mail.from || "(default)")}</div>
          <div><strong>Subject:</strong> ${escapeHtml(mail.subject)}</div>
          <div style="color:#6b7280; font-size:12px; margin-top:6px;">
            ${new Date(mail.createdAt).toLocaleString()}
          </div>
        </div>
        <div style="padding:16px; border:1px solid #e5e7eb; border-radius:12px;">
          ${mail.html}
        </div>
      </div>
    `);
  });
}

function escapeHtml(s: string) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
