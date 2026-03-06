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
    return res.send(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Mail Preview</title>
  <style>
    * { box-sizing: border-box; }
    body { margin: 0; padding: 0; background: #f9fafb; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
    .wrap { max-width: 680px; margin: 0 auto; padding: 24px 16px; }
    .meta { background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px 20px; margin-bottom: 16px; font-size: 13px; line-height: 1.6; }
    .meta strong { color: #374151; }
    .meta span { color: #6b7280; }
    .label { font-size: 10px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: #F36A21; margin-bottom: 6px; }
    .preview-frame { width: 100%; border: 1px solid #e5e7eb; border-radius: 12px; background: #fff; }
  </style>
</head>
<body>
  <div class="wrap">
    <p class="label">Mail Preview (dev)</p>
    <div class="meta">
      <div><strong>Para:</strong> <span>${escapeHtml(mail.to)}</span></div>
      <div><strong>De:</strong> <span>${escapeHtml(mail.from || "(default)")}</span></div>
      <div><strong>Asunto:</strong> <span>${escapeHtml(mail.subject)}</span></div>
      <div style="margin-top:4px;"><strong>Enviado:</strong> <span>${new Date(mail.createdAt).toLocaleString("es-AR")}</span></div>
    </div>
    <iframe
      class="preview-frame"
      frameborder="0"
      scrolling="no"
      style="height:600px;"
      srcdoc="${mail.html.replaceAll('"', "&quot;")}"
    ></iframe>
    <script>
      // auto-resize iframe to content height
      (function() {
        var iframe = document.querySelector('iframe');
        if (!iframe) return;
        iframe.addEventListener('load', function() {
          try {
            var h = iframe.contentDocument.body.scrollHeight;
            iframe.style.height = (h + 32) + 'px';
          } catch(e) {}
        });
      })();
    </script>
  </div>
</body>
</html>`);
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
