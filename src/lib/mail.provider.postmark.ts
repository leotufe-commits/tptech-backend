// tptech-backend/src/lib/mail.provider.postmark.ts
import type { SendMailOptions } from "./mail.service";

function mustEnv(name: string) {
  const v = process.env[name];
  if (!v) throw new Error(`[MAIL] Missing env ${name}`);
  return v;
}

// ✅ este nombre ES el que importa mail.service.ts
export async function postmarkSendMail(options: SendMailOptions) {
  const token = mustEnv("POSTMARK_SERVER_TOKEN");

  const defaultFrom = process.env.MAIL_FROM || "";
  const messageStream = process.env.POSTMARK_MESSAGE_STREAM || "outbound";

  const payload = {
    From: options.from || defaultFrom,
    To: options.to,
    Subject: options.subject,
    HtmlBody: options.html,
    TextBody: options.text || undefined,
    MessageStream: messageStream,
  };

  if (!payload.From) {
    throw new Error("[MAIL] Missing From (set MAIL_FROM or pass options.from)");
  }

  const res = await fetch("https://api.postmarkapp.com/email", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "X-Postmark-Server-Token": token,
    },
    body: JSON.stringify(payload),
  });

  const data = await res.json().catch(() => ({} as any));

  if (!res.ok) {
    const msg =
      data?.Message || data?.ErrorCode
        ? `${data?.Message || "Postmark error"} (code ${data?.ErrorCode})`
        : `Postmark HTTP ${res.status}`;
    throw new Error(`[MAIL] ${msg}`);
  }

  return data;
}

// ✅ opcional por compatibilidad
export const sendPostmarkMail = postmarkSendMail;
