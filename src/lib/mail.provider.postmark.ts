// tptech-backend/src/lib/mail.provider.postmark.ts
import type { SendMailOptions } from "./mail.service.js";

function mustEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`[MAIL] Missing env ${name}`);
  return v;
}

// ✅ este nombre ES el que importa mail.service.ts
export async function postmarkSendMail(options: SendMailOptions) {
  const token = mustEnv("POSTMARK_SERVER_TOKEN");

  const defaultFrom = process.env.MAIL_FROM || "";
  const messageStream = process.env.POSTMARK_MESSAGE_STREAM || "outbound";

  // 🔒 Validaciones preventivas
  if (!options?.to) {
    throw new Error("[MAIL] Missing recipient (options.to)");
  }

  if (!options?.subject) {
    throw new Error("[MAIL] Missing subject");
  }

  if (!options?.html && !options?.text) {
    throw new Error("[MAIL] Missing email body (html or text)");
  }

  const payload = {
    From: options.from || defaultFrom,
    To: options.to,
    Subject: options.subject,
    HtmlBody: options.html || undefined,
    TextBody: options.text || undefined,
    MessageStream: messageStream,
  };

  if (!payload.From) {
    throw new Error("[MAIL] Missing From (set MAIL_FROM or pass options.from)");
  }

  // 🧠 Log controlado
  console.log("[MAIL] Sending via Postmark →", {
    to: payload.To,
    subject: payload.Subject,
    stream: payload.MessageStream,
  });

  // ⏱ Timeout de seguridad
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);

  let res: Response;

  try {
    res = await fetch("https://api.postmarkapp.com/email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "X-Postmark-Server-Token": token,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
  } catch (err: any) {
    clearTimeout(timeout);

    if (err?.name === "AbortError") {
      throw new Error("[MAIL] Postmark request timeout");
    }

    throw new Error(`[MAIL] Network error: ${err?.message || err}`);
  }

  clearTimeout(timeout);

  const data: any = await res.json().catch(() => ({}));

  if (!res.ok) {
    console.error("[MAIL] Postmark failed →", {
      to: payload.To,
      status: res.status,
      response: data,
    });

    const msg =
      data?.Message || data?.ErrorCode
        ? `${data?.Message || "Postmark error"} (code ${data?.ErrorCode})`
        : `Postmark HTTP ${res.status}`;

    throw new Error(`[MAIL] ${msg}`);
  }

  console.log("[MAIL] Sent OK →", {
    to: payload.To,
    messageId: data?.MessageID,
  });

  return data; // MessageID, To, SubmittedAt, etc.
}

// ✅ opcional por compatibilidad
export const sendPostmarkMail = postmarkSendMail;
