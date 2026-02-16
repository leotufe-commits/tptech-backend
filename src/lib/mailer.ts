// tptech-backend/src/lib/mailer.ts
import { sendMail } from "./mail.service.js";

const DEFAULT_FROM =
  process.env.MAIL_FROM ||
  process.env.POSTMARK_FROM ||
  process.env.SMTP_USER ||
  "no-reply@tptech.local";

function escapeHtml(s: string) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

type SendLinkEmailOpts = {
  subject: string;
  heading?: string;
  lead?: string;
  ctaText?: string;
  linkLabel?: string;
};

async function sendLinkEmail(to: string, link: string, opts: SendLinkEmailOpts) {
  const safeLink = escapeHtml(link);

  const subject = opts.subject;
  const heading = opts.heading || subject;
  const lead = opts.lead || "Abrí este link para continuar:";
  const ctaText = opts.ctaText || "Continuar";
  const linkLabel = opts.linkLabel || "Link directo:";

  const html = `
    <div style="font-family: ui-sans-serif, system-ui; line-height: 1.4; padding: 4px 0;">
      <h2 style="margin:0 0 12px 0;">${escapeHtml(heading)}</h2>
      <p style="margin:0 0 12px 0;">${escapeHtml(lead)}</p>

      <p style="margin:0 0 14px 0;">
        <a href="${safeLink}"
           style="display:inline-block; padding:10px 14px; border-radius:10px; text-decoration:none; color:#ffffff; background:#F36A21; font-weight:700;">
          ${escapeHtml(ctaText)}
        </a>
      </p>

      <p style="margin:0; color:#6b7280; font-size:12px;">
        Si vos no solicitaste esto, podés ignorar este email.
      </p>

      <hr style="border:none;border-top:1px solid #e5e7eb;margin:16px 0;" />

      <div style="color:#6b7280;font-size:12px;">
        ${escapeHtml(linkLabel)} <a href="${safeLink}">${safeLink}</a>
      </div>
    </div>
  `;

  const text = `${subject}\n\n${lead}\n${link}\n`;

  await sendMail({
    to,
    from: DEFAULT_FROM,
    subject,
    html,
    text,
  });
}

/** Reset de contraseña (single-use link) */
export async function sendResetEmail(to: string, resetLink: string) {
  return sendLinkEmail(to, resetLink, {
    subject: "TPTech - Restablecer contraseña",
    heading: "Restablecer contraseña",
    lead: "Recibimos una solicitud para restablecer tu contraseña.",
    ctaText: "Restablecer",
    linkLabel: "Link directo:",
  });
}

/** Invitación (mismo link, distinto texto/subject) */
export async function sendInviteEmail(to: string, inviteLink: string) {
  return sendLinkEmail(to, inviteLink, {
    subject: "TPTech - Invitación de acceso",
    heading: "Invitación de acceso",
    lead: "Te invitaron a acceder a TPTech. Creá tu contraseña para ingresar.",
    ctaText: "Aceptar invitación",
    linkLabel: "Link directo:",
  });
}
