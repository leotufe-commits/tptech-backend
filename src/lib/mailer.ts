// tptech-backend/src/lib/mailer.ts
import { sendMail } from "./mail.service.js";

const DEFAULT_FROM =
  process.env.MAIL_FROM ||
  process.env.POSTMARK_FROM ||
  process.env.SMTP_USER ||
  "no-reply@tptech.local";

const APP_NAME = process.env.MAIL_APP_NAME || "TPTech";

/* =========================
   HELPERS
========================= */

function escapeHtml(s: string) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/* =========================
   BASE TEMPLATE
   Compatible con Gmail, Outlook, Apple Mail.
   Usa table-based layout + CSS inline.
========================= */

type TemplateOpts = {
  subject: string;
  heading: string;
  intro: string;
  ctaText: string;
  ctaUrl: string;
  expiry?: string;           // ej. "30 minutos" | "7 días"
  showIgnoreNote?: boolean;  // "Si no solicitaste esto, ignorá este email"
};

function buildHtml(opts: TemplateOpts): string {
  const { heading, intro, ctaText, ctaUrl, expiry, showIgnoreNote = true } = opts;
  const safeUrl = escapeHtml(ctaUrl);
  const safeHeading = escapeHtml(heading);
  const safeIntro = escapeHtml(intro);
  const safeCtaText = escapeHtml(ctaText);
  const safeAppName = escapeHtml(APP_NAME);

  const expiryRow = expiry
    ? `<tr>
        <td style="padding:0 0 20px 0;">
          <p style="margin:0; font-size:13px; color:#9ca3af;">
            Este link es de un solo uso y vence en <strong>${escapeHtml(expiry)}</strong>.
          </p>
        </td>
      </tr>`
    : "";

  const ignoreRow = showIgnoreNote
    ? `<tr>
        <td style="padding:16px 0 0 0; border-top:1px solid #f3f4f6;">
          <p style="margin:0; font-size:12px; color:#9ca3af; line-height:1.5;">
            Si no solicitaste esto, podés ignorar este email. Tu cuenta no sufrirá ningún cambio.
          </p>
        </td>
      </tr>`
    : "";

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${safeHeading}</title>
</head>
<body style="margin:0; padding:0; background-color:#f3f4f6; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">

  <!-- Outer wrapper -->
  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f3f4f6; padding:40px 16px;">
    <tr>
      <td align="center">

        <!-- Card (max 560px) -->
        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:560px; background-color:#ffffff; border-radius:16px; overflow:hidden; box-shadow:0 2px 12px rgba(0,0,0,0.08);">

          <!-- Header naranja -->
          <tr>
            <td style="background-color:#F36A21; padding:28px 32px;">
              <p style="margin:0; font-size:22px; font-weight:700; color:#ffffff; letter-spacing:-0.3px;">${safeAppName}</p>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:32px 32px 0 32px;">
              <table width="100%" cellpadding="0" cellspacing="0" border="0">

                <!-- Heading -->
                <tr>
                  <td style="padding:0 0 12px 0;">
                    <h1 style="margin:0; font-size:22px; font-weight:700; color:#111827; line-height:1.3;">
                      ${safeHeading}
                    </h1>
                  </td>
                </tr>

                <!-- Intro -->
                <tr>
                  <td style="padding:0 0 24px 0;">
                    <p style="margin:0; font-size:15px; color:#374151; line-height:1.6;">
                      ${safeIntro}
                    </p>
                  </td>
                </tr>

                <!-- CTA Button -->
                <tr>
                  <td style="padding:0 0 20px 0;">
                    <a href="${safeUrl}"
                       style="display:inline-block; padding:14px 28px; background-color:#F36A21; color:#ffffff; text-decoration:none; border-radius:10px; font-size:15px; font-weight:700; letter-spacing:0.1px;">
                      ${safeCtaText}
                    </a>
                  </td>
                </tr>

                <!-- Expiry note -->
                ${expiryRow}

                <!-- Ignore note -->
                ${ignoreRow}

              </table>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding:20px 32px 28px 32px;">
              <p style="margin:0; font-size:12px; color:#9ca3af; line-height:1.5;">
                Si el botón no funciona, copiá y pegá este link en tu navegador:
              </p>
              <p style="margin:4px 0 0 0; font-size:12px;">
                <a href="${safeUrl}" style="color:#F36A21; word-break:break-all;">${safeUrl}</a>
              </p>
            </td>
          </tr>

        </table>
        <!-- /Card -->

        <!-- Bottom tagline -->
        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:560px; margin-top:20px;">
          <tr>
            <td align="center">
              <p style="margin:0; font-size:12px; color:#9ca3af;">${safeAppName} · Sistema de gestión para joyerías</p>
            </td>
          </tr>
        </table>

      </td>
    </tr>
  </table>

</body>
</html>`;
}

function buildText(opts: TemplateOpts): string {
  const { subject, intro, ctaUrl, expiry } = opts;
  const lines = [subject, "", intro, ""];
  if (expiry) lines.push(`Este link vence en ${expiry}.`, "");
  lines.push(ctaUrl, "");
  lines.push("Si no solicitaste esto, podés ignorar este email.");
  return lines.join("\n");
}

/* =========================
   ENVÍO GENÉRICO
========================= */

async function sendTemplatedEmail(to: string, opts: TemplateOpts) {
  await sendMail({
    to,
    from: DEFAULT_FROM,
    subject: opts.subject,
    html: buildHtml(opts),
    text: buildText(opts),
  });
}

/* =========================
   EMAILS ESPECÍFICOS
========================= */

/** Recuperación de contraseña (link de un solo uso, 30 minutos) */
export async function sendResetEmail(to: string, resetLink: string) {
  return sendTemplatedEmail(to, {
    subject: `${APP_NAME} · Recuperar contraseña`,
    heading: "Recuperar contraseña",
    intro: "Recibimos una solicitud para restablecer la contraseña de tu cuenta. Hacé click en el botón para crear una contraseña nueva.",
    ctaText: "Restablecer contraseña",
    ctaUrl: resetLink,
    expiry: "30 minutos",
    showIgnoreNote: true,
  });
}

/** Invitación de acceso al sistema (link de un solo uso, 7 días) */
export async function sendInviteEmail(to: string, inviteLink: string) {
  return sendTemplatedEmail(to, {
    subject: `${APP_NAME} · Te invitaron a ingresar`,
    heading: "Bienvenido a " + APP_NAME,
    intro: "Un administrador te invitó a acceder al sistema. Hacé click en el botón para crear tu contraseña y activar tu cuenta.",
    ctaText: "Aceptar invitación",
    ctaUrl: inviteLink,
    expiry: "7 días",
    showIgnoreNote: false,
  });
}
