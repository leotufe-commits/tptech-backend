// tptech-backend/src/lib/mailer.ts
import { sendMail } from "./mail.service.js";

const DEFAULT_FROM =
  process.env.MAIL_FROM ||
  process.env.POSTMARK_FROM ||
  process.env.SMTP_USER ||
  "no-reply@tptech.local";

const APP_NAME = process.env.MAIL_APP_NAME || "TPTech";
const BRAND_COLOR = "#F36A21";

/* =========================
   TENANT MAIL CONTEXT
   Contexto de branding por joyería.
   Se pasa a sendResetEmail / sendInviteEmail cuando el backend
   tiene acceso al registro Jewelry del tenant.

   Rutas de expansión futura:
   - logoUrl         → header con logo de la joyería
   - signature       → firma al pie del cuerpo
   - footer          → párrafo de pie del correo
   - contact/phone   → datos de contacto en el footer
   - replyTo         → pasa directo como Reply-To header
========================= */
export type TenantMailContext = {
  senderName?:     string; // "Joyería Pérez" — nombre visible del remitente
  replyTo?:        string; // ventas@joyeriaperez.com
  logoUrl?:        string; // URL del logo para el header
  signature?:      string; // Firma al pie del cuerpo del email
  footer?:         string; // Párrafo de pie del correo
  contact?:        string; // email de contacto visible
  phone?:          string;
  whatsapp?:       string;
  addressLine?:    string;
  businessHours?:  string;
  website?:        string;
  instagram?:      string;
};

/**
 * Construye el encabezado "From" para un tenant.
 * Ejemplo: "Joyería Pérez <no-reply@tptech.com>"
 *
 * El FROM real siempre es el de TPTech (envío desde infraestructura propia).
 * Solo el nombre visible cambia según la joyería.
 */
export function buildSenderFrom(tenantSenderName?: string): string {
  const name = String(tenantSenderName || "").trim() || APP_NAME;
  return `${name} <${DEFAULT_FROM}>`;
}

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
            <td style="background-color:${BRAND_COLOR}; padding:28px 32px;">
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
                       style="display:inline-block; padding:14px 28px; background-color:${BRAND_COLOR}; color:#ffffff; text-decoration:none; border-radius:10px; font-size:15px; font-weight:700; letter-spacing:0.1px;">
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
                <a href="${safeUrl}" style="color:${BRAND_COLOR}; word-break:break-all;">${safeUrl}</a>
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

async function sendTemplatedEmail(to: string, opts: TemplateOpts, tenant?: TenantMailContext) {
  await sendMail({
    to,
    from: buildSenderFrom(tenant?.senderName),
    replyTo: tenant?.replyTo || undefined,
    subject: opts.subject,
    html: buildHtml(opts),
    text: buildText(opts),
  });
}

/* =========================
   EMAILS ESPECÍFICOS
========================= */

/** Recuperación de contraseña (link de un solo uso, 30 minutos) */
export async function sendResetEmail(to: string, resetLink: string, tenant?: TenantMailContext) {
  return sendTemplatedEmail(to, {
    subject: `${APP_NAME} · Recuperar contraseña`,
    heading: "Recuperar contraseña",
    intro: "Recibimos una solicitud para restablecer la contraseña de tu cuenta. Hacé click en el botón para crear una contraseña nueva.",
    ctaText: "Restablecer contraseña",
    ctaUrl: resetLink,
    expiry: "30 minutos",
    showIgnoreNote: true,
  }, tenant);
}

/** Verificación de email al registrarse (link de un solo uso, 48 horas) */
export async function sendVerifyEmail(to: string, verifyLink: string, tenant?: TenantMailContext) {
  return sendTemplatedEmail(to, {
    subject: `${APP_NAME} · Verificá tu email`,
    heading: "Verificá tu email",
    intro: "Para activar tu cuenta en TPTech, hacé click en el botón. Este link es de un solo uso.",
    ctaText: "Verificar mi email",
    ctaUrl: verifyLink,
    expiry: "48 horas",
    showIgnoreNote: true,
  }, tenant);
}

/** Invitación de acceso al sistema (link de un solo uso, 7 días) */
export async function sendInviteEmail(to: string, inviteLink: string, jewelryName?: string, tenant?: TenantMailContext) {
  const storeName = jewelryName ? escapeHtml(jewelryName) : APP_NAME;
  return sendTemplatedEmail(to, {
    subject: `Te invitaron a unirte a ${storeName} en ${APP_NAME}`,
    heading: `Bienvenido/a a ${storeName}`,
    intro: `Fuiste invitado/a a acceder a ${APP_NAME} como parte del equipo de ${storeName}. Hacé click en el botón para crear tu contraseña y activar tu cuenta.`,
    ctaText: "Activar mi cuenta",
    ctaUrl: inviteLink,
    expiry: "7 días",
    showIgnoreNote: false,
  }, tenant);
}
