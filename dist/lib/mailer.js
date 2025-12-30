import nodemailer from "nodemailer";
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : undefined;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
export async function sendResetEmail(to, resetLink) {
    // Si no hay SMTP configurado, imprimimos el link en consola (DEV)
    if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) {
        console.log("📩 [DEV] Reset link para:", to);
        console.log("🔗", resetLink);
        return;
    }
    const transporter = nodemailer.createTransport({
        host: SMTP_HOST,
        port: SMTP_PORT,
        secure: SMTP_PORT === 465,
        auth: { user: SMTP_USER, pass: SMTP_PASS },
    });
    await transporter.sendMail({
        from: SMTP_USER,
        to,
        subject: "TPTech - Restablecer contraseña",
        text: `Abrí este link para restablecer tu contraseña: ${resetLink}`,
        html: `<p>Abrí este link para restablecer tu contraseña:</p><p><a href="${resetLink}">${resetLink}</a></p>`,
    });
}
