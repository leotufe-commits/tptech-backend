// src/modules/auth/auth.google.controller.ts
import type { Request, Response } from "express";
import { OAuth2Client } from "google-auth-library";
import type { TokenPayload } from "google-auth-library";
import { UserStatus } from "@prisma/client";

import { prisma } from "../../lib/prisma.js";
import { buildAuthResponse } from "../../lib/authResponse.js";
import { auditLog } from "../../lib/auditLogger.js";
import {
  fetchUsersForLoginOptions,
  fetchUserForAuthByEmailAndTenant,
  signToken,
  setAuthCookie,
  s,
} from "./auth.controller.js";

/* =========================
   ENV / CONST
========================= */
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const client = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

/* =========================
   CONTROLLER
========================= */

/**
 * POST /api/auth/google/token
 * Verifica el ID token de Google y:
 *   - Si el usuario existe y está ACTIVE  → login directo (emite cookie + JWT)
 *   - Si el usuario existe y está PENDING → lo activa (Google verificó el email) + login
 *   - Si el usuario no existe             → devuelve REGISTER_REQUIRED
 *   - Si tiene múltiples tenants          → devuelve TENANT_REQUIRED
 */
export async function googleToken(req: Request, res: Response) {
  const { credential } = req.body as { credential?: unknown };

  if (!s(credential)) {
    return res.status(400).json({ ok: false, message: "El campo credential es requerido." });
  }

  if (!client || !GOOGLE_CLIENT_ID) {
    console.error("[auth.google] GOOGLE_CLIENT_ID no está configurado.");
    return res.status(500).json({ ok: false, message: "Google Auth no está configurado en el servidor." });
  }

  // ── Verificar token con Google ────────────────────────────────────────────
  let payload: TokenPayload | undefined;

  try {
    const ticket = await client.verifyIdToken({
      idToken:  s(credential),
      audience: GOOGLE_CLIENT_ID,
    });
    payload = ticket.getPayload();
  } catch {
    return res.status(401).json({ ok: false, message: "Token de Google inválido o expirado." });
  }

  if (!payload) {
    return res.status(401).json({ ok: false, message: "Token de Google inválido." });
  }

  const googleId      = s(payload.sub);
  const email         = s(payload.email).toLowerCase();
  const emailVerified = payload.email_verified === true;
  const fullName      = s(payload.name);
  const firstName     = s(payload.given_name);
  const lastName      = s(payload.family_name);
  const avatarUrl     = s(payload.picture) || null;

  if (!email || !emailVerified) {
    return res.status(400).json({ ok: false, message: "La cuenta de Google no tiene email verificado." });
  }

  try {
    // ── Buscar tenants asociados al email ─────────────────────────────────
    const tenants = await fetchUsersForLoginOptions(email);

    // ── Sin cuenta → necesita registrarse ────────────────────────────────
    if (tenants.length === 0) {
      return res.json({
        ok:      true,
        action:  "REGISTER_REQUIRED",
        profile: { googleId, email, emailVerified, firstName, lastName, fullName, avatarUrl },
      });
    }

    // ── Múltiples tenants → no podemos elegir automáticamente ────────────
    if (tenants.length > 1) {
      return res.json({
        ok:      true,
        action:  "TENANT_REQUIRED",
        tenants,
        profile: { googleId, email, emailVerified, firstName, lastName, fullName, avatarUrl },
      });
    }

    // ── Un solo tenant ────────────────────────────────────────────────────
    const user = await fetchUserForAuthByEmailAndTenant(email, tenants[0].id);

    if (!user || (user as any).deletedAt) {
      return res.status(401).json({ ok: false, message: "Usuario no encontrado." });
    }

    if (user.status === UserStatus.BLOCKED) {
      auditLog(req, {
        action: "auth.google.login",
        success: false,
        userId: user.id,
        tenantId: user.jewelryId,
        meta: { email, reason: "user_blocked" },
      });
      return res.status(403).json({ ok: false, message: "Tu cuenta está bloqueada. Contactá al administrador." });
    }

    // ── Usuario PENDING: Google verificó el email → activar automáticamente
    if (user.status === UserStatus.PENDING) {
      await prisma.user.update({
        where: { id: user.id },
        data: { status: UserStatus.ACTIVE },
      });
    }

    // ── Recargar usuario (para asegurar estado ACTIVE) ────────────────────
    const freshUser = await fetchUserForAuthByEmailAndTenant(email, tenants[0].id);
    if (!freshUser) {
      return res.status(500).json({ ok: false, message: "Error al procesar el login." });
    }

    const token = signToken(freshUser.id, freshUser.jewelryId, freshUser.tokenVersion);
    setAuthCookie(req, res, token);

    auditLog(req, {
      action: "auth.google.login",
      success: true,
      userId: freshUser.id,
      tenantId: freshUser.jewelryId,
      meta: { email, wasActivated: user.status === UserStatus.PENDING },
    });

    return res.json({
      ok:     true,
      action: "LOGIN",
      ...buildAuthResponse({ user: freshUser, token, includeToken: true }),
    });

  } catch (err: unknown) {
    console.error("[auth.google] googleToken error:", err);
    return res.status(500).json({ ok: false, message: "Error al procesar el login con Google." });
  }
}

// TEMP: endpoint de prueba para Google OAuth
export async function googleTest(req: Request, res: Response) {
  console.log("[GOOGLE TEST] ejecutando test endpoint");
  const mockReq = { ...req, body: { credential: "fake" } } as Request;
  return googleToken(mockReq, res);
}
