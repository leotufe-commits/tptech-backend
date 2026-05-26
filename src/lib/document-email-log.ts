// src/lib/document-email-log.ts
// =============================================================================
//  Helper de persistencia para el historial documental de emails (E1).
//
//  TPTech es la SSOT del historial — los mails NO aparecen en "Elementos
//  enviados" del Outlook/Gmail del operador (porque salen desde el
//  provider del backend, Postmark). Este log es lo que asegura
//  trazabilidad: quién envió qué a quién y cuándo.
//
//  Reglas duras del helper:
//    · Multi-tenant: `jewelryId` siempre requerido. Cero excepciones.
//    · `documentId` es string libre — NO FK al Sale. Sobrevive a
//      soft-delete del documento (la auditoría no se borra).
//    · `bodySnapshot` debe ser texto plano del mensaje enviado (no
//      HTML). El caller es responsable de pasarlo así.
//    · Inmutable: este modelo no expone update en v1. Cualquier
//      cambio futuro (delivered/opened via webhook) será otra función.
//    · NO propaga errores: si la persistencia falla, devuelve null
//      y deja un `console.error`. El log JAMÁS debe impedir que el
//      envío real del mail funcione.
//
//  Status:
//    · "SENT"    — provider aceptó el mensaje (default).
//    · "FAILED"  — provider rechazó o hubo error de red.
//    · "PENDING" — reservado para futuros flujos async. NO se usa
//                   en E2 — se ignora si llega.
// =============================================================================

import { prisma } from "./prisma.js";

export type DocumentEmailLogStatus = "PENDING" | "SENT" | "FAILED";

export type DocumentEmailLogKind =
  | "SALE_INVOICE"
  | "BUDGET"
  | "ORDER"
  | "REMITO"
  | "CREDIT_NOTE";

/** Input mínimo para crear un log. Todos los campos opcionales se
 *  resuelven a `null` o al default declarado en el schema. */
export interface CreateDocumentEmailLogInput {
  jewelryId:           string;
  documentKind:        DocumentEmailLogKind | string;
  documentId:          string;
  /** Si el documento ya está persistido como Sale en backend. v1 lo
   *  llena para Factura de Ventas (siempre); otros kinds lo dejan en
   *  null hasta tener su persistencia propia. */
  saleId?:             string | null;
  recipientEmail:      string;
  /** Asunto FINAL enviado (tras interpolación de variables). */
  subjectSnapshot:     string;
  /** Cuerpo FINAL enviado — TEXTO PLANO, NO HTML. */
  bodySnapshot:        string;
  attachmentFilename?: string | null;
  provider?:           string;
  providerMessageId?:  string | null;
  status?:             DocumentEmailLogStatus;
  sentByUserId?:       string | null;
}

export interface CreatedDocumentEmailLog {
  id: string;
}

/** Crea un log de email enviado. NUNCA lanza — si la persistencia
 *  falla, devuelve null y loggea el error en stderr. Pensado para
 *  envolver el final del flujo de envío sin riesgo de romper la
 *  operación del operador.
 *
 *  Multi-tenant: el caller DEBE pasar `jewelryId` desde el context
 *  del request (`req.user.jewelryId`). Esta función no valida cross-
 *  tenant — confía en el caller para eso. */
export async function createDocumentEmailLog(
  input: CreateDocumentEmailLogInput,
): Promise<CreatedDocumentEmailLog | null> {
  try {
    const created = await prisma.documentEmailLog.create({
      data: {
        jewelryId:          input.jewelryId,
        documentKind:       input.documentKind,
        documentId:         input.documentId,
        saleId:             input.saleId ?? null,
        recipientEmail:     input.recipientEmail,
        subjectSnapshot:    input.subjectSnapshot,
        bodySnapshot:       input.bodySnapshot,
        attachmentFilename: input.attachmentFilename ?? null,
        provider:           input.provider ?? "postmark",
        providerMessageId:  input.providerMessageId ?? null,
        status:             input.status ?? "SENT",
        sentByUserId:       input.sentByUserId ?? null,
      },
      select: { id: true },
    });
    return created;
  } catch (err) {
    console.error("[document-email-log] failed to persist log:", err);
    return null;
  }
}
