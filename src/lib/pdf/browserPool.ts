// src/lib/pdf/browserPool.ts
// =============================================================================
// C4 — Pool singleton de Chromium para Puppeteer.
//
// El cold-start de Chromium en serverless / Render (descargar binario,
// inicializar el browser) cuesta varios cientos de ms. Como el renderer
// HTML del PDF se invoca por cada generación de factura, mantenemos UN
// solo Browser vivo entre invocaciones y abrimos/cerramos sólo la
// `Page` por request.
//
// Reglas:
//   · El renderer JAMÁS instancia su propio `puppeteer.launch()`. Sólo
//     usa `getBrowser()` de acá.
//   · Si el browser se cae (`disconnected`), la próxima llamada lo
//     reabre transparentemente.
//   · `closeBrowser()` se llama desde shutdown del server o desde tests
//     (afterAll). Si no se llama, Node lo libera al salir el proceso.
//   · En tests usamos `__setBrowserFactoryForTests` para inyectar un
//     mock — NUNCA lanzamos Chromium real en Vitest.
//
// Variables de entorno:
//   · CHROMIUM_REMOTE_URL — URL al tarball de chromium (requerido por
//     @sparticuz/chromium-min). Si no se setea, se usa el default de
//     la versión instalada (apunta a un CDN público).
//   · CHROMIUM_HEADLESS    — "false" para debug local con UI; default true.
// =============================================================================

import type { Browser, LaunchOptions } from "puppeteer-core";

// ─── Inyección de factory (sólo tests) ────────────────────────────────────────

/** Factory que sabe lanzar un browser. En producción es el wrapper que
 *  arma `executablePath` + `args` de chromium-min y llama a
 *  `puppeteer.launch`. En tests se reemplaza con un mock que devuelve un
 *  objeto Browser falso. */
type BrowserFactory = () => Promise<Browser>;

let browserFactory: BrowserFactory = defaultBrowserFactory;

/** Sólo para tests. Permite reemplazar la factory que produce el
 *  Browser. Llamar `__setBrowserFactoryForTests(null)` para volver al
 *  default. */
export function __setBrowserFactoryForTests(factory: BrowserFactory | null): void {
  browserFactory = factory ?? defaultBrowserFactory;
  // Si ya había un browser cacheado, lo invalidamos para que la próxima
  // `getBrowser()` use el mock fresco.
  cachedBrowser = null;
}

async function defaultBrowserFactory(): Promise<Browser> {
  // Imports dinámicos para que el require de chromium-min (que es
  // pesado, ~20MB) no impacte el cold-start del server cuando el PDF
  // engine HTML todavía no está activo (C5 lo enciende vía PDF_ENGINE).
  const puppeteer  = (await import("puppeteer-core")).default;
  const chromium   = (await import("@sparticuz/chromium-min")).default;

  const remoteUrl  = process.env.CHROMIUM_REMOTE_URL?.trim();
  const headlessEnv = process.env.CHROMIUM_HEADLESS?.trim().toLowerCase();
  const headless   = headlessEnv === "false" ? false : true;

  // chromium-min necesita una URL pública del tarball del binario. Si no
  // se setea, usa el default de la versión instalada (public CDN). En
  // Render, recomendado pinear con CHROMIUM_REMOTE_URL para evitar
  // cambios silenciosos.
  const executablePath = await chromium.executablePath(remoteUrl);

  const launchOpts: LaunchOptions = {
    args: chromium.args,
    executablePath,
    headless,
  };

  return puppeteer.launch(launchOpts);
}

// ─── Estado del pool ──────────────────────────────────────────────────────────

let cachedBrowser: Browser | null = null;
/** Promise en vuelo del lanzamiento — evita que dos requests concurrentes
 *  arranquen DOS browsers cuando el primero llega y todavía no terminó
 *  de iniciar. */
let launching: Promise<Browser> | null = null;

/** Devuelve el browser singleton. Si está caído o nunca arrancó, lo
 *  (re)inicia. Concurrencia-safe: si dos calls llegan al mismo tiempo
 *  durante el launch, comparten la misma promise. */
export async function getBrowser(): Promise<Browser> {
  // Si tengo browser cacheado y está conectado, lo devuelvo.
  if (cachedBrowser && cachedBrowser.connected) {
    return cachedBrowser;
  }

  // Si hay un launch en curso, espero ese.
  if (launching) {
    return launching;
  }

  // Lanzo uno nuevo. El cleanup del cacheado previo (si lo había pero
  // estaba disconnected) lo hacemos best-effort sin bloquear.
  if (cachedBrowser) {
    safeCloseBrowser(cachedBrowser);
    cachedBrowser = null;
  }

  launching = (async (): Promise<Browser> => {
    const b = await browserFactory();
    // Registramos handler de disconnect para invalidar el cache si el
    // proceso muere. Esto sólo se aplica al browser real con eventos
    // EventEmitter — el mock de tests puede o no implementarlo.
    if (typeof b.on === "function") {
      b.on("disconnected", () => {
        if (cachedBrowser === b) {
          cachedBrowser = null;
        }
      });
    }
    cachedBrowser = b;
    return b;
  })();

  try {
    return await launching;
  } finally {
    launching = null;
  }
}

/** Cierra el browser singleton si está vivo. Idempotente. Pensado para
 *  shutdown hooks del server y `afterAll` de tests. */
export async function closeBrowser(): Promise<void> {
  const b = cachedBrowser;
  cachedBrowser = null;
  if (!b) return;
  await safeCloseBrowser(b);
}

async function safeCloseBrowser(b: Browser): Promise<void> {
  try {
    await b.close();
  } catch {
    // Si ya estaba cerrado o crasheó, no nos importa — el objetivo era
    // liberar recursos. No queremos que un error de cleanup tumbe el
    // process.
  }
}
