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
//   · CHROMIUM_EXECUTABLE_PATH — override explícito del path al binario.
//     Si está, gana sobre cualquier auto-detect (útil para CI/Render
//     con Chromium pre-instalado en una ruta conocida).
//   · CHROMIUM_HEADLESS — "false" para debug local con UI; default true.
//   · CHROMIUM_EXTRA_ARGS — args extra separados por coma (avanzado).
//
// Resolución del binario (orden):
//   1. CHROMIUM_EXECUTABLE_PATH si está definido.
//   2. `@sparticuz/chromium` (incluye binario para Linux serverless;
//      en Windows/Mac no resuelve y caemos al paso 3).
//   3. `puppeteer` (full, devDep) — bundled Chromium descargado al
//      `npm install` por el operador en su máquina local.
//   4. Error claro indicando cómo configurar.
// =============================================================================

import { existsSync } from "node:fs";
import type { Browser, LaunchOptions } from "puppeteer-core";

// ─── Inyección de factory (sólo tests) ────────────────────────────────────────

/** Factory que sabe lanzar un browser. En producción/dev es el wrapper
 *  que resuelve `executablePath` + `args` y llama a `puppeteer.launch`.
 *  En tests se reemplaza con un mock que devuelve un objeto Browser
 *  falso. */
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
  // Imports dinámicos para que el peso de chromium/puppeteer no
  // impacte cold-start cuando el PDF HTML no está activo.
  const puppeteer = (await import("puppeteer-core")).default;
  const { executablePath, args } = await resolveChromiumConfig();

  const headlessEnv = process.env.CHROMIUM_HEADLESS?.trim().toLowerCase();
  const headless    = headlessEnv === "false" ? false : true;

  const extraArgs = (process.env.CHROMIUM_EXTRA_ARGS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  const launchOpts: LaunchOptions = {
    args: [...args, ...extraArgs],
    executablePath,
    headless,
  };

  return puppeteer.launch(launchOpts);
}

// ─── Resolución del Chromium executable path ──────────────────────────────────

export interface ChromiumConfig {
  executablePath: string;
  args:           string[];
}

/** Resuelve el path al binario de Chromium probando varias fuentes
 *  en orden: env override → @sparticuz/chromium (serverless) →
 *  puppeteer full (dev local). Falla con un mensaje accionable si
 *  ninguna funciona.
 *
 *  Exportado para tests + para troubleshooting (`resolveChromiumConfig()`
 *  desde un repl muestra qué path se está usando). */
export async function resolveChromiumConfig(): Promise<ChromiumConfig> {
  // 1) Override por env. Útil cuando hay un Chromium custom en
  // /usr/bin/chromium-browser (Render con apt-get install chromium)
  // o en CHROME_BIN para CI.
  const envPath = process.env.CHROMIUM_EXECUTABLE_PATH?.trim();
  if (envPath) {
    return { executablePath: envPath, args: defaultLaunchArgs() };
  }

  // 2) @sparticuz/chromium — incluye binario Linux para serverless.
  //    Sólo lo intentamos en Linux: en Windows/Mac `executablePath()`
  //    puede devolver un path inexistente (ej. `/tmp/chromium`) que
  //    rompe el spawn. Verificamos `existsSync` antes de aceptarlo
  //    para protegernos de versiones futuras del paquete que cambien
  //    el comportamiento del path.
  if (process.platform === "linux") {
    try {
      const chromium = (await import("@sparticuz/chromium")).default;
      const ep = await chromium.executablePath();
      if (ep && typeof ep === "string" && ep.length > 0 && existsSync(ep)) {
        return { executablePath: ep, args: chromium.args };
      }
      if (ep) {
        console.warn(`[PDF] @sparticuz/chromium devolvió path inexistente: ${ep}. Cayendo a fallback.`);
      }
    } catch (err) {
      console.warn(
        `[PDF] @sparticuz/chromium executablePath() no disponible: ${err instanceof Error ? err.message : err}`,
      );
    }
  }

  // 3) puppeteer (full, devDep) — bundled Chromium descargado al
  // `npm install`. Funciona en Windows/Mac/Linux para dev local.
  // También verificamos `existsSync` — si el operador limpió la cache
  // de puppeteer pero no reinstaló, queremos un error claro.
  try {
    const puppeteerFull = (await import("puppeteer")).default;
    const ep = puppeteerFull.executablePath();
    if (ep && typeof ep === "string" && ep.length > 0 && existsSync(ep)) {
      return { executablePath: ep, args: defaultLaunchArgs() };
    }
    if (ep) {
      console.warn(`[PDF] puppeteer devolvió path inexistente: ${ep}. Reinstalá puppeteer.`);
    }
  } catch (err) {
    console.warn(
      `[PDF] puppeteer (full) executablePath() no disponible: ${err instanceof Error ? err.message : err}`,
    );
  }

  // 4) Nada funcionó — mensaje claro.
  throw new Error(
    "No se pudo resolver el binario de Chromium. Opciones:\n" +
    "  · Setear CHROMIUM_EXECUTABLE_PATH al path absoluto del binario.\n" +
    "  · En Linux/serverless: instalar `@sparticuz/chromium` (ya está en deps).\n" +
    "  · En desarrollo local: instalar `puppeteer` (full): `npm install puppeteer --save-dev`.",
  );
}

/** Args por defecto cuando no usamos @sparticuz/chromium (que tiene
 *  los suyos). Estos son sane defaults para correr Chromium headless
 *  en cualquier OS sin opcionales adicionales. */
function defaultLaunchArgs(): string[] {
  return [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
  ];
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
