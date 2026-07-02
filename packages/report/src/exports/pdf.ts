/**
 * PDF export via puppeteer-core (§13). LAZY + GRACEFUL: puppeteer-core is only
 * imported when a PDF is actually requested, and if no browser executable is
 * available (the common CI / air-gapped case) it fails with a clear, typed
 * signal rather than crashing report generation. A `PdfRenderer` can be injected
 * so the PDF path is exercised OFFLINE in tests without a real browser.
 */
import type { Report } from "@montr/contracts";
import { renderReportHtml } from "./html.js";

/** Renders finished HTML to PDF bytes. The default uses puppeteer-core. */
export type PdfRenderer = (html: string) => Promise<Uint8Array>;

export interface PdfOptions {
  /** Path to a Chromium/Chrome executable (or set PUPPETEER_EXECUTABLE_PATH). */
  executablePath?: string;
  /** Inject a renderer (tests / an alternative engine). Bypasses puppeteer-core. */
  renderer?: PdfRenderer;
}

/** Thrown when a PDF is requested but no browser is available. Catchable/graceful. */
export class PdfBrowserUnavailableError extends Error {
  readonly code = "PDF_BROWSER_UNAVAILABLE";
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "PdfBrowserUnavailableError";
  }
}

/**
 * Minimal structural view of puppeteer-core — only the members we call. Bridged
 * with `as unknown as` so the build does not couple to puppeteer's heavy type
 * surface (the real module satisfies this shape at runtime).
 */
interface PdfPageLike {
  setContent(html: string, opts?: { waitUntil?: string }): Promise<unknown>;
  pdf(opts?: { format?: string; printBackground?: boolean }): Promise<Uint8Array>;
}
interface PdfBrowserLike {
  newPage(): Promise<PdfPageLike>;
  close(): Promise<void>;
}
interface PuppeteerLike {
  launch(opts: {
    executablePath: string;
    headless?: boolean;
    args?: string[];
  }): Promise<PdfBrowserLike>;
}

/** Default renderer: lazily launch puppeteer-core, print, and always close. */
async function puppeteerRender(html: string, opts: PdfOptions): Promise<Uint8Array> {
  let mod: { default?: PuppeteerLike } & Partial<PuppeteerLike>;
  try {
    mod = (await import("puppeteer-core")) as unknown as {
      default?: PuppeteerLike;
    } & Partial<PuppeteerLike>;
  } catch (cause) {
    throw new PdfBrowserUnavailableError(
      "puppeteer-core is not available; PDF export unavailable",
      {
        cause,
      },
    );
  }
  const puppeteer: PuppeteerLike | undefined = mod.launch ? (mod as PuppeteerLike) : mod.default;
  if (!puppeteer) {
    throw new PdfBrowserUnavailableError("puppeteer-core did not expose a launcher");
  }

  const executablePath = opts.executablePath ?? process.env["PUPPETEER_EXECUTABLE_PATH"];
  if (!executablePath) {
    throw new PdfBrowserUnavailableError(
      "no browser executable configured (set PdfOptions.executablePath or PUPPETEER_EXECUTABLE_PATH); PDF export skipped gracefully",
    );
  }

  let browser: PdfBrowserLike | undefined;
  try {
    browser = await puppeteer.launch({
      executablePath,
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    });
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: "networkidle0" });
    return await page.pdf({ format: "A4", printBackground: true });
  } catch (cause) {
    throw new PdfBrowserUnavailableError(`browser failed to render PDF: ${String(cause)}`, {
      cause,
    });
  } finally {
    await browser?.close();
  }
}

/**
 * Render a report to PDF bytes. Uses the injected `renderer` if present, else
 * puppeteer-core. Throws {@link PdfBrowserUnavailableError} when no browser is
 * available — callers treat PDF as best-effort.
 */
export async function renderReportPdf(report: Report, opts: PdfOptions = {}): Promise<Uint8Array> {
  const html = renderReportHtml(report);
  const render = opts.renderer ?? ((h: string) => puppeteerRender(h, opts));
  return render(html);
}
