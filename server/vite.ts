import express, { type Express } from "express";
import fs from "fs";
import path from "path";
import { type Server } from "http";
import { randomUUID } from "node:crypto";

export function log(message: string, source = "express") {
  const formattedTime = new Date().toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });

  console.log(`${formattedTime} [${source}] ${message}`);
}

export async function setupVite(app: Express, server: Server) {
  // All Vite-related packages are devDependencies pruned in production.
  // We load them via dynamic import() so they are only resolved when this
  // function is actually called (development only). Static top-level imports
  // would be hoisted to the top of the ESM bundle by esbuild and evaluated
  // before any code runs, crashing the production server at startup.
  const [
    { createServer: createViteServer, createLogger },
    { default: react },
    { default: runtimeErrorOverlay },
  ] = await Promise.all([
    import("vite"),
    import("@vitejs/plugin-react"),
    import("@replit/vite-plugin-runtime-error-modal"),
  ]);

  const viteLogger = createLogger();

  // Resolve paths relative to the project root (one level up from this file
  // in source; two levels up from dist/index.js in the production bundle –
  // but this function is never called there).
  const projectRoot = path.resolve(import.meta.dirname, "..");
  const clientRoot = path.resolve(projectRoot, "client");

  const extraPlugins: import("vite").Plugin[] = [];
  if (process.env.REPL_ID !== undefined) {
    const { cartographer } = await import("@replit/vite-plugin-cartographer");
    extraPlugins.push(cartographer());
  }

  const vite = await createViteServer({
    plugins: [react(), runtimeErrorOverlay(), ...extraPlugins],
    resolve: {
      alias: {
        "@": path.resolve(clientRoot, "src"),
        "@shared": path.resolve(projectRoot, "shared"),
        "@assets": path.resolve(projectRoot, "attached_assets"),
      },
    },
    root: clientRoot,
    build: {
      outDir: path.resolve(projectRoot, "dist", "public"),
      emptyOutDir: true,
    },
    server: {
      middlewareMode: true,
      hmr: { server },
      allowedHosts: true as const,
      fs: {
        strict: true,
        deny: ["**/.*"],
      },
    },
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      },
    },
    appType: "custom",
  });

  app.use(vite.middlewares);
  app.use("*", async (req, res, next) => {
    const url = req.originalUrl;

    try {
      const clientTemplate = path.resolve(clientRoot, "index.html");

      // always reload the index.html file from disk incase it changes
      let template = await fs.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${randomUUID()}"`,
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e as Error);
      next(e);
    }
  });
}

export function serveStatic(app: Express) {
  const distPath = path.resolve(import.meta.dirname, "public");

  if (!fs.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`,
    );
  }

  app.use(express.static(distPath));

  // fall through to index.html if the file doesn't exist
  app.use("*", (_req, res) => {
    res.sendFile(path.resolve(distPath, "index.html"));
  });
}
