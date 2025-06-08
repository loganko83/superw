import express, { type Express, type Request, type Response, type NextFunction } from "express";
import fs from "fs";
import path from "path";
import { log } from "./vite";

export function serveStatic(app: Express) {
  const distPath = path.resolve(process.cwd(), "dist", "public");
  const indexPath = path.join(distPath, "index.html");

  // Serve static files from the dist directory
  app.use(express.static(distPath, {
    maxAge: process.env.NODE_ENV === "production" ? "1y" : "0",
    etag: true,
    lastModified: true
  }));

  // Handle client-side routing by serving index.html for all non-API routes
  app.use("*", async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Skip API routes
      if (req.originalUrl.startsWith("/api")) {
        return next();
      }

      // Check if the built index.html file exists
      try {
        await fs.promises.access(indexPath);
        const html = await fs.promises.readFile(indexPath, "utf-8");
        res.status(200).set({ "Content-Type": "text/html" }).end(html);
      } catch (error) {
        log(`Built files not found at ${distPath}. Please run 'npm run build' first.`);
        res.status(404).send("Application not built. Please run 'npm run build' first.");
      }
    } catch (error) {
      log(`Error serving static files: ${error}`);
      res.status(500).send("Internal Server Error");
    }
  });
}