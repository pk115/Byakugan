import { createHash, randomBytes } from "node:crypto";
import { resolve } from "node:path";

function requiredSecret(name: string): string {
  const value = process.env[name];
  if (value && value.length >= 24) return value;
  if (process.env.NODE_ENV === "production") {
    throw new Error(`${name} must be set and contain at least 24 characters`);
  }
  return randomBytes(32).toString("hex");
}

export const config = {
  host: process.env.SUPAPULSE_HOST ?? "127.0.0.1",
  port: Number(process.env.SUPAPULSE_PORT ?? 3000),
  dataDir: resolve(process.env.SUPAPULSE_DATA_DIR ?? "./data"),
  masterKey: createHash("sha256").update(requiredSecret("SUPAPULSE_MASTER_KEY")).digest(),
  sessionSecret: requiredSecret("SUPAPULSE_SESSION_SECRET"),
  isProduction: process.env.NODE_ENV === "production",
  secureCookies: process.env.SUPAPULSE_SECURE_COOKIES === "true",
  publicOrigin: process.env.SUPAPULSE_PUBLIC_ORIGIN?.replace(/\/$/,""),
  // Number of reverse proxies in front of the app (Cloudflare Tunnel = 1). 0 = use the socket address. Only set it when the port is not reachable except through the proxy.
  trustProxyHops: Math.max(0, Math.trunc(Number(process.env.SUPAPULSE_TRUST_PROXY_HOPS ?? 0)) || 0)
  ,maintenanceMode: process.env.SUPAPULSE_MAINTENANCE_MODE === "true"
};
