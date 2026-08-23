import { createHmac, timingSafeEqual } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";
import { config } from "./config.js";

const COOKIE_NAME = "supapulse_session";

function signature(payload: string) {
  return createHmac("sha256", config.sessionSecret).update(payload).digest("base64url");
}

export function createSession(userId: number) {
  const payload = Buffer.from(JSON.stringify({ userId, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 })).toString("base64url");
  return `${payload}.${signature(payload)}`;
}

export function sessionUser(token?: string): number | null {
  if (!token) return null;
  const [payload, suppliedSignature] = token.split(".");
  if (!payload || !suppliedSignature) return null;
  const expected = signature(payload);
  const supplied = Buffer.from(suppliedSignature);
  const expectedBuffer = Buffer.from(expected);
  if (supplied.length !== expectedBuffer.length || !timingSafeEqual(supplied, expectedBuffer)) return null;
  try {
    const value = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { userId: number; exp: number };
    return value.exp > Date.now() ? value.userId : null;
  } catch {
    return null;
  }
}

export function setSessionCookie(reply: FastifyReply, token: string) {
  reply.setCookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: "strict",
    secure: config.secureCookies,
    path: "/",
    maxAge: 7 * 24 * 60 * 60
  });
}

export function clearSessionCookie(reply: FastifyReply) {
  reply.clearCookie(COOKIE_NAME, { path: "/" });
}

export async function requireAuth(request: FastifyRequest, reply: FastifyReply) {
  const userId = sessionUser(request.cookies[COOKIE_NAME]);
  if (!userId) return reply.code(401).send({ error: "Authentication required" });
}
