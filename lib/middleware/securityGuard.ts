// src/lib/middleware/securityGuard.ts
import { NextRequest, NextResponse } from "next/server";
import { getCspConfig } from "@/lib/security/cspConfig";
import type { MiddlewareContext } from "./types";
import crypto from "crypto";

export class SecurityGuard {
  private static readonly ALLOWED_ORIGINS = [
    process.env.NEXT_PUBLIC_BASE_URL,
    "https://*.vercel.app",
    "https://*.vercel.pub",
    "https://mouaucm.vercel.app",
    "https://mouaucm-g1kvoi20t-i3hub.vercel.app",
    "https://mouaucm-r4f1pbdz8-i3hub.vercel.app",
    "http://localhost",
    "https://localhost",
    "http://192.168.0.*",
    "https://192.168.0.*",
  ].filter(Boolean) as string[];

  private static readonly ALLOWED_METHODS = [
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
    "HEAD",
  ];

  private static readonly ALLOWED_HEADERS = [
    "Content-Type",
    "Authorization",
    "X-Requested-With",
    "X-CSRF-Token",
    "Accept",
    "Origin",
    "Cache-Control",
    "x-client-ip",
    "x-request-id",
    "x-user-id",
    "x-user-role",
    "x-authenticated",
    "x-geo-country",
    "x-geo-region",
    "x-bot-score",
    "x-abuse-score",
  ];

  private static readonly EXPOSED_HEADERS = [
    "x-request-id",
    "x-processing-time",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-user-id",
    "x-user-role",
    "x-authenticated",
    "x-geo-country",
    "x-geo-region",
    "x-bot-score",
    "x-abuse-score",
    "x-ip-reputation",
  ];

  static apply(request: NextRequest, context: MiddlewareContext): NextResponse {
    try {
      // Handle CORS preflight
      if (request.method === "OPTIONS") {
        return this.handlePreflight(request);
      }

      const response = NextResponse.next();

      // Add security headers
      this.applySecurityHeaders(response, context);
      this.applyCorsHeaders(request, response);

      // Mark as protected
      response.headers.set("x-security-guard", "active");
      response.headers.set("x-protected-by", "MOUAU ClassMate Shield");

      return response;
    } catch (error) {
      console.error("[SecurityGuard] Error:", error);
      // Never block on errors
      return NextResponse.next();
    }
  }

  private static handlePreflight(request: NextRequest): NextResponse {
    const origin = request.headers.get("origin");
    
    const headers = new Headers({
      "Access-Control-Allow-Methods": this.ALLOWED_METHODS.join(", "),
      "Access-Control-Allow-Headers": this.ALLOWED_HEADERS.join(", "),
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin",
    });

    if (origin && this.isOriginAllowed(origin)) {
      headers.set("Access-Control-Allow-Origin", origin);
      headers.set("Access-Control-Allow-Credentials", "true");
    } else {
      headers.set("Access-Control-Allow-Origin", request.nextUrl.origin);
    }

    return new NextResponse(null, { status: 204, headers });
  }

  private static applySecurityHeaders(
    response: NextResponse,
    context: MiddlewareContext
  ): void {
    // Basic security headers
    const headers: Record<string, string> = {
      "X-Frame-Options": "DENY",
      "X-Content-Type-Options": "nosniff",
      "X-XSS-Protection": "1; mode=block",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
      "X-Powered-By": "MOUAU ClassMate",
    };

    Object.entries(headers).forEach(([key, value]) => {
      if (!response.headers.has(key)) {
        response.headers.set(key, value);
      }
    });

    // HSTS - only in production
    if (process.env.NODE_ENV === "production") {
      response.headers.set(
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains; preload"
      );
    }

    // Content-Security-Policy - Permissive in dev, report-only in prod
    const nonce = context.nonce || Buffer.from(crypto.randomUUID()).toString("base64");
    
    if (process.env.NODE_ENV === "production") {
      // Use report-only mode in production to avoid blocking
      const csp = this.getPermissiveCsp(nonce);
      response.headers.set("Content-Security-Policy-Report-Only", csp);
    } else {
      const csp = this.getPermissiveCsp(nonce);
      response.headers.set("Content-Security-Policy", csp);
    }
    
    response.headers.set("X-CSP-Nonce", nonce);
    
    if (!response.headers.has("x-nonce")) {
      response.headers.set("x-nonce", nonce);
    }
  }

  private static getPermissiveCsp(nonce: string): string {
    return [
      "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:",
      `script-src * 'unsafe-inline' 'unsafe-eval' 'nonce-${nonce}'`,
      "style-src * 'unsafe-inline'",
      "img-src * data: blob:",
      "font-src * data:",
      "connect-src *",
      "frame-src *",
      "object-src *",
      "base-uri *",
      "form-action *",
    ].join("; ");
  }

  private static applyCorsHeaders(
    request: NextRequest,
    response: NextResponse
  ): void {
    const origin = request.headers.get("origin");

    if (origin && this.isOriginAllowed(origin)) {
      response.headers.set("Access-Control-Allow-Origin", origin);
      response.headers.set("Access-Control-Allow-Credentials", "true");
      response.headers.set(
        "Access-Control-Expose-Headers",
        this.EXPOSED_HEADERS.join(", ")
      );
      response.headers.set("Vary", "Origin");
    }
  }

  private static isOriginAllowed(origin: string): boolean {
    try {
      const url = new URL(origin);
      const hostname = url.hostname;
      
      // Allow all Vercel preview deployments
      if (hostname.includes('.vercel.app')) return true;
      
      return this.ALLOWED_ORIGINS.some((pattern) => {
        if (!pattern) return false;
        if (pattern.includes('*')) {
          const regex = new RegExp(
            "^" + pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace("*", ".*") + "$"
          );
          return regex.test(origin);
        }
        return pattern === origin;
      });
    } catch {
      return false;
    }
  }
}