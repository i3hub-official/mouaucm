// src/lib/middleware/requestTransformer.ts
import { NextRequest, NextResponse } from "next/server";
import type { MiddlewareContext } from "./types";

export class RequestTransformer {
  private static readonly DANGEROUS_PATTERNS = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /vbscript:/gi,
    /on\w+\s*=/gi,
    /expression\s*\(/gi,
    /@@\w+/gi,
    /\bUNION\b.*\bSELECT\b/gi,
    /\bINSERT\b.*\bINTO\b/gi,
    /\bDELETE\b.*\bFROM\b/gi,
    /\bUPDATE\b.*\bSET\b/gi,
    /\bDROP\b.*\bTABLE\b/gi,
    /'\s*OR\s*'\d'='1/gi,
    /--/g,
    /;\s*(--|\/\*)/g,
    /\.\.\//g,
    /etc\/passwd/gi,
    /<iframe/gi,
    /onload\s*=/gi,
  ];

  // Whitelist of safe paths that shouldn't be heavily scanned
  private static readonly SAFE_PATH_PREFIXES = [
    '/_next',
    '/static',
    '/images',
    '/favicon.ico',
    '/api/auth',  // Auth endpoints might contain special chars
    '/api/public',
    '/health',
    '/sr',
    '/check',
  ];

  static transform(
    request: NextRequest,
    context: MiddlewareContext
  ): NextResponse {
    // Development bypass (keep this for dev)
    if (process.env.NODE_ENV === "development") {
      console.log("[RequestTransformer] Dev mode → bypassed");
      return NextResponse.next();
    }
    
    // Production bypass for static assets and auth routes
    const pathname = request.nextUrl.pathname;
    if (this.SAFE_PATH_PREFIXES.some(prefix => pathname.startsWith(prefix))) {
      return NextResponse.next();
    }
    
    try {
      // PHASE 1: EARLY MALICIOUS DETECTION — NUCLEAR RESPONSE
      const fullUrl = request.url;
      const queryString = request.nextUrl.search;
      const userAgent = request.headers.get("user-agent") || "";
      
      // Only check GET parameters for dangerous patterns
      // POST body is handled separately by your API routes
      const paramValues = request.method === 'GET' 
        ? Array.from(request.nextUrl.searchParams.values())
        : []; // Skip POST body params in middleware

      const maliciousInput = [
        fullUrl,
        queryString,
        pathname,
        userAgent,
        ...paramValues,
      ].some((str) => {
        // Skip empty strings
        if (!str) return false;
        
        // Check each pattern
        return this.DANGEROUS_PATTERNS.some((pattern) => {
          try {
            return pattern.test(str);
          } catch {
            return false;
          }
        });
      });

      if (maliciousInput) {
        console.log(
          `[REQUEST TRANSFORMER] NUCLEAR THREAT DETECTED → NEUTRALIZING`
        );

        const blockUrl = new URL("/security/blocked", request.url);
        blockUrl.searchParams.set(
          "id",
          `MAL-${Date.now().toString(36).toUpperCase()}-${Math.random()
            .toString(36)
            .substring(2, 6)}`
        );
        blockUrl.searchParams.set("score", "99.9");
        blockUrl.searchParams.set(
          "reason",
          "MALICIOUS_PAYLOAD_DETECTED"
        );
        blockUrl.searchParams.set("action", "NEUTRALIZE");

        const response = NextResponse.redirect(blockUrl);
        response.headers.set("X-Defense-Action", "NEUTRALIZE");
        response.headers.set(
          "X-Reason",
          "Malicious payload detected in request"
        );
        response.headers.set(
          "Cache-Control",
          "no-store, no-cache, must-revalidate, proxy-revalidate"
        );
        response.headers.set("Pragma", "no-cache");
        response.headers.set("Expires", "0");

        return response;
      }

      // PHASE 2: Normal transformation (safe requests only)
      const url = new URL(request.url);

      // Sanitize query params (safe now)
      this.sanitizeSearchParams(url.searchParams);

      // Normalize headers
      const headers = new Headers(request.headers);
      this.normalizeHeaders(headers);

      // Add metadata
      headers.set("x-client-ip", context.clientIp);
      headers.set("x-request-id", this.generateRequestId());
      headers.set("x-request-timestamp", new Date().toISOString());

      // Create transformed request
      const transformedRequest = new NextRequest(url.toString(), {
        method: request.method,
        headers,
        body: request.method !== 'GET' && request.method !== 'HEAD' 
          ? request.body 
          : undefined,
        // @ts-ignore - duplex is experimental but needed for streams
        duplex: request.body ? "half" : undefined,
      });

      const response = NextResponse.next({
        request: transformedRequest,
      });

      response.headers.set("x-transformed", "true");
      response.headers.set("x-sanitized", "true");

      return response;
    } catch (error) {
      console.error(
        "[REQUEST TRANSFORMER] Critical failure:",
        error
      );

      // In production, log but don't block on errors
      if (process.env.NODE_ENV === "production") {
        console.error("[REQUEST TRANSFORMER] Error details:", error);
        return NextResponse.next(); // Allow request to proceed
      }

      // In development, still show the error
      const blockUrl = new URL("/security/blocked", request.url);
      blockUrl.searchParams.set("reason", "TRANSFORMER_FAILURE");
      blockUrl.searchParams.set("score", "98");
      blockUrl.searchParams.set("action", "NEUTRALIZE");

      const response = NextResponse.redirect(blockUrl);
      response.headers.set("X-Defense-Action", "NEUTRALIZE");
      return response;
    }
  }

  // Safe sanitization (only runs if no malicious pattern found)
  private static sanitizeSearchParams(searchParams: URLSearchParams): void {
    for (const [key, value] of searchParams.entries()) {
      // Truncate extremely long values (potential DoS)
      if (value.length > 1000) {
        searchParams.set(key, value.substring(0, 1000));
      }
      
      // Remove null bytes and control characters
      const cleanValue = value.replace(/[\x00-\x1F\x7F]/g, '');
      if (cleanValue !== value) {
        searchParams.set(key, cleanValue);
      }
    }
  }

  private static normalizeHeaders(headers: Headers): void {
    const ua = headers.get("user-agent");
    if (ua && ua.length > 500) {
      headers.set("user-agent", ua.substring(0, 500) + "...");
    }

    // Only remove spoofing headers, not essential ones
    if (headers.has("x-forwarded-for") && headers.get("x-forwarded-for")?.includes(',')) {
      // Keep the first IP if there are multiple
      const forwardedFor = headers.get("x-forwarded-for");
      if (forwardedFor) {
        const firstIp = forwardedFor.split(',')[0].trim();
        headers.set("x-forwarded-for", firstIp);
      }
    }
  }

  private static generateRequestId(): string {
    return `req_${Date.now().toString(36)}-${Math.random()
      .toString(36)
      .substring(2, 7)}`;
  }
}
