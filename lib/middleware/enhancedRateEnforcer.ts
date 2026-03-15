// src/lib/middleware/enhancedRateEnforcer.ts
import { NextRequest, NextResponse } from "next/server";
import { rateLimit } from "@/lib/middleware/rateLimit";
import type { MiddlewareContext, AuthenticatedActionContext } from "./types";
import { AuthenticatedActionHandler } from "./authenticatedActionHandler";
import { ClientIPDetector } from "@/lib/clientIp";

/**
 * EnhancedRateEnforcer — The Smart Traffic Cop
 */
export class EnhancedRateEnforcer {
  private static readonly CONFIGS = {
    auth: {
      signin: { windowMs: 15 * 60 * 1000, limit: 10, burst: 5 }, // Increased limits
      signup: { windowMs: 60 * 60 * 1000, limit: 5, burst: 2 },
      password_reset: { windowMs: 30 * 60 * 1000, limit: 5, burst: 2 },
      verify_email: { windowMs: 10 * 60 * 1000, limit: 10, burst: 5 },
    },
    api: {
      public: { windowMs: 60 * 1000, limit: 120 }, // Increased limits
      authenticated: { windowMs: 60 * 1000, limit: 600 },
      admin: { windowMs: 60 * 1000, limit: 2000 },
    },
    default: { windowMs: 60 * 1000, limit: 200 },
  };

  static async enforce(
    request: NextRequest,
    context: MiddlewareContext
  ): Promise<NextResponse> {
    const authContext = AuthenticatedActionHandler.enhanceContext(
      request,
      context
    );

    // Development bypass
    if (process.env.NODE_ENV !== "production") {
      return NextResponse.next();
    }

    // Skip rate limiting for static assets
    if (request.nextUrl.pathname.startsWith('/_next') || 
        request.nextUrl.pathname.startsWith('/static') ||
        request.nextUrl.pathname === '/favicon.ico') {
      return NextResponse.next();
    }

    const actionType = authContext.actionType;

    // Dynamic key
    const key = this.getRateLimitKey(request, context, authContext);
    const config = this.getDynamicConfig(actionType, authContext);

    try {
      const result = await rateLimit(request, {
        windowMs: config.windowMs,
        limit: config.limit,
        key,
        namespace: `rate_${actionType}_${
          authContext.isAuthenticated ? "auth" : "anon"
        }`,
        burst: config.burst,
      });

      return this.buildResponse(result, config);
    } catch (error) {
      console.error("[RateEnforcer] Error:", error);
      // Fail open - don't block requests on error
      return NextResponse.next();
    }
  }

  private static getRateLimitKey(
    request: NextRequest,
    context: MiddlewareContext,
    authContext: AuthenticatedActionContext
  ): string {
    if (authContext.userContext?.userId) {
      return `user:${authContext.userContext.userId}`;
    }
    if (context.sessionToken) {
      return `session:${context.sessionToken.substring(0, 32)}`;
    }
    
    // Simple IP-based key for anonymous users
    const ip = ClientIPDetector.getClientIP(request).ip;
    return `ip:${ip}`;
  }

  private static getDynamicConfig(
    actionType: AuthenticatedActionContext["actionType"],
    authContext: AuthenticatedActionContext
  ): { windowMs: number; limit: number; burst?: number } {
    if (actionType === "signin") return this.CONFIGS.auth.signin;
    if (actionType === "signup") return this.CONFIGS.auth.signup;
    if (actionType === "password_reset") return this.CONFIGS.auth.password_reset;
    if (actionType === "verify_email") return this.CONFIGS.auth.verify_email;

    if (authContext.isPrivatePath || authContext.isAuthenticated) {
      if (authContext.userContext?.role === "ADMIN") {
        return this.CONFIGS.api.admin;
      }
      return this.CONFIGS.api.authenticated;
    }

    if (authContext.pathname.startsWith("/api/")) {
      return this.CONFIGS.api.public;
    }

    return this.CONFIGS.default;
  }

  private static buildResponse(
    result: {
      success: boolean;
      limit: number;
      remaining: number;
      reset: number;
    },
    config: any
  ): NextResponse {
    const { success, limit, remaining, reset } = result;
    
    // Always allow in production if there's any doubt
    if (!success && process.env.NODE_ENV === "production") {
      // Log but don't block in production
      console.warn(`[RateEnforcer] Would block, but allowing: ${remaining} remaining`);
      const response = NextResponse.next();
      response.headers.set("X-RateLimit-Limit", limit.toString());
      response.headers.set("X-RateLimit-Remaining", Math.max(0, remaining).toString());
      response.headers.set("X-RateLimit-Warning", "approaching_limit");
      return response;
    }

    const response = success
      ? NextResponse.next()
      : new NextResponse(
          JSON.stringify({
            error: "Too Many Requests",
            message: "Rate limit exceeded. Please try again later.",
            retryAfter: Math.max(1, Math.ceil((reset - Date.now()) / 1000)),
          }),
          {
            status: 429,
            headers: {
              "Content-Type": "application/json",
              "Retry-After": Math.max(1, Math.ceil((reset - Date.now()) / 1000)).toString(),
            },
          }
        );

    response.headers.set("X-RateLimit-Limit", limit.toString());
    response.headers.set("X-RateLimit-Remaining", Math.max(0, remaining).toString());
    response.headers.set("X-RateLimit-Reset", new Date(reset).toISOString());

    return response;
  }

  private static simpleHash(str: string): string {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash + char) | 0;
    }
    return (hash >>> 0).toString(36);
  }
}