// src/lib/middleware/sessionTokenValidator.ts
import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/server/prisma";
import { JWTUtils, type TokenPayload } from "@/lib/server/jwt";
import { nanoid } from "nanoid";
import { ClientIPDetector } from "@/lib/clientIp";
import type { MiddlewareContext } from "./types";
import { Role, AuditAction } from "@/lib/generated/prisma/enums";

interface SessionUser {
  id: string;
  name: string | null;
  email: string;
  role: Role;
  matricNumber?: string | null;
  employeeId?: string | null; // Changed from teacherId to employeeId
  department?: string | null;
}

interface SessionValidationResult {
  isValid: boolean;
  needsRefresh: boolean;
  shouldLogout: boolean;
  user?: SessionUser;
  action: "continue" | "refresh" | "logout" | "redirect_login";
  errorCode?:
    | "TOKEN_INVALID"
    | "TOKEN_EXPIRED"
    | "INVALID_SIGNATURE"
    | "USER_INACTIVE"
    | "DEVICE_MISMATCH"
    | "SUSPICIOUS_ACTIVITY"
    | "RATE_LIMITED"
    | "SYSTEM_ERROR";
  securityLevel: "low" | "medium" | "high";
}

// Define type for Prisma session with user
type SessionWithUser = {
  id: string;
  sessionToken: string;
  userId: string;
  expires: Date;
  createdAt: Date;
  updatedAt: Date;
  deviceFingerprint: string | null;
  userAgent: string | null;
  ipAddress: string | null;
  securityLevel: string;
  lastAccessedAt: Date;
  refreshCount: number;
  user: {
    id: string;
    name: string | null;
    email: string;
    role: Role;
    isActive: boolean;
    student: {
      matricNumber: string;
      department: string;
    } | null;
    teacher: {
      employeeId: string; // Changed from teacherId to employeeId
      department: string;
    } | null;
  };
};

export class SessionTokenValidator {
  private static readonly CONFIG = {
    MAX_CONCURRENT_SESSIONS: 5,
    REFRESH_RATE_LIMIT_PER_MIN: 10,
    DEVICE_SIMILARITY_THRESHOLD: 0.75,
  };

  private static initialized = false;

  static async validate(
    request: NextRequest,
    context: MiddlewareContext
  ): Promise<NextResponse> {
    if (!SessionTokenValidator.initialized) {
      console.log("[SESSION VALIDATOR] Shield Activated — JWT Aligned");
      SessionTokenValidator.initialized = true;
    }

    const ipInfo = ClientIPDetector.getClientIP(request);
    const startTime = Date.now();

    try {
      const result = await SessionTokenValidator.validateSession(
        request,
        context,
        ipInfo
      );

      // Audit significant events
      if (!result.isValid || result.action === "refresh") {
        await SessionTokenValidator.auditEvent(
          request,
          result,
          ipInfo,
          Date.now() - startTime
        );
      }

      switch (result.action) {
        case "logout":
          return await SessionTokenValidator.secureLogout(
            request,
            result,
            ipInfo
          );
        case "refresh":
          if (
            result.user &&
            (await SessionTokenValidator.isRefreshRateLimited(result.user.id))
          ) {
            return SessionTokenValidator.rateLimitedResponse(request);
          }
          return await SessionTokenValidator.silentRefresh(
            request,
            result,
            ipInfo
          );
        case "redirect_login":
          return SessionTokenValidator.redirectToLogin(request);
        default:
          return SessionTokenValidator.attachUserContext(request, result);
      }
    } catch (error) {
      console.error("[SESSION VALIDATOR] Critical failure:", error);
      await SessionTokenValidator.auditError(request, error, ipInfo);
      return SessionTokenValidator.secureLogout(
        request,
        {
          isValid: false,
          needsRefresh: false,
          shouldLogout: true,
          action: "logout",
          errorCode: "SYSTEM_ERROR",
          securityLevel: "high",
        },
        ipInfo
      );
    }
  }

  private static async validateSession(
    request: NextRequest,
    context: MiddlewareContext,
    ipInfo: any
  ): Promise<SessionValidationResult> {
    const sessionToken = request.cookies.get("session-token")?.value;
    const refreshToken = request.cookies.get("refresh-token")?.value;
    const authHeader = request.headers.get("authorization");

    // No credentials → public route or login redirect
    if (!sessionToken && !refreshToken && !authHeader) {
      return {
        isValid: false,
        needsRefresh: false,
        shouldLogout: false,
        action: context.isPrivatePath ? "redirect_login" : "continue",
        securityLevel: "low",
      };
    }

    // 1. Primary: Session Token (DB-backed)
    if (sessionToken) {
      const result = await SessionTokenValidator.validateDbSession(
        sessionToken,
        request,
        ipInfo
      );
      if (result.isValid) return result;
    }

    // 2. Refresh Token → triggers silent refresh
    if (refreshToken) {
      const result = await SessionTokenValidator.validateRefreshJwt(
        refreshToken
      );
      if (result.isValid && result.user) {
        return { ...result, action: "refresh" };
      }
    }

    // 3. Bearer Token (API auth)
    if (authHeader?.startsWith("Bearer ")) {
      const token = authHeader.slice(7);
      const result = await SessionTokenValidator.validateAuthJwt(token);
      if (result.isValid && result.user) {
        return { ...result, action: "continue" };
      }
    }

    // All failed
    return {
      isValid: false,
      needsRefresh: false,
      shouldLogout: true,
      action: "logout",
      errorCode: "TOKEN_INVALID",
      securityLevel: "high",
    };
  }

  // ─────────────────────────────────────────────────────────────────────
  // 1. DB Session Validation (Primary)
  // ─────────────────────────────────────────────────────────────────────
  private static async validateDbSession(
    token: string,
    request: NextRequest,
    ipInfo: any
  ): Promise<SessionValidationResult> {
    const session = await prisma.session.findUnique({
      where: { sessionToken: token },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            role: true,
            isActive: true,
            student: { 
              select: { 
                matricNumber: true, 
                department: true 
              } 
            },
            teacher: { 
              select: { 
                employeeId: true, // Changed from teacherId to employeeId
                department: true 
              } 
            },
          },
        },
      },
    });

    if (!session?.user || !session.user.isActive) {
      if (session)
        await SessionTokenValidator.cleanupSession(session.id, "INVALID_USER");
      return SessionTokenValidator.invalid("USER_INACTIVE");
    }

    // Cast to proper type
    const typedSession = session as SessionWithUser;

    if (typedSession.expires < new Date()) {
      await SessionTokenValidator.cleanupSession(typedSession.id, "SESSION_EXPIRED");
      return SessionTokenValidator.invalid("TOKEN_EXPIRED");
    }

    // Device fingerprint check
    const fpCheck = SessionTokenValidator.checkFingerprint(
      typedSession.deviceFingerprint,
      request
    );
    if (!fpCheck.valid) {
      await SessionTokenValidator.flagSuspicious(
        typedSession.userId,
        "DEVICE_MISMATCH",
        request,
        ipInfo
      );
      return SessionTokenValidator.invalid("DEVICE_MISMATCH");
    }

    const needsRefresh = typedSession.expires.getTime() - Date.now() < 2 * 3600000; // < 2h

    return {
      isValid: true,
      needsRefresh,
      shouldLogout: false,
      user: SessionTokenValidator.mapUser(typedSession.user),
      action: needsRefresh ? "refresh" : "continue",
      securityLevel: fpCheck.level,
    };
  }

  // ─────────────────────────────────────────────────────────────────────
  // 2. Refresh Token Validation (JWTUtils aligned)
  // ─────────────────────────────────────────────────────────────────────
  private static async validateRefreshJwt(
    token: string
  ): Promise<SessionValidationResult> {
    try {
      const payload = await JWTUtils.verifyToken(token);

      if (payload.type !== "refresh" || !payload.userId) {
        return SessionTokenValidator.invalid("TOKEN_INVALID");
      }

      const user = await prisma.user.findUnique({
        where: { id: payload.userId as string },
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          isActive: true,
          student: { 
            select: { 
              matricNumber: true, 
              department: true 
            } 
          },
          teacher: { 
            select: { 
              employeeId: true, // Changed from teacherId to employeeId
              department: true 
            } 
          },
        },
      });

      if (!user || !user.isActive)
        return SessionTokenValidator.invalid("USER_INACTIVE");

      return {
        isValid: true,
        needsRefresh: true,
        shouldLogout: false,
        user: SessionTokenValidator.mapUser(user),
        action: "refresh",
        securityLevel: "medium",
      };
    } catch (error: any) {
      const code = error.code || "TOKEN_INVALID";
      return SessionTokenValidator.invalid(code as any);
    }
  }

  // ─────────────────────────────────────────────────────────────────────
  // 3. Auth Bearer Token Validation (JWTUtils aligned)
  // ─────────────────────────────────────────────────────────────────────
  private static async validateAuthJwt(
    token: string
  ): Promise<SessionValidationResult> {
    try {
      const payload = await JWTUtils.verifyAuthToken(token);

      const user = await prisma.user.findUnique({
        where: { id: payload.userId },
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          isActive: true,
          student: { 
            select: { 
              matricNumber: true, 
              department: true 
            } 
          },
          teacher: { 
            select: { 
              employeeId: true, // Changed from teacherId to employeeId
              department: true 
            } 
          },
        },
      });

      if (!user || !user.isActive)
        return SessionTokenValidator.invalid("USER_INACTIVE");

      return {
        isValid: true,
        needsRefresh: false,
        shouldLogout: false,
        user: SessionTokenValidator.mapUser(user),
        action: "continue",
        securityLevel: "high",
      };
    } catch (error: any) {
      return {
        isValid: false,
        needsRefresh: false,
        shouldLogout: false,
        action: "continue",
        securityLevel: "low",
      };
    }
  }

  // ─────────────────────────────────────────────────────────────────────
  // Silent Refresh — 100% aligned with JWTUtils
  // ─────────────────────────────────────────────────────────────────────
  private static async silentRefresh(
    request: NextRequest,
    result: SessionValidationResult,
    ipInfo: any
  ): Promise<NextResponse> {
    const user = result.user!;
    const oldToken = request.cookies.get("session-token")?.value;

    // Enforce max concurrent sessions
    await SessionTokenValidator.enforceConcurrentLimit(user.id);

    // Generate new tokens using your JWTUtils
    const [newSessionToken, newRefreshToken, newAuthToken] = await Promise.all([
      nanoid(32),
      JWTUtils.generateRefreshToken(user.id),
      JWTUtils.generateAuthToken({
        userId: user.id,
        email: user.email,
        schoolId: user.id,
        role: user.role,
        schoolNumber: user.matricNumber || user.employeeId || "",
      }),
    ]);

    const expires = new Date(Date.now() + 8 * 3600000); // 8h

    await prisma.session.create({
      data: {
        sessionToken: newSessionToken,
        userId: user.id,
        expires,
        deviceFingerprint: SessionTokenValidator.generateFingerprint(request),
        ipAddress: ipInfo.ip,
        userAgent: request.headers.get("user-agent") || "unknown",
      },
    });

    if (oldToken) {
      await prisma.session.deleteMany({ where: { sessionToken: oldToken } });
    }

    const response = NextResponse.next();
    response.cookies.set("session-token", newSessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      expires,
    });
    response.cookies.set("refresh-token", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      expires: new Date(Date.now() + 7 * 24 * 3600000),
    });
    response.cookies.set("userId", user.id, { path: "/", expires });

    SessionTokenValidator.attachHeaders(response, user, true);
    return response;
  }

  // ─────────────────────────────────────────────────────────────────────
  // Secure Logout (aligned with signout route)
  // ─────────────────────────────────────────────────────────────────────
  private static async secureLogout(
    request: NextRequest,
    result: SessionValidationResult,
    ipInfo: any
  ): Promise<NextResponse> {
    const token = request.cookies.get("session-token")?.value;
    if (token) {
      const session = await prisma.session.findUnique({
        where: { sessionToken: token },
      });
      if (session) {
        await prisma.auditLog.create({
          data: {
            userId: session.userId,
            action: AuditAction.SESSION_TERMINATED,
            details: { reason: result.errorCode, source: "validator" },
            ipAddress: ipInfo.ip,
            userAgent: request.headers.get("user-agent") || "unknown",
          },
        });
        await prisma.session.delete({ where: { id: session.id } });
      }
    }

    const url = new URL("/signin", request.url);
    url.searchParams.set(
      "reason",
      result.errorCode?.toLowerCase() || "expired"
    );

    const response = NextResponse.redirect(url);
    ["session-token", "refresh-token", "userId"].forEach((name) =>
      response.cookies.delete(name)
    );
    response.headers.set("clear-site-data", '"cookies","storage"');
    response.headers.set("x-logout-reason", result.errorCode || "unknown");

    return response;
  }

  // ─────────────────────────────────────────────────────────────────────
  // Helpers
  // ─────────────────────────────────────────────────────────────────────
  private static attachUserContext(
    request: NextRequest,
    result: SessionValidationResult
  ): NextResponse {
    const response = NextResponse.next();
    if (result.user)
      SessionTokenValidator.attachHeaders(response, result.user, false);
    return response;
  }

  private static attachHeaders(
    response: NextResponse,
    user: SessionUser,
    refreshed: boolean
  ) {
    response.headers.set("x-user-id", user.id);
    response.headers.set("x-user-role", user.role);
    response.headers.set("x-user-email", user.email);
    if (user.matricNumber)
      response.headers.set("x-user-matric", user.matricNumber);
    if (user.employeeId) // Changed from teacherId to employeeId
      response.headers.set("x-user-employee-id", user.employeeId);
    if (user.department)
      response.headers.set("x-user-department", user.department);
    response.headers.set("x-authenticated", "true");
    if (refreshed) response.headers.set("x-session-refreshed", "true");
  }

  private static generateFingerprint(request: NextRequest): string {
    const parts = [
      request.headers.get("user-agent") || "",
      request.headers.get("accept-language") || "",
      ClientIPDetector.getClientIP(request).ip,
    ];
    return require("crypto")
      .createHash("sha256")
      .update(parts.join("|"))
      .digest("hex")
      .slice(0, 32);
  }

  private static checkFingerprint(stored: string | null, request: NextRequest) {
    if (!stored) return { valid: true, level: "medium" as const };
    const current = SessionTokenValidator.generateFingerprint(request);
    const similarity =
      [...stored].filter((c, i) => c === current[i]).length / stored.length;
    return {
      valid:
        similarity >= SessionTokenValidator.CONFIG.DEVICE_SIMILARITY_THRESHOLD,
      level: similarity >= 0.9 ? ("high" as const) : ("medium" as const),
    };
  }

  private static invalid(
    code: SessionValidationResult["errorCode"] = "TOKEN_INVALID"
  ): SessionValidationResult {
    return {
      isValid: false,
      needsRefresh: false,
      shouldLogout: true,
      action: "logout",
      errorCode: code,
      securityLevel: "high",
    };
  }

  private static mapUser(user: any): SessionUser {
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      matricNumber: user.student?.matricNumber || null,
      employeeId: user.teacher?.employeeId || null, // Changed from teacherId to employeeId
      department: user.student?.department || user.teacher?.department || null,
    };
  }

  private static async enforceConcurrentLimit(userId: string) {
    const count = await prisma.session.count({
      where: { userId, expires: { gt: new Date() } },
    });
    if (count >= SessionTokenValidator.CONFIG.MAX_CONCURRENT_SESSIONS) {
      const sessionsToDelete = await prisma.session.findMany({
        where: { userId, expires: { gt: new Date() } },
        orderBy: { createdAt: "asc" },
        take: count - SessionTokenValidator.CONFIG.MAX_CONCURRENT_SESSIONS + 1,
        select: { id: true },
      });
      const ids = sessionsToDelete.map((s) => s.id);
      if (ids.length > 0) {
        await prisma.session.deleteMany({
          where: { id: { in: ids } },
        });
      }
    }
  }

  private static async isRefreshRateLimited(userId: string): Promise<boolean> {
    const minuteAgo = new Date(Date.now() - 60000);
    const count = await prisma.auditLog.count({
      where: {
        userId,
        action: AuditAction.SESSION_REFRESHED,
        createdAt: { gte: minuteAgo },
      },
    });
    return count >= SessionTokenValidator.CONFIG.REFRESH_RATE_LIMIT_PER_MIN;
  }

  private static rateLimitedResponse(request: NextRequest): NextResponse {
    return NextResponse.json(
      { error: "Too many refresh attempts" },
      { status: 429 }
    );
  }

  private static redirectToLogin(request: NextRequest): NextResponse {
    const url = new URL("/signin", request.url);
    if (!request.nextUrl.pathname.startsWith("/signin")) {
      url.searchParams.set(
        "redirect",
        request.nextUrl.pathname + request.nextUrl.search
      );
    }
    return NextResponse.redirect(url);
  }

// src/lib/middleware/sessionTokenValidator.ts

// ... (all your existing code remains the same until line ~650)

  // Auditing - FIX THIS METHOD
  private static async auditEvent(
    request: NextRequest,
    result: SessionValidationResult,
    ipInfo: any,
    duration: number
  ) {
    if (!result.isValid || result.action === "refresh") {
      // Use proper enum values
      let action: AuditAction;
      
      if (result.action === "refresh") {
        action = AuditAction.SESSION_REFRESHED;
      } else if (result.isValid) {
        action = AuditAction.SESSION_INVALIDATED;
      } else {
        action = AuditAction.SESSION_TERMINATED;
      }

      await prisma.auditLog.create({
        data: {
          userId: result.user?.id || null,
          action, // This is now the enum value
          details: {
            path: request.nextUrl.pathname,
            error: result.errorCode,
            duration_ms: duration,
          },
          ipAddress: ipInfo.ip,
          userAgent: request.headers.get("user-agent") || "unknown",
        },
      });
    }
  }

  // FIX THIS METHOD - Use the enum value instead of string with type assertion
  private static async auditError(
    request: NextRequest,
    error: any,
    ipInfo: any
  ) {
    await prisma.auditLog.create({
      data: {
        userId: null,
        action: AuditAction.SESSION_VALIDATOR_ERROR, // Use the enum value directly
        details: {
          error: error.message || "unknown",
          path: request.nextUrl.pathname,
        },
        ipAddress: ipInfo.ip,
        userAgent: request.headers.get("user-agent") || "unknown",
      },
    });
  }

  private static async flagSuspicious(
    userId: string,
    reason: string,
    request: NextRequest,
    ipInfo: any
  ) {
    await prisma.auditLog.create({
      data: {
        userId,
        action: AuditAction.SUSPICIOUS_ACTIVITY_DETECTED,
        details: { reason, path: request.nextUrl.pathname },
        ipAddress: ipInfo.ip,
        userAgent: request.headers.get("user-agent") || "unknown",
      },
    });
  }

  private static async cleanupSession(sessionId: string, reason: string) {
    await prisma.session.delete({ where: { id: sessionId } });
  }
}