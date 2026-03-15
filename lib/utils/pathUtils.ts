// src/lib/utils/pathsUtils.ts

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC PATHS — No auth required
// ─────────────────────────────────────────────────────────────────────────────
export const PUBLIC_PATHS = [
  "/",
  "/sitemap",
  "/about",
  "/contact",
  "/school",
  "/help",
  "/faq",
  "/terms",
  "/privacy",
  "/support",
  "/news",
  "/blog",
  "/events",
  "/gallery",
  "/public",
  "/sr", // Role selection page
  "/check", // Check page
  "/security/blocked", // Security blocked page
] as const;

// ─────────────────────────────────────────────────────────────────────────────
// AUTH PATHS — Login, signup, password reset, etc.
// ─────────────────────────────────────────────────────────────────────────────
export const AUTH_PATHS = [
  "/signin",
  "/signup",
  "/forgot-password",
  "/reset-password",
  "/verify-email",
  "/resend-verification",
  "/auth/callback",
  "/p/s/signup", // Student signup
  "/p/t/signup", // Teacher signup
] as const;

// ─────────────────────────────────────────────────────────────────────────────
// PRIVATE PATHS — Require authentication
// ─────────────────────────────────────────────────────────────────────────────
export const PRIVATE_PATHS = [
  "/dashboard",
  "/profile",
  "/courses",
  "/grades",
  "/assignments",
  "/schedule",
  "/admin",
  "/settings",
  "/notifications",
  "/messages",
  
  // Admin portal routes
  "/p/a",
  "/p/a/*",
  "/p/a/dashboard",
  "/p/a/users",
  "/p/a/users/*",
  "/p/a/audits",
  "/p/a/audits/*",
  "/p/a/reports",
  "/p/a/reports/*",
  "/p/a/settings",
  
  // Student portal routes
  "/p/s",
  "/p/s/*",
  "/p/s/dashboard",
  "/p/s/assignments",
  "/p/s/assignments/*",
  "/p/s/courses",
  "/p/s/courses/*",
  "/p/s/grades",
  "/p/s/profile",
  "/p/s/schedule",
  "/p/s/schedule/*",
  
  // Teacher portal routes
  "/p/t",
  "/p/t/*",
  "/p/t/dashboard",
  "/p/t/assignments",
  "/p/t/assignments/*",
  "/p/t/attendance",
  "/p/t/attendance/*",
  "/p/t/classes",
  "/p/t/classes/*",
  "/p/t/courses",
  "/p/t/courses/*",
  "/p/t/grades",
  "/p/t/grades/*",
  "/p/t/profile",
  "/p/t/schedule",
  "/p/t/schedule/*",
] as const;

// ─────────────────────────────────────────────────────────────────────────────
// CACHEABLE PATHS — Safe to cache (GET-only, stable data)
// ─────────────────────────────────────────────────────────────────────────────
export const CACHEABLE_PATHS = [
  // Public pages
  "/",
  "/about",
  "/contact",
  "/school",
  "/help",
  "/faq",
  "/terms",
  "/privacy",
  "/support",
  "/news",
  "/blog",
  "/events",
  "/gallery",
  "/sr",
  "/check",
  "/security/blocked",

  // Wildcard public sections
  "/school/*",
  "/help/*",
  "/news/*",
  "/blog/*",
  "/events/*",
  "/gallery/*",

  // Auth pages (static forms)
  "/signin",
  "/signup",
  "/forgot-password",
  "/reset-password",
  "/verify-email",
  "/p/s/signup",
  "/p/t/signup",

  // Static assets
  "/_next/*",
  "/static/*",
  "/assets/*",
  "/images/*",
  "/uploads/public/*",
  "/media/*",
  "/favicon.ico",
  "/robots.txt",
  "/sitemap.xml",
  "/manifest.json",

  // Public API routes (stable data)
  "/api/public/*",
  "/api/auth/health",
  "/api/auth/status",
  "/api/courses/public",
  "/api/courses/list",
  "/api/courses/details/*",
  "/api/school/info",
  "/api/school/faculties",
  "/api/school/departments",
  "/api/events/public",
  "/api/news/public",
  "/api/static/*",

  // Grade summary (short cache)
  "/api/grades/summary",
  "/api/grades/performance",
  "/api/grades/recent",

  // User public profile
  "/api/user/profile/public/*",
  
  // Portal API routes (GET requests only)
  "/api/s/courses/*",
  "/api/s/assignments/*",
  "/api/s/grades/*",
  "/api/s/schedule/*",
  "/api/t/courses/*",
  "/api/t/assignments/*",
  "/api/t/students/*",
  "/api/t/classes/*",
  "/api/a/users/*",
  "/api/a/audits/*",
  "/api/a/reports/*",
] as const;

// ─────────────────────────────────────────────────────────────────────────────
// NON-CACHEABLE PATHS — Dynamic, user-specific, or mutating
// ─────────────────────────────────────────────────────────────────────────────
export const NON_CACHEABLE_PATHS = [
  // Auth endpoints
  "/api/auth/*",

  // User-specific
  "/api/user/me",
  "/api/user/profile",
  "/api/user/settings",
  "/api/user/greeting",

  // Grades (sensitive/full)
  "/api/grades/raw",
  "/api/grades/export",

  // Assignments
  "/api/assignments/submit",
  "/api/assignments/submissions/*",
  "/api/assignments/grade",
  "/api/s/assignment/submit",
  "/api/t/assignments/grade/*",

  // Admin & sensitive operations
  "/api/admin/*",
  "/api/a/*/create",
  "/api/a/*/update",
  "/api/a/*/delete",

  // Student operations
  "/api/s/*/create",
  "/api/s/*/update",
  "/api/s/*/delete",
  "/api/s/assignment/*/submit",
  "/api/s/profile/update",

  // Teacher operations
  "/api/t/*/create",
  "/api/t/*/update",
  "/api/t/*/delete",
  "/api/t/attendance/mark",
  "/api/t/attendance/*",
  "/api/t/results/upload",
  "/api/t/results/*",

  // Payments & transactions
  "/api/payments/*",
  "/api/transactions/*",

  // Real-time / dynamic
  "/api/notifications",
  "/api/messages",
  "/api/chat/*",

  // Form submissions
  "/api/contact",
  "/api/forms/*",

  // Any mutation endpoints
  "/api/*/create",
  "/api/*/update",
  "/api/*/delete",
  "/api/*/submit",
  "/api/*/upload",
] as const;

// ─────────────────────────────────────────────────────────────────────────────
// TYPE EXPORTS
// ─────────────────────────────────────────────────────────────────────────────
export type PublicPath = (typeof PUBLIC_PATHS)[number];
export type AuthPath = (typeof AUTH_PATHS)[number];
export type PrivatePath = (typeof PRIVATE_PATHS)[number];
export type CacheablePath = (typeof CACHEABLE_PATHS)[number];
export type NonCacheablePath = (typeof NON_CACHEABLE_PATHS)[number];

// ─────────────────────────────────────────────────────────────────────────────
// IMPROVED PATH MATCHER (supports /* wildcards correctly)
// ─────────────────────────────────────────────────────────────────────────────
export function matchPath(
  targetPath: string,
  patterns: readonly string[]
): boolean {
  return patterns.some((pattern) => {
    if (pattern === targetPath) return true;

    if (pattern.endsWith("/*")) {
      const base = pattern.slice(0, -2);
      return targetPath === base || targetPath.startsWith(base + "/");
    }

    if (pattern.includes("*")) {
      const regex = new RegExp(
        "^" + pattern.replace(/\*/g, "[^/]*").replace(/\//g, "\\/") + "$"
      );
      return regex.test(targetPath);
    }

    return false;
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// TYPE GUARDS
// ─────────────────────────────────────────────────────────────────────────────
export const isPublicPath = (path: string): path is PublicPath =>
  matchPath(path, PUBLIC_PATHS);

export const isAuthPath = (path: string): path is AuthPath =>
  matchPath(path, AUTH_PATHS);

export const isPrivatePath = (path: string): path is PrivatePath =>
  matchPath(path, PRIVATE_PATHS);

export const isCacheablePath = (path: string): path is CacheablePath =>
  matchPath(path, CACHEABLE_PATHS);

export const isNonCacheablePath = (path: string): path is NonCacheablePath =>
  matchPath(path, NON_CACHEABLE_PATHS);

// ─────────────────────────────────────────────────────────────────────────────
// AUTH & ACCESS HELPERS
// ─────────────────────────────────────────────────────────────────────────────
export const requiresAuth = (path: string): boolean =>
  isPrivatePath(path) && !isAuthPath(path);

export const isAccessibleWithoutAuth = (path: string): boolean =>
  isPublicPath(path) || isAuthPath(path);

// ─────────────────────────────────────────────────────────────────────────────
// CACHE DURATION (ms)
// ─────────────────────────────────────────────────────────────────────────────
export const getCacheDuration = (path: string): number => {
  if (matchPath(path, ["/api/grades/summary", "/api/courses/details/*", "/api/s/grades/summary"])) {
    return 5 * 60 * 1000; // 5 min
  }
  if (
    matchPath(path, ["/api/grades/performance", "/api/assignments/course/*", "/api/t/classes/*"])
  ) {
    return 2 * 60 * 1000; // 2 min
  }
  if (path === "/api/grades/recent" || path === "/api/s/grades/recent") {
    return 60 * 1000; // 1 min
  }
  if (path.startsWith("/api/courses/") || path.startsWith("/api/school/") || 
      path.startsWith("/api/s/courses/") || path.startsWith("/api/t/courses/")) {
    return 10 * 60 * 1000; // 10 min
  }
  if (isCacheablePath(path)) {
    return path.startsWith("/api/") ? 5 * 60 * 1000 : 30 * 60 * 1000;
  }
  return 0;
};

// ─────────────────────────────────────────────────────────────────────────────
// CACHE KEY GENERATOR
// ─────────────────────────────────────────────────────────────────────────────
export const generateCacheKey = (path: string, userId?: string): string => {
  if (userId && (path.startsWith("/api/grades/") || path.startsWith("/api/s/grades/") || path.startsWith("/api/t/grades/"))) {
    return `cache:${path}:user:${userId}`;
  }
  if (path.includes("/api/courses/details/") || path.includes("/api/s/courses/")) {
    const courseId = path.split("/").pop();
    return `cache:${path}:course:${courseId}`;
  }
  if (path.includes("/api/t/classes/")) {
    const classId = path.split("/").pop();
    return `cache:${path}:class:${classId}`;
  }
  return `cache:${path}`;
};

// ─────────────────────────────────────────────────────────────────────────────
// CACHE INVALIDATION PATTERNS
// ─────────────────────────────────────────────────────────────────────────────
export const CACHE_INVALIDATION_PATTERNS = {
  GRADES_UPDATED: ["/api/grades/*", "/api/s/grades/*", "/api/t/grades/*", "/api/t/results/*"],
  ASSIGNMENTS_UPDATED: ["/api/assignments/*", "/api/s/assignment/*", "/api/t/assignments/*", "/api/grades/*"],
  COURSES_UPDATED: ["/api/courses/*", "/api/s/courses/*", "/api/t/courses/*"],
  USER_PROFILE_UPDATED: ["/api/user/profile/public/*", "/api/s/profile/*", "/api/t/profile/*"],
  NEWS_EVENTS_UPDATED: ["/api/news/*", "/api/events/*"],
  ATTENDANCE_UPDATED: ["/api/t/attendance/*", "/api/attendance/*"],
} as const;

export const shouldInvalidateCache = (
  path: string,
  operation: keyof typeof CACHE_INVALIDATION_PATTERNS
): boolean => matchPath(path, CACHE_INVALIDATION_PATTERNS[operation]);

// ─────────────────────────────────────────────────────────────────────────────
// PATH TYPE DETECTION
// ─────────────────────────────────────────────────────────────────────────────
export const getPathType = (
  path: string
): "public" | "private" | "auth" | "unknown" => {
  if (isPublicPath(path)) return "public";
  if (isPrivatePath(path)) return "private";
  if (isAuthPath(path)) return "auth";
  return "unknown";
};

// ─────────────────────────────────────────────────────────────────────────────
// ROLE-SPECIFIC PATH HELPERS
// ─────────────────────────────────────────────────────────────────────────────
export const isAdminPath = (path: string): boolean => 
  path.startsWith("/p/a") || path.startsWith("/api/a/");

export const isStudentPath = (path: string): boolean => 
  path.startsWith("/p/s") || path.startsWith("/api/s/");

export const isTeacherPath = (path: string): boolean => 
  path.startsWith("/p/t") || path.startsWith("/api/t/");

export const getRequiredRole = (path: string): "ADMIN" | "TEACHER" | "STUDENT" | null => {
  if (isAdminPath(path)) return "ADMIN";
  if (isTeacherPath(path)) return "TEACHER";
  if (isStudentPath(path)) return "STUDENT";
  return null;
};