// src/lib/middleware/orchestrator.ts
import { NextRequest, NextResponse } from "next/server";
import { performance } from "perf_hooks";

// Core
import { ContextBuilder } from "./contextBuilder";
import { AuthenticatedActionHandler } from "./authenticatedActionHandler";

// Defense Layers
import { SecurityGuard } from "./securityGuard";
import { EnhancedRateEnforcer } from "./enhancedRateEnforcer";
import { EncryptionEnforcer } from "./encryptionEnforcer";
import { SessionTokenValidator } from "./sessionTokenValidator";
import { GeoGuard } from "./geoGuard";
import { TrustedSourceManager } from "./trustedSourceManager";
import { BehaviorAnalyst } from "./behaviorAnalyst";
import { ComplianceMonitor } from "./complianceMonitor";
import { RequestTransformer } from "./requestTransformer";
import { CacheManager } from "./cacheManager";
import { ActivityLogger } from "./activityLogger";

// Utilities
import { ResponseMerger } from "./responseMerger";
import { Defense } from "./UnifiedThreatDefenseSystem";
import { ComprehensiveHealthMonitor } from "./healthMonitor";

// NEW: The bulletproof executor
import { enhancedExecute } from "./executionWrapper";

// IP Detection — THE SOURCE OF TRUTH
import { ClientIPDetector } from "@/lib/clientIp";

// NEW: Bot Protection
import { BotProtection } from "./botProtection";

// Types
import type { MiddlewareContext } from "./types";
import type { AuthenticatedActionContext } from "./authenticatedActionHandler";

interface LayerResult {
  name: string;
  result: NextResponse;
  logs: string[];
  executionTime: number;
  status: number;
  success: boolean;
  earlyExit?: boolean;
  threatScore?: number;
  decision?: string;
  skipped?: boolean;
}

export class orchestrator {
  // ===========================================================
  // TEMPORARY DISABLE FLAGS - Set to true to disable specific layers
  // ===========================================================
  private static readonly DISABLED_LAYERS = {
    // Foundation Layers
    SecurityGuard: false,
    EnhancedRateEnforcer: false,
    EncryptionEnforcer: false,
    SessionTokenValidator: false,
    
    // Defense Layers
    UnifiedThreatDefense: false,
    
    // Secondary Layers
    GeoGuard: false,
    CacheManager: false,
    BehaviorAnalyst: false,
    ComplianceMonitor: false,
    RequestTransformer: false,
    
    // Observability
    ActivityLogger: false,
  };

  // ===========================================================
  // ENVIRONMENT-BASED DISABLE - Disable layers in specific environments
  // ===========================================================
  private static shouldDisableLayer(layerName: string): boolean {
    if (this.DISABLED_LAYERS[layerName as keyof typeof this.DISABLED_LAYERS]) {
      return true;
    }

    if (process.env.NODE_ENV === 'development') {
      const devDisabledLayers = [
        'EnhancedRateEnforcer',
        'GeoGuard',
      ];
      
      if (devDisabledLayers.includes(layerName)) {
        console.log(`[orchestrator] 🚧 Layer ${layerName} disabled in development`);
        return true;
      }
    }

    if (process.env.DISABLE_SECURITY === 'true') {
      const securityLayers = ['SecurityGuard', 'EncryptionEnforcer', 'SessionTokenValidator'];
      if (securityLayers.includes(layerName)) {
        return true;
      }
    }

    return false;
  }

  private static readonly LAYERS = {
    FOUNDATION: [
      { name: "SecurityGuard", fn: SecurityGuard.apply, critical: true },
      {
        name: "EnhancedRateEnforcer",
        fn: EnhancedRateEnforcer.enforce,
        critical: true,
      },
      {
        name: "EncryptionEnforcer",
        fn: EncryptionEnforcer.enforce,
        critical: true,
      },
      {
        name: "SessionTokenValidator",
        fn: SessionTokenValidator.validate,
        critical: false,
      },
    ],
    DEFENSE: [
      { name: "UnifiedThreatDefense", fn: Defense.defend, critical: true },
    ],
    SECONDARY: [
      { name: "GeoGuard", fn: GeoGuard.guard },
      { name: "CacheManager", fn: CacheManager.manage },
      { name: "BehaviorAnalyst", fn: BehaviorAnalyst.analyze },
      { name: "ComplianceMonitor", fn: ComplianceMonitor.monitor },
      { name: "RequestTransformer", fn: RequestTransformer.transform },
    ],
    OBSERVABILITY: [
      { name: "ActivityLogger", fn: ActivityLogger.log, async: true },
    ],
  };

  static async execute(request: NextRequest): Promise<NextResponse> {
    const globalStart = performance.now();
    let context: MiddlewareContext = {} as any;
    let authContext: AuthenticatedActionContext = {} as any;
    const results: LayerResult[] = [];

    // ===========================================================
    // PHASE 0: BOT PROTECTION - Run first
    // ===========================================================
    const botInfo = BotProtection.inspect(request);
    
    // Add bot score to headers for downstream use
    request.headers.set('x-bot-score', botInfo.score.toString());
    request.headers.set('x-bot-reason', botInfo.reason.join(', '));
    
    // Calculate abuse header score
    const abuseScores = BotProtection.getAbuseHeaderScore(request);
    const totalAbuseScore = Math.round(
      Object.values(abuseScores).reduce((a, b) => a + b, 0) / 
      Object.keys(abuseScores).length
    );
    request.headers.set('x-abuse-score', totalAbuseScore.toString());

    // Check for existing challenge verification
    const challengePassed = request.cookies.get('bot-challenge-passed')?.value === 'true';
    const verifiedParam = request.nextUrl.searchParams.get('verified');
    
    // If coming back from challenge with verification
    if (verifiedParam === 'true' && !challengePassed) {
      const response = NextResponse.redirect(new URL(request.nextUrl.pathname, request.url));
      response.cookies.set('bot-challenge-passed', 'true', {
        maxAge: 3600,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
      });
      return response;
    }

    // Enforce bot protection (skip if challenge already passed)
    const botDecision = BotProtection.enforce(botInfo.score, request, challengePassed);
    if (botDecision) {
      console.log(`[BotProtection] Blocked request with score ${botInfo.score}:`, botInfo.reason);
      return botDecision;
    }

    // ===========================================================
    // PATH-BASED BYPASS - Skip security for static assets
    // ===========================================================
    const bypassPaths = [
      '/_next',
      '/favicon.ico',
      '/sw.js',
      '/manifest.json',
      '/robots.txt',
      '/api/public',
      '/health',
      '/images',
      '/fonts',
      '/icons',
    ];

    if (bypassPaths.some(path => request.nextUrl.pathname.startsWith(path))) {
      console.log(`[orchestrator] 🚧 Bypassing security for path: ${request.nextUrl.pathname}`);
      const response = NextResponse.next();
      response.headers.set('x-bot-score', botInfo.score.toString());
      response.headers.set('x-abuse-score', totalAbuseScore.toString());
      return response;
    }

    // ===========================================================
    // TEMPORARY BYPASS - Use this to completely bypass all security
    // ===========================================================
    if (process.env.BYPASS_ALL_SECURITY === 'true') {
      console.warn('⚠️⚠️⚠️ ALL SECURITY LAYERS BYPASSED ⚠️⚠️⚠️');
      const response = NextResponse.next();
      response.headers.set('x-bot-score', botInfo.score.toString());
      response.headers.set('x-abuse-score', totalAbuseScore.toString());
      return response;
    }

    try {
      // Initialize trusted sources once
      TrustedSourceManager.initialize();

      // ──────────────────────────────
      // PHASE 1: Get Real Client IP (Critical Foundation)
      // ──────────────────────────────
      const ipInfo = ClientIPDetector.getClientIP(request);
      
      console.log(`[orchestrator] Request from IP: ${ipInfo.ip}, Source: ${ipInfo.source}, Confidence: ${ipInfo.confidence}`);

      // ──────────────────────────────
      // PHASE 2: Build Context (with real IP)
      // ──────────────────────────────
      const contextExec = await enhancedExecute(
        () => ContextBuilder.build(request),
        {
          fallback: {} as MiddlewareContext,
          name: "ContextBuilder",
          context: undefined,
        }
      );

      // Enrich context with accurate IP data
      context = contextExec.result;
      Object.assign(context, {
        clientIp: ipInfo.ip,
        clientIpSource: ipInfo.source,
        clientIpConfidence: Number(ipInfo.confidence),
        isProxy: ipInfo.isProxy || ipInfo.isVPN || ipInfo.isTor || ipInfo.isDatacenter,
        country: ipInfo.geo?.country || "XX",
        region: ipInfo.geo?.city || "XX",
        botScore: botInfo.score,
        abuseScore: totalAbuseScore,
        botReason: botInfo.reason,
      });

      authContext = AuthenticatedActionHandler.enhanceContext(request, context);

      results.push({
        name: "ContextBuilder",
        result: NextResponse.next(),
        logs: [
          `IP: ${ipInfo.ip} (${ipInfo.source})`,
          `Bot Score: ${botInfo.score}`,
          `Abuse Score: ${totalAbuseScore}`,
          `Action: ${authContext.actionType}`,
          `Sensitivity: ${authContext.sensitivity}`,
        ],
        executionTime: 0,
        status: 200,
        success: true,
      });

      // ──────────────────────────────
      // PHASE 3: Foundation Security
      // ──────────────────────────────
      console.log("[orchestrator] Starting FOUNDATION layers...");
      let response = await orchestrator.executeLayer(
        request,
        authContext,
        orchestrator.LAYERS.FOUNDATION,
        results,
        "FOUNDATION"
      );

      if (orchestrator.shouldEarlyExit(response, results)) {
        console.log("[orchestrator] Early exit triggered in FOUNDATION phase");
        return orchestrator.finalize(request, response, results, globalStart, ipInfo.ip, botInfo.score, totalAbuseScore);
      }

      // ──────────────────────────────
      // PHASE 4: AI Defense (uses real IP)
      // ──────────────────────────────
      if (!this.shouldDisableLayer("UnifiedThreatDefense")) {
        console.log("[orchestrator] Starting DEFENSE layer...");
        const defenseExec = await enhancedExecute(
          () => Defense.defend(request, context),
          {
            fallback: NextResponse.next(),
            name: "UnifiedThreatDefense",
            context: authContext,
            request,
          }
        );

        const action = defenseExec.result.headers.get("x-action") || "ALLOW";
        const score = parseFloat(defenseExec.result.headers.get("x-threat-final") || "0");

        results.push({
          name: "UnifiedThreatDefense",
          result: defenseExec.result,
          logs: defenseExec.logs,
          executionTime: defenseExec.executionTime,
          status: defenseExec.result.status,
          success: action === "ALLOW",
          threatScore: score,
          decision: action,
          earlyExit: !["ALLOW", "RATE_LIMIT"].includes(action),
        });

        if (!["ALLOW", "RATE_LIMIT"].includes(action)) {
          console.log(`[DEFENSE] ${action} → ${ipInfo.ip} blocked (Score: ${score})`);
          return orchestrator.finalize(request, defenseExec.result, results, globalStart, ipInfo.ip, botInfo.score, totalAbuseScore);
        }

        response = defenseExec.result;
      } else {
        console.log("[orchestrator] 🚧 UnifiedThreatDefense layer disabled");
      }

      // ──────────────────────────────
      // PHASE 5: Secondary Layer
      // ──────────────────────────────
      console.log("[orchestrator] Starting SECONDARY layers...");
      response = await orchestrator.executeLayer(
        request,
        authContext,
        orchestrator.LAYERS.SECONDARY,
        results,
        "SECONDARY",
        response
      );

      // ──────────────────────────────
      // PHASE 6: Async Logging (with real IP)
      // ──────────────────────────────
      if (!this.shouldDisableLayer("ActivityLogger")) {
        enhancedExecute(() => ActivityLogger.log(request, authContext), {
          fallback: undefined,
          name: "ActivityLogger",
          context: authContext,
        }).catch(() => {});
      }

      console.log("[orchestrator] All layers completed successfully");
      return orchestrator.finalize(request, response, results, globalStart, ipInfo.ip, botInfo.score, totalAbuseScore);
    } catch (error) {
      console.error(`[orchestrator] CRASH after ${(performance.now() - globalStart).toFixed(1)}ms:`, error);
      const resp = NextResponse.json({ error: "System failure" }, { status: 503 });
      return orchestrator.finalize(request, resp, results, globalStart, "crash", 0, 0);
    }
  }

  // ─────────────────────────────────────────────────────────────────────
  private static async executeLayer(
    request: NextRequest,
    authContext: AuthenticatedActionContext,
    layers: any[],
    results: LayerResult[],
    phase: string,
    base: NextResponse = NextResponse.next()
  ): Promise<NextResponse> {
    let response = base;

    for (const layer of layers) {
      if (this.shouldDisableLayer(layer.name)) {
        console.log(`[orchestrator] 🚧 Layer ${layer.name} is disabled, skipping...`);
        results.push({
          name: layer.name,
          result: NextResponse.next(),
          logs: ["DISABLED"],
          executionTime: 0,
          status: 200,
          success: true,
          skipped: true,
        });
        continue;
      }

      console.log(`[orchestrator] Executing layer: ${layer.name}`);

      if (AuthenticatedActionHandler.shouldSkipMiddleware(layer.name, authContext)) {
        console.log(`[orchestrator] Layer ${layer.name} skipped`);
        results.push({
          name: layer.name,
          result: NextResponse.next(),
          logs: ["SKIPPED"],
          executionTime: 0,
          status: 200,
          success: true,
          skipped: true,
        });
        continue;
      }

      try {
        const exec = await enhancedExecute(() => layer.fn(request, authContext), {
          fallback: layer.critical
            ? NextResponse.json({ error: "Blocked by security" }, { status: 403 })
            : NextResponse.next(),
          name: layer.name,
          context: authContext,
          request,
        });

        if (!exec.success || exec.result.status === 403) {
          console.error(`🔥 BLOCKED BY ${layer.name}:`, {
            path: request.nextUrl.pathname,
            status: exec.result.status,
            headers: Object.fromEntries(exec.result.headers.entries())
          });
        }

        console.log(`[orchestrator] Layer ${layer.name} completed:`, {
          success: exec.success,
          status: exec.result.status,
          hasLogs: exec.logs.length > 0,
          threatScore: exec.threatScore
        });

        results.push({
          name: layer.name,
          result: exec.result,
          logs: exec.logs,
          executionTime: exec.executionTime,
          status: exec.result.status,
          success: exec.success,
          earlyExit: layer.critical && !exec.success,
          threatScore: exec.threatScore,
        });

        if (layer.critical && !exec.success) {
          console.log(`[orchestrator] Critical layer ${layer.name} failed, returning error response`);
          return exec.result;
        }

        response = ResponseMerger.merge(response, exec.result);
      } catch (layerError) {
        console.error(`[orchestrator] Error in layer ${layer.name}:`, layerError);
        
        if (layer.critical) {
          const errorResponse = NextResponse.json(
            { error: "Blocked by security" },
            { status: 403 }
          );
          return errorResponse;
        }
      }
    }

    return response;
  }

  private static shouldEarlyExit(response: NextResponse, results: LayerResult[]): boolean {
    return response.status >= 400 || response.redirected || results.some((r) => r.earlyExit);
  }

  private static finalize(
    request: NextRequest,
    response: NextResponse,
    results: LayerResult[],
    start: number,
    clientIp: string,
    botScore: number,
    abuseScore: number
  ): NextResponse {
    const total = performance.now() - start;

    response = ResponseMerger.addSystemHeaders(response, {
      startTime: start,
      requestId: results[0]?.result.headers.get("x-request-id") || "unknown",
      processingTime: total,
      clientIp,
      chain: results.map((r) => r.name),
    });

    // Add security headers
    const defense = results.find((r) => r.name === "UnifiedThreatDefense");
    if (defense) {
      response.headers.set("X-Threat-Final", defense.threatScore?.toFixed(1) || "0");
      response.headers.set("X-Defense-Action", defense.decision || "ALLOW");
    }
    
    // Add bot protection headers
    response.headers.set("X-Bot-Score", botScore.toString());
    response.headers.set("X-Abuse-Score", abuseScore.toString());
    
    // Add IP reputation header (simplified)
    const ipReputation = botScore > 70 ? "POOR" : botScore > 40 ? "FAIR" : "GOOD";
    response.headers.set("X-IP-Reputation", ipReputation);

    ComprehensiveHealthMonitor.recordRequest(total, response.status);
    orchestrator.printSummary(results, total, clientIp, botScore, abuseScore);

    return response;
  }

  private static printSummary(
    results: LayerResult[], 
    total: number, 
    ip: string, 
    botScore?: number,
    abuseScore?: number
  ) {
    if (process.env.NODE_ENV !== "development") return;

    console.log("\norchestrator SUMMARY");
    console.log("=".repeat(90));
    results.forEach((r, i) => {
      const icon = r.skipped ? "⏭️" : r.success ? "✅" : "❌";
      const status = r.skipped ? "SKIPPED" : r.status;
      const time = r.executionTime > 0 ? `${r.executionTime.toFixed(1)}ms` : "";
      const extra = r.threatScore ? ` | Score: ${r.threatScore.toFixed(1)}` : "";
      console.log(`${i + 1}. ${icon} ${r.name.padEnd(25)} → ${status}${time}${extra}`);
    });
    console.log("=".repeat(90));
    console.log(`IP: ${ip} | Bot: ${botScore || 0} | Abuse: ${abuseScore || 0} | Total: ${total.toFixed(1)}ms`);
    console.log(`Defense: ${process.env.BYPASS_ALL_SECURITY === 'true' ? 'BYPASSED' : 'ACTIVE'}\n`);
  }
}
