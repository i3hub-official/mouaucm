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
import { IntegrationUtils } from "./integration-utils";
import { Defense } from "./UnifiedThreatDefenseSystem";
import { ComprehensiveHealthMonitor } from "./healthMonitor";

// NEW: The bulletproof executor
import { enhancedExecute } from "./executionWrapper";

// IP Detection — THE SOURCE OF TRUTH
import { ClientIPDetector } from "@/lib/clientIp";

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
    SecurityGuard: true,           // Set to true to disable
    EnhancedRateEnforcer: true,     // Set to true to disable
    EncryptionEnforcer: true,       // Set to true to disable
    SessionTokenValidator: true,    // Set to true to disable
    
    // Defense Layers
    UnifiedThreatDefense: true,     // Set to true to disable
    
    // Secondary Layers
    GeoGuard: false,                 // Set to true to disable
    CacheManager: false,             // Set to true to disable
    BehaviorAnalyst: false,          // Set to true to disable
    ComplianceMonitor: false,        // Set to true to disable
    RequestTransformer: false,       // Set to true to disable
    
    // Observability
    ActivityLogger: false,           // Set to true to disable
  };

  // ===========================================================
  // ENVIRONMENT-BASED DISABLE - Disable layers in specific environments
  // ===========================================================
  private static shouldDisableLayer(layerName: string): boolean {
    // Check if explicitly disabled
    if (this.DISABLED_LAYERS[layerName as keyof typeof this.DISABLED_LAYERS]) {
      return true;
    }

    // Disable specific layers in development
    if (process.env.NODE_ENV === 'development') {
      const devDisabledLayers = [
        'EnhancedRateEnforcer',  // Disable rate limiting in dev
        'GeoGuard',              // Disable geo blocking in dev
        // Add more as needed
      ];
      
      if (devDisabledLayers.includes(layerName)) {
        console.log(`[orchestrator] 🚧 Layer ${layerName} disabled in development`);
        return true;
      }
    }

    // Disable based on feature flags
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
    // TEMPORARY BYPASS - Use this to completely bypass all security
    // ===========================================================
    if (process.env.BYPASS_ALL_SECURITY === 'true') {
      console.warn('⚠️⚠️⚠️ ALL SECURITY LAYERS BYPASSED ⚠️⚠️⚠️');
      return NextResponse.next();
    }

    // ===========================================================
    // PATH-BASED BYPASS - Skip security for specific paths
    // ===========================================================
    const bypassPaths = [
      '/api/public',
      '/health',
      '/_next',
      '/favicon.ico',
      ...(process.env.NODE_ENV === 'development' ? ['/sr', '/check'] : [])
    ];

    if (bypassPaths.some(path => request.nextUrl.pathname.startsWith(path))) {
      console.log(`[orchestrator] 🚧 Bypassing security for path: ${request.nextUrl.pathname}`);
      return NextResponse.next();
    }

    try {
      // Initialize trusted sources once
      TrustedSourceManager.initialize();

      // ──────────────────────────────
      // PHASE 0: Get Real Client IP (Critical Foundation)
      // ──────────────────────────────
      const ipInfo = ClientIPDetector.getClientIP(request);
      
      console.log(`[orchestrator] Request from IP: ${ipInfo.ip}, Source: ${ipInfo.source}, Confidence: ${ipInfo.confidence}`);

      // ──────────────────────────────
      // PHASE 1: Build Context (with real IP)
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
      });

      authContext = AuthenticatedActionHandler.enhanceContext(request, context);

      results.push({
        name: "ContextBuilder",
        result: NextResponse.next(),
        logs: [
          `IP: ${ipInfo.ip} (${ipInfo.source})`,
          `Action: ${authContext.actionType}`,
          `Sensitivity: ${authContext.sensitivity}`,
        ],
        executionTime: 0,
        status: 200,
        success: true,
      });

      // ──────────────────────────────
      // PHASE 2: Foundation Security
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
        return orchestrator.finalize(request, response, results, globalStart, ipInfo.ip);
      }

      // ──────────────────────────────
      // PHASE 3: AI Defense (uses real IP)
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
          return orchestrator.finalize(request, defenseExec.result, results, globalStart, ipInfo.ip);
        }

        response = defenseExec.result;
      } else {
        console.log("[orchestrator] 🚧 UnifiedThreatDefense layer disabled");
      }

      // ──────────────────────────────
      // PHASE 4: Secondary Layer
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
      // PHASE 5: Async Logging (with real IP)
      // ──────────────────────────────
      if (!this.shouldDisableLayer("ActivityLogger")) {
        enhancedExecute(() => ActivityLogger.log(request, authContext), {
          fallback: undefined,
          name: "ActivityLogger",
          context: authContext,
        }).catch(() => {});
      }

      console.log("[orchestrator] All layers completed successfully");
      return orchestrator.finalize(request, response, results, globalStart, ipInfo.ip);
    } catch (error) {
      console.error(`[orchestrator] CRASH after ${(performance.now() - globalStart).toFixed(1)}ms:`, error);
      const resp = NextResponse.json({ error: "System failure" }, { status: 503 });
      return orchestrator.finalize(request, resp, results, globalStart, "crash");
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
      // Check if this layer is disabled
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
    clientIp: string
  ): NextResponse {
    const total = performance.now() - start;

    response = ResponseMerger.addSystemHeaders(response, {
      startTime: start,
      requestId: results[0]?.result.headers.get("x-request-id") || "unknown",
      processingTime: total,
      clientIp,
      chain: results.map((r) => r.name),
    });

    const defense = results.find((r) => r.name === "UnifiedThreatDefense");
    if (defense) {
      response.headers.set("X-Threat-Final", defense.threatScore?.toFixed(1) || "0");
      response.headers.set("X-Defense-Action", defense.decision || "ALLOW");
    }

    ComprehensiveHealthMonitor.recordRequest(total, response.status);
    orchestrator.printSummary(results, total, clientIp);

    return response;
  }

  private static printSummary(results: LayerResult[], total: number, ip: string) {
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
    console.log(`IP: ${ip} | Total: ${total.toFixed(1)}ms | Defense: ${process.env.BYPASS_ALL_SECURITY === 'true' ? 'BYPASSED' : 'ACTIVE'}\n`);
  }
}
