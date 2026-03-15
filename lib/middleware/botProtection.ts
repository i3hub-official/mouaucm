// src/lib/middleware/botProtection.ts
import { NextRequest, NextResponse } from "next/server";
import { getClientIP } from "../clientIp";

// Known good bot user agents
const GOOD_BOTS = [
  'Googlebot',
  'Google-InspectionTool',
  'Google-PageRenderer',
  'bingbot',
  'BingPreview',
  'Slurp', // Yahoo
  'DuckDuckBot',
  'Baiduspider',
  'YandexBot',
  'facebookexternalhit',
  'Twitterbot',
  'LinkedInBot',
  'Applebot',
  'Pinterestbot',
  'Slackbot',
  'Discordbot',
  'TelegramBot',
  'WhatsApp',
  'Amazonbot',
  'AhrefsBot',
  'SemrushBot',
  'MozBot',
  'BLEXBot',
  'DotBot', // Alexa
  'PetalBot',
  'SeznamBot',
  'Sogou',
  'Exabot',
  'MJ12bot', // Majestic
  'Rogerbot', // Moz
  'UptimeRobot',
  'Pingdom',
  'StatusCake',
  'Better Uptime',
  'PagerDuty',
  'Zendesk',
  'Intercom',
  'HubSpot',
  'Salesforce',
  'Mail.ru',
  'Yahoo!',
  'Gmail',
  'Outlook',
  'ProtonMail',
  'Thunderbird',
  'RainLoop',
  'Roundcube',
  'SquirrelMail',
  'Horde',
  'IMP',
  'Cyrus',
  'Dovecot',
  'Postfix',
  'Sendmail',
  'Exim',
  'Qmail',
  'Courier',
  'Zimbra',
  'Scalix',
  'Open-Xchange',
  'Kerio',
  'IceWarp',
  'MDaemon',
  'Alt-N',
  'Merak',
  'ArGoSoft',
  'hMailServer',
  'MailEnable',
  'SmarterMail',
  'IceWarp',
  'MDaemon',
  'Alt-N',
  'Merak',
  'ArGoSoft',
  'hMailServer',
  'MailEnable',
  'SmarterMail',
];

// Suspicious patterns in user agents
const BOT_INDICATORS = [
  /bot/i,
  /crawler/i,
  /spider/i,
  /scraper/i,
  /scrape/i,
  /harvest/i,
  /collect/i,
  /extract/i,
  /parser/i,
  /downloader/i,
  /fetcher/i,
  /gatherer/i,
  /miner/i,
  /ripper/i,
  /extractor/i,
  /archive/i,
  /wayback/i,
  /internetarchive/i,
  /ia_archiver/i,
  /archive.org/i,
  /wget/i,
  /curl/i,
  /python/i,
  /perl/i,
  /ruby/i,
  /php/i,
  /java/i,
  /go-http/i,
  /rust/i,
  /scrapy/i,
  /beautifulsoup/i,
  /selenium/i,
  /puppeteer/i,
  /playwright/i,
  /cypress/i,
  /headless/i,
  /phantom/i,
  /slimer/i,
  /trident/i,
  /msie/i,
  /node/i,
  /axios/i,
  /request/i,
  /superagent/i,
  /got/i,
  /fetch/i,
  /http/i,
  /client/i,
  /agent/i,
  /mechanize/i,
  /urllib/i,
  /httplib/i,
  /httpx/i,
  /aiohttp/i,
  /httpx/i,
  /httpx/i,
  /httpx/i,
];

// Known bad IP ranges (example - you'd want to use a proper IP reputation service)
const BAD_IP_RANGES: never[] = [
  // Add known spam/malicious IP ranges
  // Example: '45.0.0.0/8', '185.0.0.0/8', etc.
];

interface BotScore {
  score: number; // 0-100 (higher = more likely bad bot)
  reason: string[];
  isGoodBot: boolean;
  isBadBot: boolean;
  isPotentialBot: boolean;
}

interface AbuseHeaders {
  userAgent: string;
  accept: string;
  acceptLanguage: string;
  acceptEncoding: string;
  connection: string;
  cacheControl: string;
  upgradeInsecureRequests: string;
  dnt: string;
  purpose: string;
  xPurpose: string;
  secChUa: string;
  secChUaMobile: string;
  secChUaPlatform: string;
  secFetchDest: string;
  secFetchMode: string;
  secFetchSite: string;
  secFetchUser: string;
  viewportWidth: string;
  viewportHeight: string;
  deviceMemory: string;
  hardwareConcurrency: string;
  rtt: string;
  downlink: string;
  ect: string;
}

export class BotProtection {
  private static requestCounts = new Map<string, { count: number; timestamp: number }>();
  private static readonly FLOOD_THRESHOLD = 100; // requests per minute
  private static readonly CLEANUP_INTERVAL = 60000; // 1 minute

  static {
    // Clean up old entries every minute
    setInterval(() => {
      const now = Date.now();
      for (const [key, value] of this.requestCounts.entries()) {
        if (now - value.timestamp > 60000) { // older than 1 minute
          this.requestCounts.delete(key);
        }
      }
    }, this.CLEANUP_INTERVAL);
  }

  /**
   * Inspect request for bot characteristics
   */
  static inspect(request: NextRequest): BotScore {
    const userAgent = request.headers.get('user-agent') || '';
    const ip = getClientIP(request);
    const accept = request.headers.get('accept') || '';
    const acceptLanguage = request.headers.get('accept-language') || '';
    const secFetchMode = request.headers.get('sec-fetch-mode') || '';
    const secFetchSite = request.headers.get('sec-fetch-site') || '';
    const secFetchDest = request.headers.get('sec-fetch-dest') || '';
    const cacheControl = request.headers.get('cache-control') || '';
    const purpose = request.headers.get('purpose') || request.headers.get('x-purpose') || '';
    const dnt = request.headers.get('dnt') || '';
    const upgradeInsecure = request.headers.get('upgrade-insecure-requests') || '';
    const secChUa = request.headers.get('sec-ch-ua') || '';
    const secChUaMobile = request.headers.get('sec-ch-ua-mobile') || '';
    const secChUaPlatform = request.headers.get('sec-ch-ua-platform') || '';
    const viewportWidth = request.headers.get('viewport-width') || '';
    const viewportHeight = request.headers.get('viewport-height') || '';
    const deviceMemory = request.headers.get('device-memory') || '';
    const hardwareConcurrency = request.headers.get('hardware-concurrency') || '';
    const rtt = request.headers.get('rtt') || '';
    const downlink = request.headers.get('downlink') || '';
    const ect = request.headers.get('ect') || '';

    let score = 0;
    const reason: string[] = [];

    // Check for known good bots (score 0)
    const isGoodBot = GOOD_BOTS.some(bot => 
      userAgent.toLowerCase().includes(bot.toLowerCase())
    );

    if (isGoodBot) {
      return {
        score: 0,
        reason: ['Known good bot'],
        isGoodBot: true,
        isBadBot: false,
        isPotentialBot: false,
      };
    }

    // Check for bad bot indicators
    for (const pattern of BOT_INDICATORS) {
      if (pattern.test(userAgent)) {
        score += 30;
        reason.push(`Bot indicator: ${pattern}`);
        break;
      }
    }

    // Missing or suspicious Accept header
    if (!accept || accept === '*/*') {
      score += 10;
      reason.push('Suspicious Accept header');
    }

    // Missing Accept-Language
    if (!acceptLanguage) {
      score += 15;
      reason.push('Missing Accept-Language');
    }

    // Suspicious Sec-Fetch headers (modern browsers always send these)
    if (request.method === 'GET' && !secFetchMode && !secFetchSite) {
      score += 25;
      reason.push('Missing Sec-Fetch headers');
    }

    // Check Sec-Fetch-Mode
    if (secFetchMode === 'navigate' && secFetchSite === 'none') {
      // This is a direct navigation - likely a real user
    } else if (secFetchMode === 'cors' && secFetchSite === 'cross-site') {
      score += 10;
      reason.push('Suspicious cross-site request');
    }

    // Check for automation/driver indicators
    if (userAgent.includes('Headless') || userAgent.includes('headless')) {
      score += 40;
      reason.push('Headless browser detected');
    }

    // Check for missing browser features
    if (!secChUa) {
      score += 5;
      reason.push('Missing Sec-CH-UA');
    }

    if (!secChUaPlatform) {
      score += 5;
      reason.push('Missing Sec-CH-UA-Platform');
    }

    // Check for prefetch/cache hints
    if (purpose === 'prefetch' || purpose === 'preview') {
      score -= 10; // Legitimate prefetch
      reason.push('Legitimate prefetch');
    }

    // Check DNT (Do Not Track) - usually real users
    if (dnt === '1') {
      score -= 5;
      reason.push('Do Not Track enabled');
    }

    // Check for upgrade-insecure-requests (real browsers send this)
    if (upgradeInsecure) {
      score -= 5;
      reason.push('Upgrade insecure requests');
    }

    // Check for realistic viewport dimensions
    if (viewportWidth && viewportHeight) {
      const width = parseInt(viewportWidth);
      const height = parseInt(viewportHeight);
      
      if (width > 300 && width < 4000 && height > 300 && height < 4000) {
        score -= 10;
        reason.push('Realistic viewport dimensions');
      } else {
        score += 10;
        reason.push('Suspicious viewport dimensions');
      }
    }

    // Check for device capabilities (real browsers have these)
    if (deviceMemory) {
      const memory = parseInt(deviceMemory);
      if (memory >= 2 && memory <= 8) {
        score -= 5;
        reason.push('Realistic device memory');
      }
    }

    if (hardwareConcurrency) {
      const cores = parseInt(hardwareConcurrency);
      if (cores >= 2 && cores <= 16) {
        score -= 5;
        reason.push('Realistic hardware concurrency');
      }
    }

    // Check network quality hints (real browsers have these)
    if (rtt || downlink || ect) {
      score -= 5;
      reason.push('Network quality hints present');
    }

    // Check for request flooding
    const floodScore = this.detectFlooding(ip);
    if (floodScore > 0) {
      score += floodScore;
      reason.push(`Request flooding detected (+${floodScore})`);
    }

    // Check IP reputation
    const ipRepScore = this.checkIPReputation(ip);
    if (ipRepScore > 0) {
      score += ipRepScore;
      reason.push(`Poor IP reputation (+${ipRepScore})`);
    }

    // Clamp score between 0 and 100
    score = Math.max(0, Math.min(100, score));

    return {
      score,
      reason,
      isGoodBot: false,
      isBadBot: score > 70,
      isPotentialBot: score > 40 && score <= 70,
    };
  }

  /**
   * Detect request flooding
   */
  private static detectFlooding(ip: string): number {
    const now = Date.now();
    const key = `flood:${ip}`;
    
    const current = this.requestCounts.get(key) || { count: 0, timestamp: now };
    
    // Reset if older than 1 minute
    if (now - current.timestamp > 60000) {
      current.count = 0;
      current.timestamp = now;
    }
    
    current.count++;
    this.requestCounts.set(key, current);
    
    if (current.count > this.FLOOD_THRESHOLD) {
      // Exponential score based on how much over threshold
      const excess = current.count - this.FLOOD_THRESHOLD;
      return Math.min(40, Math.floor(excess / 5) * 5);
    }
    
    return 0;
  }

  /**
   * Check IP reputation (simplified - in production, use a service like IPQualityScore)
   */
  private static checkIPReputation(ip: string): number {
    // This is a placeholder - in production, integrate with:
    // - IPQualityScore
    // - AbuseIPDB
    // - MaxMind
    // - Cloudflare Threat Intelligence
    
    // Check against known bad ranges
    for (const range of BAD_IP_RANGES) {
      if (this.ipInRange(ip, range)) {
        return 30;
      }
    }
    
    // Check if it's a datacenter IP (often used by bots)
    if (ip.startsWith('34.') || ip.startsWith('35.') || ip.startsWith('52.') || 
        ip.startsWith('54.') || ip.startsWith('13.') || ip.startsWith('18.')) {
      return 10;
    }
    
    return 0;
  }

  /**
   * Simple IP range check (CIDR)
   */
  private static ipInRange(ip: string, cidr: string): boolean {
    const [range, bits] = cidr.split('/');
    const mask = parseInt(bits, 10);
    
    const ipNum = this.ipToNumber(ip);
    const rangeNum = this.ipToNumber(range);
    const maskNum = ~(2 ** (32 - mask) - 1);
    
    return (ipNum & maskNum) === (rangeNum & maskNum);
  }

  private static ipToNumber(ip: string): number {
    const parts = ip.split('.').map(Number);
    return ((parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
  }

  /**
   * Enforce bot protection - return challenge or block response
   */
  static enforce(score: number, request?: NextRequest, challengePassed?: boolean): NextResponse | null {
    // Good bot - allow
    if (score === 0) {
      return null;
    }
    
    // Suspicious bot - require JavaScript challenge
    if (score > 40 && score <= 70) {
      return this.sendChallenge(request);
    }
    
    // Bad bot - block
    if (score > 70) {
      return this.blockRequest(request);
    }
    
    // Normal request - allow
    return null;
  }

  /**
   * Send JavaScript challenge to verify if it's a real browser
   */
  private static sendChallenge(request?: NextRequest): NextResponse {
    const challengeHTML = `
      <!DOCTYPE html>
      <html>
        <head>
          <title>Verifying you are human...</title>
          <style>
            body {
              font-family: system-ui, -apple-system, sans-serif;
              background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
              color: white;
              min-height: 100vh;
              display: flex;
              align-items: center;
              justify-content: center;
              margin: 0;
            }
            .challenge-box {
              background: rgba(255, 255, 255, 0.1);
              backdrop-filter: blur(10px);
              padding: 2rem;
              border-radius: 1rem;
              text-align: center;
              box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
            }
            .loader {
              width: 48px;
              height: 48px;
              border: 4px solid #FFF;
              border-bottom-color: transparent;
              border-radius: 50%;
              margin: 20px auto;
              animation: rotation 1s linear infinite;
            }
            @keyframes rotation {
              0% { transform: rotate(0deg); }
              100% { transform: rotate(360deg); }
            }
            p {
              margin: 10px 0;
              font-size: 1.1rem;
            }
          </style>
        </head>
        <body>
          <div class="challenge-box">
            <h2>Verifying your browser...</h2>
            <div class="loader"></div>
            <p>Please wait while we check your browser.</p>
            <p class="small">This helps us ensure you're a real user.</p>
          </div>
          <script>
            // Set cookie to mark as verified
            document.cookie = "bot-challenge-passed=true; path=/; max-age=3600";
            
            // Collect browser fingerprint
            const fingerprint = {
              userAgent: navigator.userAgent,
              platform: navigator.platform,
              language: navigator.language,
              languages: navigator.languages,
              cookiesEnabled: navigator.cookieEnabled,
              doNotTrack: navigator.doNotTrack,
              deviceMemory: navigator.deviceMemory,
              hardwareConcurrency: navigator.hardwareConcurrency,
              maxTouchPoints: navigator.maxTouchPoints,
              vendor: navigator.vendor,
              plugins: Array.from(navigator.plugins || []).map(p => p.name),
              screenWidth: screen.width,
              screenHeight: screen.height,
              screenColorDepth: screen.colorDepth,
              timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
              sessionStorage: !!window.sessionStorage,
              localStorage: !!window.localStorage,
              indexedDB: !!window.indexedDB,
              openDatabase: !!window.openDatabase,
              cpuClass: navigator.cpuClass,
              platformVersion: navigator.platformVersion,
              oscpu: navigator.oscpu,
              appName: navigator.appName,
              appVersion: navigator.appVersion,
              appCodeName: navigator.appCodeName,
              product: navigator.product,
              productSub: navigator.productSub,
              vendorSub: navigator.vendorSub,
              mimeTypes: Array.from(navigator.mimeTypes || []).map(m => m.type),
            };
            
            // Send fingerprint back
            setTimeout(() => {
              window.location.href = window.location.href + '?verified=true&fp=' + 
                encodeURIComponent(JSON.stringify(fingerprint));
            }, 2000);
          </script>
        </body>
      </html>
    `;
    
    return new NextResponse(challengeHTML, {
      status: 403,
      headers: {
        'Content-Type': 'text/html',
        'X-Bot-Challenge': 'required',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
      },
    });
  }

  /**
   * Block bad bot
   */
  private static blockRequest(request?: NextRequest): NextResponse {
    const isAPI = request?.nextUrl.pathname.startsWith('/api');
    
    if (isAPI) {
      return NextResponse.json(
        {
          error: 'Access Denied',
          message: 'Your request has been blocked by our security systems.',
          code: 'BOT_BLOCKED',
        },
        { 
          status: 403,
          headers: {
            'X-Bot-Blocked': 'true',
            'Cache-Control': 'no-store',
          },
        }
      );
    }
    
    const blockHTML = `
      <!DOCTYPE html>
      <html>
        <head>
          <title>Access Denied</title>
          <style>
            body {
              font-family: system-ui, -apple-system, sans-serif;
              background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
              color: white;
              min-height: 100vh;
              display: flex;
              align-items: center;
              justify-content: center;
              margin: 0;
            }
            .block-box {
              background: rgba(255, 255, 255, 0.1);
              backdrop-filter: blur(10px);
              padding: 2rem;
              border-radius: 1rem;
              text-align: center;
              box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
              max-width: 400px;
            }
            h1 {
              font-size: 2rem;
              margin-bottom: 1rem;
            }
            p {
              margin: 1rem 0;
              font-size: 1.1rem;
              line-height: 1.5;
            }
            .code {
              background: rgba(0, 0, 0, 0.2);
              padding: 0.5rem;
              border-radius: 0.5rem;
              font-family: monospace;
              font-size: 0.9rem;
            }
          </style>
        </head>
        <body>
          <div class="block-box">
            <h1>🔒 Access Denied</h1>
            <p>Your request has been automatically blocked by our security systems.</p>
            <p>This may be due to:</p>
            <ul style="text-align: left;">
              <li>Suspicious bot activity</li>
              <li>Request flooding</li>
              <li>Poor IP reputation</li>
              <li>Abusive headers</li>
            </ul>
            <p class="code">Reference: BOT-${Date.now().toString(36)}</p>
            <p>If you believe this is an error, please contact support.</p>
          </div>
        </body>
      </html>
    `;
    
    return new NextResponse(blockHTML, {
      status: 403,
      headers: {
        'Content-Type': 'text/html',
        'X-Bot-Blocked': 'true',
        'Cache-Control': 'no-store',
      },
    });
  }

  /**
   * Get abuse header score breakdown
   */
  static getAbuseHeaderScore(request: NextRequest): Record<string, number> {
    const scores: Record<string, number> = {};
    const headers = this.extractHeaders(request);
    
    // Score each header
    scores.userAgent = this.scoreUserAgent(headers.userAgent);
    scores.accept = this.scoreAccept(headers.accept);
    scores.acceptLanguage = this.scoreAcceptLanguage(headers.acceptLanguage);
    scores.secFetch = this.scoreSecFetch(headers);
    scores.browserFeatures = this.scoreBrowserFeatures(headers);
    scores.networkQuality = this.scoreNetworkQuality(headers);
    
    return scores;
  }

  private static extractHeaders(request: NextRequest): AbuseHeaders {
    return {
      userAgent: request.headers.get('user-agent') || '',
      accept: request.headers.get('accept') || '',
      acceptLanguage: request.headers.get('accept-language') || '',
      acceptEncoding: request.headers.get('accept-encoding') || '',
      connection: request.headers.get('connection') || '',
      cacheControl: request.headers.get('cache-control') || '',
      upgradeInsecureRequests: request.headers.get('upgrade-insecure-requests') || '',
      dnt: request.headers.get('dnt') || '',
      purpose: request.headers.get('purpose') || '',
      xPurpose: request.headers.get('x-purpose') || '',
      secChUa: request.headers.get('sec-ch-ua') || '',
      secChUaMobile: request.headers.get('sec-ch-ua-mobile') || '',
      secChUaPlatform: request.headers.get('sec-ch-ua-platform') || '',
      secFetchDest: request.headers.get('sec-fetch-dest') || '',
      secFetchMode: request.headers.get('sec-fetch-mode') || '',
      secFetchSite: request.headers.get('sec-fetch-site') || '',
      secFetchUser: request.headers.get('sec-fetch-user') || '',
      viewportWidth: request.headers.get('viewport-width') || '',
      viewportHeight: request.headers.get('viewport-height') || '',
      deviceMemory: request.headers.get('device-memory') || '',
      hardwareConcurrency: request.headers.get('hardware-concurrency') || '',
      rtt: request.headers.get('rtt') || '',
      downlink: request.headers.get('downlink') || '',
      ect: request.headers.get('ect') || '',
    };
  }

  private static scoreUserAgent(ua: string): number {
    if (!ua) return 100;
    if (ua.length < 10) return 50;
    if (ua.includes('Headless') || ua.includes('headless')) return 80;
    if (/python|curl|wget|scrapy|selenium/i.test(ua)) return 90;
    if (/chrome|firefox|safari|edge/i.test(ua)) return 0;
    return 20;
  }

  private static scoreAccept(accept: string): number {
    if (!accept) return 50;
    if (accept === '*/*') return 40;
    if (accept.includes('text/html')) return 0;
    return 10;
  }

  private static scoreAcceptLanguage(lang: string): number {
    if (!lang) return 60;
    if (lang.length > 50) return 20;
    if (/^[a-z]{2}(-[A-Z]{2})?$/.test(lang.split(',')[0].trim())) return 0;
    return 30;
  }

  private static scoreSecFetch(headers: AbuseHeaders): number {
    let score = 0;
    
    if (!headers.secFetchMode && !headers.secFetchSite) {
      score += 50;
    }
    
    if (headers.secFetchMode && !['navigate', 'cors', 'no-cors'].includes(headers.secFetchMode)) {
      score += 20;
    }
    
    if (headers.secFetchSite === 'none' && headers.secFetchMode !== 'navigate') {
      score += 30;
    }
    
    return score;
  }

  private static scoreBrowserFeatures(headers: AbuseHeaders): number {
    let score = 0;
    
    if (!headers.secChUa) score += 15;
    if (!headers.secChUaPlatform) score += 15;
    if (!headers.deviceMemory) score += 10;
    if (!headers.hardwareConcurrency) score += 10;
    if (!headers.viewportWidth || !headers.viewportHeight) score += 20;
    
    return Math.min(100, score);
  }

  private static scoreNetworkQuality(headers: AbuseHeaders): number {
    let score = 0;
    
    if (!headers.rtt) score += 15;
    if (!headers.downlink) score += 15;
    if (!headers.ect) score += 15;
    
    return Math.min(100, score);
  }
}