const spec = {
  openapi: "3.0.3",
  info: {
    title:       "IPShield — IP Risk Intelligence API",
    description: `
## Overview
IPShield provides real-time IP risk scoring combining multiple threat intelligence sources:
- **AbuseIPDB** — abuse confidence scoring and report history
- **Shodan InternetDB** — open ports, CVEs, hostnames, threat tags
- **VirusTotal** — multi-engine malware/threat detection
- **Threat Feeds** — Feodo Tracker (C2), Spamhaus DROP, Emerging Threats, AlienVault OTX
- **WHOIS/RDAP** — registration intelligence, org details, abuse contacts
- **Reverse DNS** — PTR records with FCrDNS verification and pattern detection
- **Blacklist** — internal IP blocklist with severity, categories, tags and expiry
- **Case Management** — investigation cases with IP attachments and analyst notes
- **Active Scanning** — on-demand nmap port scans and nuclei vulnerability templates

## Authentication
All endpoints except \`/api/health\` and \`/api/docs\` require the \`x-api-key\` header.

\`\`\`
x-api-key: your_api_key_here
\`\`\`

Dashboard login uses JWT via \`Authorization: Bearer <token>\`.

## Rate Limits
| Endpoint | Limit | Window |
|----------|-------|--------|
| Global | 200 requests | 15 minutes |
| /score | 30 requests | 1 minute |
| /whois | 20 requests | 1 minute |
| /report | 10 requests | 1 minute |
| /scan | 5 requests | 10 minutes |
| /auth/login | 10 attempts | 15 minutes |
| /auth/login/mfa | 10 attempts | 5 minutes |
| /auth/forgot-password | 5 attempts | 15 minutes |
| /auth/reset-password | 5 attempts | 15 minutes |

## MFA
All dashboard accounts require two-factor authentication (TOTP). On first login after activation,
users are redirected to \`/mfa-setup\` to enrol. Subsequent logins issue a short-lived challenge
token and require a 6-digit TOTP code or an 8-character backup code.

## Active Scanning
Unlike passive intelligence endpoints, \`/scan\` performs **active reconnaissance** against the
target IP using nmap and nuclei. This requires:
- **Analyst role or higher** (readonly keys are rejected with 403)
- **Explicit consent** — \`consent: true\` must be set in the request body
- **A public, non-reserved IP** — RFC-1918, loopback and link-local ranges are rejected with 400

Scans run asynchronously via a job queue. Poll \`GET /scan/job/{jobId}\` until \`status\` is
\`done\` or \`failed\`. Typical scans complete in 2–5 minutes.

## Plans & Quotas
In addition to the IP-based rate limits above, every account has a subscription
plan with its own daily quota per feature. Quotas are tracked per account
(shared across all API keys belonging to that account) and reset at midnight UTC.
 
| Feature | Free | Team |
|---------|------|------|
| IP score lookups / day | 5 | 500,000 |
| Batch scoring / day | Not available | 100,000 |
| Active scans / day | Not available | 10,000 |
| Watched IPs (max) | 1 | 10,000 |

Exceeding a quota returns \`HTTP 429\` with \`{ "error": "quota_exceeded", "plan",
"limit", "used", "upgrade_url" }\`. Requesting a feature not included on the
current plan (e.g. active scanning on Free) returns \`HTTP 403\` with
\`{ "error": "feature_not_available", "plan", "upgrade_url" }\`.
 
See [/pricing](/pricing) to view or change your plan.

## Account Pages
| Page | Description |
|------|-------------|
| \`/login\` | Email + password → MFA step |
| \`/mfa-setup\` | First-time TOTP enrolment |
| \`/activate?token=\` | Invite activation and password set |
| \`/forgot-password\` | Request a password reset link |
| \`/reset-password?token=\` | Set a new password via reset link |
    `,
    version: "2.3.0",
    contact: { name: "IPShield", url: "https://ipshield.live/" }
  },

  servers: [
    { url: "/api", description: "Current server" },
    { url: "https://ipshield.live/", description: "Production (Render)" }
  ],

  components: {
    securitySchemes: {
      ApiKeyAuth: {
        type: "apiKey", in: "header", name: "x-api-key",
        description: "Your IPShield API key."
      },
      BearerAuth: {
        type: "http", scheme: "bearer", bearerFormat: "JWT",
        description: "JWT token issued on successful login. Required for /auth, /mfa and /keys endpoints."
      }
    },
    schemas: {

        QuotaExceeded: {
        type: "object",
        properties: {
          error:       { type: "string", example: "quota_exceeded" },
          message:     { type: "string", example: 'Daily limit for "score" reached (5/day on the free plan).' },
          plan:        { type: "string", enum: ["free","team"], example: "free" },
          limit:       { type: "integer", example: 5 },
          used:        { type: "integer", example: 5 },
          upgrade_url: { type: "string", example: "/pricing" }
        }
      },
 
      FeatureNotAvailable: {
        type: "object",
        description: "Returned when the plan doesn't include this feature at all (e.g. active scanning on Free).",
        properties: {
          error:       { type: "string", example: "feature_not_available" },
          message:     { type: "string", example: 'The "active_scan" feature isn\'t included on the free plan.' },
          plan:        { type: "string", example: "free" },
          upgrade_url: { type: "string", example: "/pricing" }
        }
      },

          responses: {
      QuotaExceededResponse: {
        description: "Daily quota exceeded for this feature on the caller's current plan.",
        content: { "application/json": { schema: { "$ref": "#/components/schemas/QuotaExceeded" } } }
      },
      FeatureNotAvailableResponse: {
        description: "This feature isn't included on the caller's current plan.",
        content: { "application/json": { schema: { "$ref": "#/components/schemas/FeatureNotAvailable" } } }
      }
    },

      // Shared
      Error: {
        type: "object",
        properties: {
          error:   { type: "string", example: "Validation failed" },
          message: { type: "string", example: "IP address is required" }
        }
      },

      Signal: {
        type: "object",
        properties: {
          category: { type: "string", example: "ABUSE" },
          detail:   { type: "string", example: "Confidence score: 95/100 · 42 reports" },
          severity: { type: "string", enum: ["critical","high","medium","low","info"] }
        }
      },

      GeoInfo: {
        type: "object",
        properties: {
          country:  { type: "string",  example: "Germany" },
          region:   { type: "string",  example: "Bavaria" },
          city:     { type: "string",  example: "Munich" },
          timezone: { type: "string",  example: "Europe/Berlin" },
          lat:      { type: "number",  example: 48.1374 },
          lon:      { type: "number",  example: 11.5755 }
        }
      },

      NetworkInfo: {
        type: "object",
        properties: {
          isp:       { type: "string", example: "Deutsche Telekom AG" },
          asn:       { type: "string", example: "AS3320 Deutsche Telekom AG" },
          type:      { type: "string", enum: ["hosting","residential"], example: "hosting" },
          hostnames: { type: "array",  items: { type: "string" } }
        }
      },

      RDNSInfo: {
        type: "object",
        properties: {
          hostnames: { type: "array",   items: { type: "string" }, example: ["mail.example.com"] },
          primary:   { type: "string",  nullable: true, example: "mail.example.com" },
          fcrdns:    { type: "boolean", nullable: true },
          private:   { type: "boolean" }
        }
      },

      IntelligenceInfo: {
        type: "object",
        properties: {
          isDatacenter: { type: "boolean" },
          isProxy:      { type: "boolean" },
          isTor:        { type: "boolean" },
          velocity:     { type: "string", enum: ["LOW","MEDIUM","HIGH"] },
          openPorts:    { type: "array", items: { type: "integer" }, example: [80,443,22] },
          vulns:        { type: "array", items: { type: "string" }, example: ["CVE-2021-44228"] },
          shodanTags:   { type: "array", items: { type: "string" }, example: ["scanner","tor"] },
          virusTotal: {
            type: "object", nullable: true,
            properties: {
              malicious:  { type: "integer" },
              suspicious: { type: "integer" },
              harmless:   { type: "integer" },
              total:      { type: "integer" }
            }
          }
        }
      },

      ThreatFeedInfo: {
        type: "object",
        properties: {
          feodo:           { type: "boolean" },
          spamhaus:        { type: "boolean" },
          emergingThreats: { type: "boolean" },
          otx: {
            type: "object", nullable: true,
            properties: {
              pulseCount:   { type: "integer" },
              pulseNames:   { type: "array", items: { type: "string" } },
              malwareCount: { type: "integer" },
              tags:         { type: "array", items: { type: "string" } }
            }
          }
        }
      },

      ScoreResult: {
        type: "object",
        properties: {
          ip:        { type: "string",  example: "185.220.101.1" },
          score:     { type: "integer", minimum: 0, maximum: 100, example: 95 },
          baseScore: { type: "integer" },
          scoreBoost:{ type: "integer" },
          riskLevel: { type: "string", enum: ["CRITICAL","HIGH","MEDIUM","LOW"] },
          action:    { type: "string", enum: ["BLOCK","CHALLENGE","MONITOR","ALLOW"] },
          blacklisted: {
            type: "object", nullable: true,
            properties: {
              id:         { type: "integer" },
              severity:   { type: "string" },
              category:   { type: "string",  nullable: true },
              reason:     { type: "string",  nullable: true },
              added_by:   { type: "string",  nullable: true },
              added_at:   { type: "string" },
              expires_at: { type: "string",  nullable: true },
              tags:       { type: "array", items: { type: "string" } }
            }
          },
          geo:          { "$ref": "#/components/schemas/GeoInfo" },
          network:      { "$ref": "#/components/schemas/NetworkInfo" },
          rdns:         { "$ref": "#/components/schemas/RDNSInfo" },
          intelligence: { "$ref": "#/components/schemas/IntelligenceInfo" },
          threatFeeds:  { "$ref": "#/components/schemas/ThreatFeedInfo" },
          signals:      { type: "array", items: { "$ref": "#/components/schemas/Signal" } },
          meta: {
            type: "object",
            properties: {
              processingMs: { type: "integer" },
              cached:       { type: "boolean" },
              scoredAt:     { type: "string", format: "date-time" }
            }
          }
        }
      },

      // Auth 
      LoginRequest: {
        type: "object",
        properties: {
          email:    { type: "string", format: "email", example: "analyst@company.com" },
          password: { type: "string", example: "••••••••" },
          apiKey:   { type: "string", description: "Alternative: log in with raw API key instead of email+password" }
        }
      },

      LoginResponse: {
        type: "object",
        properties: {
          token:           { type: "string", description: "JWT session token (7d expiry)" },
          user:            { "$ref": "#/components/schemas/UserSummary" },
          mfaRequired:     { type: "boolean", description: "If true, submit TOTP to /auth/login/mfa" },
          challengeToken:  { type: "string",  description: "Short-lived JWT for MFA step (5m expiry)" },
          mfaSetupRequired:{ type: "boolean", description: "If true, redirect to /mfa-setup" }
        }
      },

      UserSummary: {
        type: "object",
        properties: {
          id:    { type: "integer", example: 42 },
          name:  { type: "string",  example: "Alice" },
          email: { type: "string",  example: "alice@company.com" },
          role:  { type: "string",  enum: ["admin","analyst","readonly"], example: "analyst" }
        }
      },

      // MFA
      MFASetupResponse: {
        type: "object",
        properties: {
          secret:  { type: "string", description: "Base32 TOTP secret for manual entry" },
          qrCode:  { type: "string", description: "Data URL of QR code PNG to scan" },
          message: { type: "string" }
        }
      },

      MFAVerifyRequest: {
        type: "object",
        required: ["token"],
        properties: {
          token: { type: "string", example: "123456", description: "6-digit TOTP code from authenticator app" }
        }
      },

      MFAVerifyResponse: {
        type: "object",
        properties: {
          message:     { type: "string", example: "MFA enabled successfully" },
          backupCodes: {
            type: "array", items: { type: "string" },
            description: "8 single-use backup codes shown exactly once — save immediately",
            example: ["A3F2C9B1","D4E5F6A7"]
          }
        }
      },

      MFAStatusResponse: {
        type: "object",
        properties: {
          enabled:    { type: "boolean" },
          verifiedAt: { type: "string", format: "date-time", nullable: true }
        }
      },

      // Keys 
      ApiKey: {
        type: "object",
        properties: {
          id:               { type: "integer" },
          name:             { type: "string" },
          email:            { type: "string", nullable: true },
          role:             { type: "string", enum: ["admin","analyst","readonly"] },
          status:           { type: "string", enum: ["active","pending","suspended","revoked"] },
          key_preview:      { type: "string", example: "a3f2c9b1••••••••••••••••" },
          daily_limit:      { type: "integer" },
          daily_used:       { type: "integer" },
          invited_at:       { type: "string", format: "date-time", nullable: true },
          invite_expires_at:{ type: "string", format: "date-time", nullable: true, description: "Pending invites expire after 7 days" },
          activated_at:     { type: "string", format: "date-time", nullable: true },
          last_used:        { type: "string", format: "date-time", nullable: true },
          notes:            { type: "string", nullable: true }
        }
      },

      InviteRequest: {
        type: "object",
        required: ["name"],
        properties: {
          name:       { type: "string",  example: "Alice" },
          email:      { type: "string",  format: "email", example: "alice@company.com" },
          role:       { type: "string",  enum: ["admin","analyst","readonly"], default: "analyst" },
          dailyLimit: { type: "integer", example: 1000 },
          notes:      { type: "string",  example: "External analyst" }
        }
      },

      InviteResponse: {
        type: "object",
        properties: {
          id:           { type: "integer" },
          name:         { type: "string" },
          email:        { type: "string", nullable: true },
          role:         { type: "string" },
          status:       { type: "string" },
          daily_limit:  { type: "integer" },
          activateUrl:  { type: "string", description: "Send this URL to the invitee — expires in 7 days" },
          invite_token: { type: "string" },
          expiresAt:    { type: "string", format: "date-time" },
          message:      { type: "string" }
        }
      },

      // Blacklist 
      BlacklistEntry: {
        type: "object",
        properties: {
          id:         { type: "integer", example: 1 },
          ip:         { type: "string",  example: "185.220.101.1" },
          severity:   { type: "string",  enum: ["CRITICAL","HIGH","MEDIUM","LOW"], example: "HIGH" },
          category:   { type: "string",  nullable: true, example: "Tor" },
          reason:     { type: "string",  nullable: true, example: "Known Tor exit node" },
          added_by:   { type: "string",  example: "analyst" },
          added_at:   { type: "string",  example: "2026-05-01T10:00:00Z" },
          expires_at: { type: "string",  nullable: true, example: "2026-12-31T23:59:59Z" },
          tags:       { type: "array",   items: { type: "string" }, example: ["tor","scanner"] },
          expired:    { type: "boolean" }
        }
      },

      BlacklistStats: {
        type: "object",
        properties: {
          total:   { type: "integer" },
          active:  { type: "integer" },
          expired: { type: "integer" },
          bySeverity: {
            type: "object",
            properties: {
              CRITICAL: { type: "integer" },
              HIGH:     { type: "integer" },
              MEDIUM:   { type: "integer" },
              LOW:      { type: "integer" }
            }
          }
        }
      },

      // Cases 
      CaseIP: {
        type: "object",
        properties: {
          id:         { type: "integer" },
          case_id:    { type: "integer" },
          ip:         { type: "string",  example: "8.8.8.8" },
          score:      { type: "integer", nullable: true },
          risk_level: { type: "string",  nullable: true },
          note:       { type: "string",  nullable: true },
          added_at:   { type: "string" }
        }
      },

      CaseNote: {
        type: "object",
        properties: {
          id:         { type: "integer" },
          case_id:    { type: "integer" },
          note:       { type: "string",  example: "IP confirmed as C2 node based on Shodan data" },
          author:     { type: "string",  example: "analyst" },
          created_at: { type: "string" }
        }
      },

      Case: {
        type: "object",
        properties: {
          id:          { type: "integer", example: 1 },
          title:       { type: "string",  example: "Tor Exit Node Campaign — May 2026" },
          description: { type: "string",  nullable: true },
          severity:    { type: "string",  enum: ["CRITICAL","HIGH","MEDIUM","LOW"] },
          status:      { type: "string",  enum: ["Open","Investigating","Contained","Resolved","Closed"] },
          assigned_to: { type: "string",  example: "analyst" },
          created_at:  { type: "string" },
          updated_at:  { type: "string" },
          closed_at:   { type: "string",  nullable: true },
          tags:        { type: "array",   items: { type: "string" } },
          ips:         { type: "array",   items: { "$ref": "#/components/schemas/CaseIP" } },
          notes:       { type: "array",   items: { "$ref": "#/components/schemas/CaseNote" } }
        }
      },

      CaseStats: {
        type: "object",
        properties: {
          total:      { type: "integer" },
          byStatus: {
            type: "object",
            properties: {
              Open:          { type: "integer" },
              Investigating: { type: "integer" },
              Contained:     { type: "integer" },
              Resolved:      { type: "integer" },
              Closed:        { type: "integer" }
            }
          },
          bySeverity: {
            type: "object",
            properties: {
              CRITICAL: { type: "integer" },
              HIGH:     { type: "integer" },
              MEDIUM:   { type: "integer" },
              LOW:      { type: "integer" }
            }
          }
        }
      },

      WatchlistEntry: {
        type: "object",
        properties: {
          ip:              { type: "string" },
          label:           { type: "string" },
          threshold:       { type: "integer" },
          last_score:      { type: "integer" },
          last_risk:       { type: "string" },
          last_checked:    { type: "integer" },
          added_at:        { type: "integer" },
          alert_on_change: { type: "integer", enum: [0,1] }
        }
      },

      // Scanning
      ScanStartRequest: {
        type: "object",
        required: ["consent"],
        properties: {
          consent: {
            type: "boolean",
            description: "Must be explicitly true. Confirms the caller is authorised to scan this IP.",
            example: true
          }
        }
      },

      ScanStartResponse: {
        type: "object",
        properties: {
          jobId:   { type: "string", format: "uuid", example: "f47ac10b-58cc-4372-a567-0e02b2c3d479" },
          ip:      { type: "string", example: "45.33.32.156" },
          status:  { type: "string", enum: ["queued"], example: "queued" },
          message: { type: "string" },
          pollUrl: { type: "string", example: "/api/v2/scan/job/f47ac10b-58cc-4372-a567-0e02b2c3d479" }
        }
      },

      ScanResultSummary: {
        type: "object",
        properties: {
          scanner:  { type: "string", enum: ["nmap","nuclei"] },
          severity: { type: "string", enum: ["CRITICAL","HIGH","MEDIUM","LOW","INFO","NONE"] },
          summary: {
            type: "object",
            description: "Distilled findings. Shape differs by scanner — see NmapSummary / NucleiSummary.",
            oneOf: [
              { "$ref": "#/components/schemas/NmapSummary" },
              { "$ref": "#/components/schemas/NucleiSummary" }
            ]
          }
        }
      },

      NmapSummary: {
        type: "object",
        properties: {
          openPorts:     { type: "array", items: { type: "integer" }, example: [22,80,443,3306] },
          services:      { type: "array", items: { type: "string" }, example: ["ssh","http","https","mysql"] },
          os: {
            type: "object", nullable: true,
            properties: {
              name:     { type: "string", example: "Linux 5.x" },
              accuracy: { type: "integer", example: 92 },
              family:   { type: "string", nullable: true, example: "Linux" }
            }
          },
          totalVulns:    { type: "integer", example: 3 },
          criticalVulns: { type: "integer", example: 1 },
          highVulns:     { type: "integer", example: 1 },
          topVulns: {
            type: "array",
            items: {
              type: "object",
              properties: {
                id:       { type: "string", example: "CVE-2024-3094" },
                cvss:     { type: "number", example: 9.8 },
                url:      { type: "string" },
                severity: { type: "string", enum: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] }
              }
            }
          }
        }
      },

      NucleiSummary: {
        type: "object",
        properties: {
          total: { type: "integer", example: 4 },
          bySeverity: {
            type: "object",
            properties: {
              CRITICAL: { type: "integer" },
              HIGH:     { type: "integer" },
              MEDIUM:   { type: "integer" },
              LOW:      { type: "integer" },
              INFO:     { type: "integer" }
            }
          },
          cves:            { type: "array", items: { type: "string" }, example: ["CVE-2024-3094"] },
          uniqueTemplates: { type: "integer" },
          topFindings: {
            type: "array",
            items: {
              type: "object",
              properties: {
                templateId:   { type: "string", example: "tls-version" },
                templateName: { type: "string", example: "Outdated TLS Version" },
                severity:     { type: "string", enum: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] },
                matched:      { type: "string", example: "https://45.33.32.156:443" },
                cve:          { type: "string", nullable: true },
                cvss:         { type: "number", nullable: true },
                description:  { type: "string" },
                tags:         { type: "array", items: { type: "string" } }
              }
            }
          }
        }
      },

      ScanJob: {
        type: "object",
        properties: {
          jobId:       { type: "string", format: "uuid" },
          ip:          { type: "string", example: "45.33.32.156" },
          status:      { type: "string", enum: ["queued","running","done","failed"] },
          progress:    { type: "integer", minimum: 0, maximum: 100, example: 100 },
          createdAt:   { type: "string", format: "date-time" },
          startedAt:   { type: "string", format: "date-time", nullable: true },
          completedAt: { type: "string", format: "date-time", nullable: true },
          error:       { type: "string", nullable: true },
          results:     { type: "array", items: { "$ref": "#/components/schemas/ScanResultSummary" } }
        }
      },

      ScanHistoryEntry: {
        type: "object",
        properties: {
          jobId:       { type: "string", format: "uuid" },
          status:      { type: "string", enum: ["queued","running","done","failed"] },
          createdAt:   { type: "string", format: "date-time" },
          completedAt: { type: "string", format: "date-time", nullable: true },
          results:     { type: "array", items: { "$ref": "#/components/schemas/ScanResultSummary" } }
        }
      },

      ScanRawResponse: {
        type: "object",
        properties: {
          jobId:    { type: "string", format: "uuid" },
          scanner:  { type: "string", enum: ["nmap","nuclei"] },
          severity: { type: "string", enum: ["CRITICAL","HIGH","MEDIUM","LOW","INFO","NONE"] },
          raw: {
            type: "object",
            description: "Full unfiltered scanner output — large payload, fetch on demand only."
          }
        }
      }
    }
  },

  security: [{ ApiKeyAuth: [] }],

  tags: [
    { name: "Auth",       description: "Login, logout, password reset" },
    { name: "MFA",        description: "Two-factor authentication setup and management" },
    { name: "Keys",       description: "API key and account management (admin)" },
    { name: "Scoring",    description: "IP risk scoring — single and batch" },
    { name: "Intelligence", description: "Deep intelligence lookups (WHOIS, reverse DNS)" },
    { name: "Blacklist",  description: "Internal IP blocklist management" },
    { name: "Cases",      description: "Investigation case management" },
    { name: "Watchlist",  description: "IP monitoring and alerting" },
    { name: "Audit",      description: "Scoring history and search" },
    { name: "Scanning",   description: "Active reconnaissance — nmap port scans and nuclei vulnerability templates (v2 only, analyst role required)" },
    { name: "System",     description: "Health, stats and documentation" }
  ],

  paths: {

    // Auth
    "/v1/auth/login": {
      post: {
        tags: ["Auth"], summary: "Login with email + password or API key",
        security: [],
        description: `Authenticates a user. Returns one of three responses:
- \`{ token, user }\` full session JWT (MFA not enabled, API key login)
- \`{ mfaRequired: true, challengeToken }\` — submit TOTP to \`/auth/login/mfa\`
- \`{ mfaSetupRequired: true, token }\` — redirect to \`/mfa-setup\` to enrol

**Rate limit:** 10 attempts / 15 minutes per IP (successful requests excluded).`,
        requestBody: {
          required: true,
          content: { "application/json": { schema: { "$ref": "#/components/schemas/LoginRequest" } } }
        },
        responses: {
          200: { description: "Login result", content: { "application/json": { schema: { "$ref": "#/components/schemas/LoginResponse" } } } },
          401: { description: "Invalid credentials" },
          403: { description: "Account suspended or revoked" },
          429: { description: "Too many login attempts" }
        }
      }
    },

    "/v1/auth/login/mfa": {
      post: {
        tags: ["Auth"], summary: "Complete login with TOTP or backup code",
        security: [],
        description: `Second factor step. Submit the \`challengeToken\` from \`/auth/login\` plus either:
- A 6-digit TOTP code from your authenticator app
- An 8-character backup code (consumed on use)

**Rate limit:** 10 attempts / 5 minutes per IP.`,
        requestBody: {
          required: true,
          content: { "application/json": { schema: {
            type: "object",
            required: ["challengeToken","totpToken"],
            properties: {
              challengeToken: { type: "string", description: "Short-lived JWT from /auth/login (5m expiry)" },
              totpToken:      { type: "string", example: "123456", description: "6-digit TOTP code or 8-character backup code" }
            }
          }}}
        },
        responses: {
          200: { description: "Full session JWT", content: { "application/json": { schema: {
            type: "object",
            properties: {
              token: { type: "string" },
              user:  { "$ref": "#/components/schemas/UserSummary" }
            }
          }}}},
          400: { description: "Missing fields or invalid challenge token" },
          401: { description: "Invalid TOTP or backup code, or challenge expired" },
          429: { description: "Too many MFA attempts" }
        }
      }
    },

    "/v1/auth/forgot-password": {
      post: {
        tags: ["Auth"], summary: "Request a password reset link",
        security: [],
        description: `Sends a reset link to the email if an active account exists.
Always returns \`{ ok: true }\` regardless, prevents email enumeration.
Reset tokens expire after 1 hour and are SHA-256 hashed in the database.

Rate limit: 5 attempts / 15 minutes per IP.`,
        requestBody: {
          required: true,
          content: { "application/json": { schema: {
            type: "object",
            required: ["email"],
            properties: {
              email: { type: "string", format: "email", example: "analyst@company.com" }
            }
          }}}
        },
        responses: {
          200: { description: "Always returns ok — check email", content: { "application/json": { schema: {
            type: "object",
            properties: { ok: { type: "boolean", example: true } }
          }}}},
          400: { description: "Invalid email format" },
          429: { description: "Too many reset attempts" }
        }
      }
    },

    "/v1/auth/reset-password": {
      post: {
        tags: ["Auth"], summary: "Set new password using reset token",
        security: [],
        description: `Sets a new password using the token from the reset email.
The token is consumed on use, request a new one if it expires.
Passwords must be 8–128 characters.

**Rate limit:** 5 attempts / 15 minutes per IP.`,
        requestBody: {
          required: true,
          content: { "application/json": { schema: {
            type: "object",
            required: ["token","password"],
            properties: {
              token:    { type: "string", description: "Reset token from email URL parameter" },
              password: { type: "string", minLength: 8, maxLength: 128, example: "MyNewPass123!" }
            }
          }}}
        },
        responses: {
          200: { description: "Password updated", content: { "application/json": { schema: {
            type: "object",
            properties: {
              ok:      { type: "boolean" },
              message: { type: "string", example: "Password updated — you can now sign in" }
            }
          }}}},
          400: { description: "Invalid/expired token or weak password" },
          429: { description: "Too many reset attempts" }
        }
      }
    },

    "/v1/auth/logout": {
      post: {
        tags: ["Auth"], summary: "Logout (client-side token drop)",
        description: "JWT is stateless, this endpoint signals intent only. The client must delete the token from localStorage.",
        responses: {
          200: { description: "Logged out" }
        }
      }
    },

    "/v1/auth/me": {
      get: {
        tags: ["Auth"], summary: "Get current user from JWT",
        security: [{ BearerAuth: [] }],
        responses: {
          200: { description: "Decoded token payload", content: { "application/json": { schema: { "$ref": "#/components/schemas/UserSummary" } } } },
          401: { description: "Missing or invalid token" }
        }
      }
    },

    // MFA 
    "/v1/mfa/setup": {
      get: {
        tags: ["MFA"], summary: "Generate TOTP secret and QR code",
        security: [{ BearerAuth: [] }],
        description: `Generates a new TOTP secret and returns a QR code data URL for scanning.
The secret is stored temporarily, MFA is **not enabled** until \`/mfa/verify-setup\` succeeds.
Safe to call again if setup is interrupted; overwrites any pending unverified secret.`,
        responses: {
          200: { description: "QR code and secret", content: { "application/json": { schema: { "$ref": "#/components/schemas/MFASetupResponse" } } } },
          400: { description: "MFA is already enabled" },
          401: { description: "Unauthorized" }
        }
      }
    },

    "/v1/mfa/verify-setup": {
      post: {
        tags: ["MFA"], summary: "Confirm TOTP code and enable MFA",
        security: [{ BearerAuth: [] }],
        description: `Verifies the 6-digit code against the pending secret and enables MFA.
Returns 8 single-use backup codes, these are shown exactly once and never stored in plain text.
Save them in a password manager immediately.`,
        requestBody: {
          required: true,
          content: { "application/json": { schema: { "$ref": "#/components/schemas/MFAVerifyRequest" } } }
        },
        responses: {
          200: { description: "MFA enabled + backup codes", content: { "application/json": { schema: { "$ref": "#/components/schemas/MFAVerifyResponse" } } } },
          400: { description: "No setup in progress or MFA already enabled" },
          401: { description: "Invalid TOTP code" }
        }
      }
    },

    "/v1/mfa/disable": {
      post: {
        tags: ["MFA"], summary: "Disable MFA (requires current TOTP code)",
        security: [{ BearerAuth: [] }],
        description: "Disables MFA and clears the secret and all backup codes. Requires a valid current TOTP code to prevent unauthorized disabling.",
        requestBody: {
          required: true,
          content: { "application/json": { schema: { "$ref": "#/components/schemas/MFAVerifyRequest" } } }
        },
        responses: {
          200: { description: "MFA disabled" },
          400: { description: "MFA not enabled or missing code" },
          401: { description: "Invalid TOTP code" }
        }
      }
    },

    "/v1/mfa/status": {
      get: {
        tags: ["MFA"], summary: "Check MFA status for current user",
        security: [{ BearerAuth: [] }],
        responses: {
          200: { description: "MFA status", content: { "application/json": { schema: { "$ref": "#/components/schemas/MFAStatusResponse" } } } },
          401: { description: "Unauthorized" }
        }
      }
    },

    // Keys
    "/v1/keys": {
      get: {
        tags: ["Keys"], summary: "List all API keys (admin)",
        security: [{ BearerAuth: [] }],
        description: "Returns all keys with status, usage, and expiry info. Admin only.",
        parameters: [
          { name: "status", in: "query", schema: { type: "string", enum: ["pending","active","revoked","suspended"] } },
          { name: "role",   in: "query", schema: { type: "string", enum: ["readonly","analyst","admin"] } },
          { name: "limit",  in: "query", schema: { type: "integer", default: 100, maximum: 200 } },
          { name: "offset", in: "query", schema: { type: "integer", default: 0 } }
        ],
        responses: {
          200: { description: "Keys list", content: { "application/json": { schema: {
            type: "object",
            properties: {
              keys:  { type: "array", items: { "$ref": "#/components/schemas/ApiKey" } },
              total: { type: "integer" }
            }
          }}}},
          401: { description: "Unauthorized" },
          403: { description: "Admin role required" }
        }
      }
    },

    "/v1/keys/invite": {
      post: {
        tags: ["Keys"], summary: "Create an invite link (admin)",
        security: [{ BearerAuth: [] }],
        description: `Creates a pending key and sends an activation email to the invitee.
The activation link expires after 7 days. If the invitee doesn't activate in time,
create a new invite, expired invites cannot be reused.`,
        requestBody: {
          required: true,
          content: { "application/json": { schema: { "$ref": "#/components/schemas/InviteRequest" } } }
        },
        responses: {
          201: { description: "Invite created", content: { "application/json": { schema: { "$ref": "#/components/schemas/InviteResponse" } } } },
          400: { description: "Validation error" },
          403: { description: "Admin role required" }
        }
      }
    },

    "/v1/keys/activate/{token}": {
      get: {
        tags: ["Keys"], summary: "Validate invite token",
        security: [],
        description: "Validates the invite token and returns invite metadata for the activation form. Returns 410 if the token has expired.",
        parameters: [{ name: "token", in: "path", required: true, schema: { type: "string" } }],
        responses: {
          200: { description: "Valid invite", content: { "application/json": { schema: {
            type: "object",
            properties: {
              valid:  { type: "boolean" },
              invite: {
                type: "object",
                properties: {
                  name:       { type: "string" },
                  email:      { type: "string", nullable: true },
                  role:       { type: "string" },
                  invited_at: { type: "string" }
                }
              }
            }
          }}}},
          404: { description: "Invalid or already-used token" },
          410: { description: "Invite link has expired — request a new one from admin" }
        }
      },
      post: {
        tags: ["Keys"], summary: "Activate account with invite token",
        security: [],
        description: `Sets email and password, activates the account, and returns the raw API key.
The API key is shown exactly once, it is immediately wiped from the database after this response.
Passwords must be 8–128 characters. The invite token is consumed and cannot be reused.`,
        parameters: [{ name: "token", in: "path", required: true, schema: { type: "string" } }],
        requestBody: {
          required: true,
          content: { "application/json": { schema: {
            type: "object",
            required: ["email","password"],
            properties: {
              email:    { type: "string", format: "email", example: "analyst@company.com" },
              password: { type: "string", minLength: 8, maxLength: 128, example: "MySecurePass123!" }
            }
          }}}
        },
        responses: {
          200: { description: "Activated — save the API key", content: { "application/json": { schema: {
            type: "object",
            properties: {
              message:     { type: "string" },
              key:         { type: "string", description: "Raw API key — shown once only" },
              name:        { type: "string" },
              role:        { type: "string" },
              daily_limit: { type: "integer" }
            }
          }}}},
          400: { description: "Weak password or invalid email" },
          404: { description: "Invalid token" },
          410: { description: "Invite link has expired" }
        }
      }
    },

    "/v1/keys/stats": {
      get: {
        tags: ["Keys"], summary: "Key statistics (admin)",
        security: [{ BearerAuth: [] }],
        responses: {
          200: { description: "Stats including expired invite count", content: { "application/json": { schema: {
            type: "object",
            properties: {
              total:          { type: "integer" },
              active:         { type: "integer" },
              pending:        { type: "integer" },
              suspended:      { type: "integer" },
              revoked:        { type: "integer" },
              expiredInvites: { type: "integer", description: "Pending invites past their 7-day expiry" },
              requestsToday:  { type: "integer" },
              totalRequests:  { type: "integer" }
            }
          }}}}
        }
      }
    },

    "/v1/keys/{id}": {
      get: {
        tags: ["Keys"], summary: "Get key details (admin)",
        security: [{ BearerAuth: [] }],
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        responses: {
          200: { description: "Key details (key value masked)" },
          404: { description: "Key not found" }
        }
      },
      put: {
        tags: ["Keys"], summary: "Update key metadata (admin)",
        security: [{ BearerAuth: [] }],
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        requestBody: {
          content: { "application/json": { schema: {
            type: "object",
            properties: {
              name:       { type: "string" },
              email:      { type: "string" },
              role:       { type: "string", enum: ["readonly","analyst","admin"] },
              dailyLimit: { type: "integer" },
              notes:      { type: "string" }
            }
          }}}
        },
        responses: {
          200: { description: "Updated key" },
          404: { description: "Key not found" }
        }
      },
      delete: {
        tags: ["Keys"], summary: "Permanently delete key (admin)",
        security: [{ BearerAuth: [] }],
        description: "Cannot delete your own admin key.",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        responses: {
          200: { description: "Deleted" },
          400: { description: "Cannot delete your own key" },
          404: { description: "Key not found" }
        }
      }
    },

    "/v1/keys/{id}/revoke": {
      post: {
        tags: ["Keys"], summary: "Revoke key (admin)",
        security: [{ BearerAuth: [] }],
        description: "Cannot revoke your own key.",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        requestBody: {
          content: { "application/json": { schema: {
            type: "object",
            properties: { reason: { type: "string", example: "Left organisation" } }
          }}}
        },
        responses: {
          200: { description: "Revoked" },
          400: { description: "Cannot revoke your own key" },
          404: { description: "Key not found" }
        }
      }
    },

    "/v1/keys/{id}/suspend": {
      post: {
        tags: ["Keys"], summary: "Suspend key (admin)",
        security: [{ BearerAuth: [] }],
        description: "Suspends an active key. Cannot suspend your own key.",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        responses: { 200: { description: "Suspended" }, 400: { description: "Cannot suspend your own key" } }
      }
    },

    "/v1/keys/{id}/reinstate": {
      post: {
        tags: ["Keys"], summary: "Reinstate suspended key (admin)",
        security: [{ BearerAuth: [] }],
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        responses: { 200: { description: "Reinstated" } }
      }
    },

    "/v1/keys/{id}/rotate": {
      post: {
        tags: ["Keys"], summary: "Rotate key — generate new value (admin)",
        security: [{ BearerAuth: [] }],
        description: "Generates a new API key value. The new key is returned once only. Cannot rotate your own key.",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        responses: {
          200: { description: "New key value (shown once)", content: { "application/json": { schema: {
            type: "object",
            properties: {
              message: { type: "string" },
              newKey:  { type: "string", description: "Raw new key — save immediately" },
              name:    { type: "string" }
            }
          }}}},
          400: { description: "Cannot rotate your own key" },
          404: { description: "Key not found or not active" }
        }
      }
    },

    "/v1/keys/{id}/usage": {
      get: {
        tags: ["Keys"], summary: "Get key usage history (admin)",
        security: [{ BearerAuth: [] }],
        parameters: [
          { name: "id",   in: "path",  required: true, schema: { type: "integer" } },
          { name: "days", in: "query", schema: { type: "integer", default: 30, maximum: 90 } }
        ],
        responses: {
          200: { description: "Daily usage log", content: { "application/json": { schema: {
            type: "object",
            properties: {
              key_id: { type: "integer" },
              days:   { type: "integer" },
              usage:  { type: "array", items: {
                type: "object",
                properties: {
                  date:       { type: "string", format: "date" },
                  requests:   { type: "integer" },
                  scores:     { type: "integer" },
                  cache_hits: { type: "integer" },
                  errors:     { type: "integer" }
                }
              }}
            }
          }}}}
        }
      }
    },

    // Health 
    "/health": {
      get: {
        tags: ["System"], summary: "Health check", security: [],
        description: "Returns server status. No authentication required.",
        responses: {
          200: {
            description: "Server is healthy",
            content: { "application/json": { schema: {
              type: "object",
              properties: {
                status:      { type: "string", example: "ok" },
                version:     { type: "string", example: "2.3.0" },
                environment: { type: "string" },
                uptime:      { type: "integer" },
                db:          { type: "string" },
                memoryMB:    { type: "integer" },
                timestamp:   { type: "string", format: "date-time" }
              }
            }}}
          }
        }
      }
    },

    // Stats 
    "/stats": {
      get: {
        tags: ["System"], summary: "Runtime statistics",
        responses: {
          200: { description: "Stats" }
        }
      }
    },

    // Scoring 
    "/score/{ip}": {
  get: {
    tags: ["Scoring"], summary: "Score a single IP",
    description: "Full risk intelligence for an IPv4 or IPv6 address.",
    parameters: [{ name: "ip", in: "path", required: true, schema: { type: "string" }, example: "185.220.101.1" }],
    responses: {
      200: { description: "Score result", content: { "application/json": { schema: { "$ref": "#/components/schemas/ScoreResult" } } } },
      400: { description: "Invalid IP" },
      401: { description: "Missing or invalid API key" },
      429: {
        description: "Either the IP-based rate limiter (30 req/min) or the plan's daily quota was exceeded — check `error` field to distinguish (`rate_limit_exceeded` vs `quota_exceeded`).",
        content: { "application/json": { schema: {
          oneOf: [
            { type: "object", properties: { error: { type: "string", example: "rate_limit_exceeded" }, message: { type: "string" }, retryAfter: { type: "integer" } } },
            { "$ref": "#/components/schemas/QuotaExceeded" }
          ]
        }}}
      }
    }
  }
},

    "/score/batch": {
  post: {
    tags: ["Scoring"], summary: "Batch score up to 50 IPs",
    requestBody: {
      required: true,
      content: { "application/json": { schema: {
        type: "object", required: ["ips"],
        properties: {
          ips: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 50, example: ["8.8.8.8","1.1.1.1"] }
        }
      }}}
    },
    responses: {
      200: { description: "Batch results" },
      429: { "$ref": "#/components/responses/QuotaExceededResponse" }
    }
  }
},

    "/report/{ip}": {
      get: {
        tags: ["Scoring"], summary: "Download PDF threat report",
        parameters: [
          { name: "ip",     in: "path",  required: true, schema: { type: "string" } },
          { name: "cached", in: "query", schema: { type: "boolean", default: true } }
        ],
        responses: {
          200: { description: "PDF file", content: { "application/pdf": { schema: { type: "string", format: "binary" } } } }
        }
      }
    },

    // Intelligence 
    "/whois/{ip}": {
      get: {
        tags: ["Intelligence"], summary: "WHOIS / RDAP deep dive",
        parameters: [{ name: "ip", in: "path", required: true, schema: { type: "string" }, example: "8.8.8.8" }],
        responses: { 200: { description: "WHOIS result" }, 400: { description: "Invalid IP" } }
      }
    },

    "/timeline/{ip}": {
      get: {
        tags: ["Intelligence"], summary: "Score history timeline",
        parameters: [
          { name: "ip",    in: "path",  required: true,  schema: { type: "string" } },
          { name: "limit", in: "query", schema: { type: "integer", default: 50, maximum: 200 } }
        ],
        responses: { 200: { description: "Timeline data" } }
      }
    },

    // Blacklist 
    "/blacklist": {
      get: {
        tags: ["Blacklist"], summary: "List blacklisted IPs",
        parameters: [
          { name: "severity", in: "query", schema: { type: "string", enum: ["CRITICAL","HIGH","MEDIUM","LOW"] } },
          { name: "status",   in: "query", schema: { type: "string", enum: ["active","expired","all"] } },
          { name: "q",        in: "query", schema: { type: "string" } },
          { name: "limit",    in: "query", schema: { type: "integer", default: 200, maximum: 500 } },
          { name: "offset",   in: "query", schema: { type: "integer", default: 0 } }
        ],
        responses: { 200: { description: "Blacklist entries" } }
      },
      post: {
        tags: ["Blacklist"], summary: "Add IP to blacklist",
        requestBody: {
          required: true,
          content: { "application/json": { schema: {
            type: "object", required: ["ip"],
            properties: {
              ip:         { type: "string",  example: "185.220.101.1" },
              severity:   { type: "string",  enum: ["CRITICAL","HIGH","MEDIUM","LOW"], default: "HIGH" },
              category:   { type: "string",  example: "Tor" },
              reason:     { type: "string",  example: "Known Tor exit node" },
              added_by:   { type: "string",  example: "analyst" },
              expires_at: { type: "string",  format: "date-time", nullable: true },
              tags:       { type: "array",   items: { type: "string" } }
            }
          }}}
        },
        responses: {
          201: { description: "Added to blacklist" },
          409: { description: "IP already actively blacklisted" }
        }
      }
    },

    "/blacklist/stats": {
      get: { tags: ["Blacklist"], summary: "Blacklist statistics", responses: { 200: { description: "Stats" } } }
    },

    "/blacklist/export": {
      get: {
        tags: ["Blacklist"], summary: "Export blacklist as firewall rules",
        parameters: [{
          name: "fmt", in: "query",
          schema: { type: "string", enum: ["txt","csv","json","nginx","iptables","cisco","paloalto","windows"], default: "txt" }
        }],
        responses: { 200: { description: "Exported file" } }
      }
    },

    "/blacklist/{id}": {
      put: {
        tags: ["Blacklist"], summary: "Update blacklist entry",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        requestBody: {
          content: { "application/json": { schema: {
            type: "object",
            properties: {
              severity:   { type: "string", enum: ["CRITICAL","HIGH","MEDIUM","LOW"] },
              category:   { type: "string" },
              reason:     { type: "string" },
              expires_at: { type: "string", format: "date-time", nullable: true },
              tags:       { type: "array", items: { type: "string" } }
            }
          }}}
        },
        responses: { 200: { description: "Updated" }, 404: { description: "Not found" } }
      },
      delete: {
        tags: ["Blacklist"], summary: "Delete blacklist entry",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        responses: { 200: { description: "Deleted" }, 404: { description: "Not found" } }
      }
    },

    "/blacklist/bulk": {
      delete: {
        tags: ["Blacklist"], summary: "Bulk delete blacklist entries",
        requestBody: {
          required: true,
          content: { "application/json": { schema: {
            type: "object", required: ["ids"],
            properties: { ids: { type: "array", items: { type: "integer" }, minItems: 1, example: [1,2,3] } }
          }}}
        },
        responses: { 200: { description: "Deleted count" } }
      }
    },

    // Cases 
    "/cases": {
      get: {
        tags: ["Cases"], summary: "List investigation cases",
        parameters: [
          { name: "status",   in: "query", schema: { type: "string", enum: ["Open","Investigating","Contained","Resolved","Closed"] } },
          { name: "severity", in: "query", schema: { type: "string", enum: ["CRITICAL","HIGH","MEDIUM","LOW"] } },
          { name: "q",        in: "query", schema: { type: "string" } },
          { name: "limit",    in: "query", schema: { type: "integer", default: 100 } },
          { name: "offset",   in: "query", schema: { type: "integer", default: 0 } }
        ],
        responses: { 200: { description: "Cases list" } }
      },
      post: {
        tags: ["Cases"], summary: "Create investigation case",
        requestBody: {
          required: true,
          content: { "application/json": { schema: {
            type: "object", required: ["title"],
            properties: {
              title:       { type: "string",  example: "Tor Exit Node Campaign" },
              description: { type: "string" },
              severity:    { type: "string",  enum: ["CRITICAL","HIGH","MEDIUM","LOW"], default: "MEDIUM" },
              status:      { type: "string",  enum: ["Open","Investigating","Contained","Resolved","Closed"], default: "Open" },
              assigned_to: { type: "string",  example: "analyst" },
              tags:        { type: "array",   items: { type: "string" } }
            }
          }}}
        },
        responses: { 201: { description: "Case created" } }
      }
    },

    "/cases/stats": {
      get: { tags: ["Cases"], summary: "Case statistics", responses: { 200: { description: "Stats" } } }
    },

    "/cases/{id}": {
      get: {
        tags: ["Cases"], summary: "Get full case details",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        responses: { 200: { description: "Full case" }, 404: { description: "Not found" } }
      },
      put: {
        tags: ["Cases"], summary: "Update case",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        requestBody: { content: { "application/json": { schema: { type: "object" } } } },
        responses: { 200: { description: "Updated" }, 404: { description: "Not found" } }
      },
      delete: {
        tags: ["Cases"], summary: "Delete case (cascade)",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        responses: { 200: { description: "Deleted" } }
      }
    },

    "/cases/{id}/ips": {
      post: {
        tags: ["Cases"], summary: "Attach IP to case",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        requestBody: {
          required: true,
          content: { "application/json": { schema: {
            type: "object", required: ["ip"],
            properties: {
              ip:         { type: "string", example: "185.220.101.1" },
              score:      { type: "integer", nullable: true },
              risk_level: { type: "string",  nullable: true },
              note:       { type: "string" }
            }
          }}}
        },
        responses: { 201: { description: "IP attached" }, 409: { description: "Already attached" } }
      }
    },

    "/cases/{id}/ips/{ipId}": {
      delete: {
        tags: ["Cases"], summary: "Remove IP from case",
        parameters: [
          { name: "id",   in: "path", required: true, schema: { type: "integer" } },
          { name: "ipId", in: "path", required: true, schema: { type: "integer" } }
        ],
        responses: { 200: { description: "Removed" } }
      }
    },

    "/cases/{id}/notes": {
      post: {
        tags: ["Cases"], summary: "Add investigation note",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        requestBody: {
          required: true,
          content: { "application/json": { schema: {
            type: "object", required: ["note"],
            properties: {
              note:   { type: "string", maxLength: 2000 },
              author: { type: "string", default: "analyst" }
            }
          }}}
        },
        responses: { 201: { description: "Note added" } }
      }
    },

    "/cases/{id}/notes/{noteId}": {
      delete: {
        tags: ["Cases"], summary: "Delete note",
        parameters: [
          { name: "id",     in: "path", required: true, schema: { type: "integer" } },
          { name: "noteId", in: "path", required: true, schema: { type: "integer" } }
        ],
        responses: { 200: { description: "Deleted" } }
      }
    },

    // Watchlist 
    "/watchlist": {
  get: {
    tags: ["Watchlist"], summary: "Get all watched IPs",
    responses: { 200: { description: "Watchlist" } }
  },
  post: {
    tags: ["Watchlist"], summary: "Add IP to watchlist",
    requestBody: {
      required: true,
      content: { "application/json": { schema: {
        type: "object", required: ["ip"],
        properties: {
          ip:            { type: "string" },
          label:         { type: "string" },
          threshold:     { type: "integer", default: 30 },
          alertOnChange: { type: "boolean", default: true }
        }
      }}}
    },
    responses: {
      201: { description: "Added" },
      400: { description: "Invalid or full" },
      403: { "$ref": "#/components/responses/FeatureNotAvailableResponse" },
      429: { "$ref": "#/components/responses/QuotaExceededResponse" }
    }
  }
},

    "/watchlist/{ip}": {
      delete: {
        tags: ["Watchlist"], summary: "Remove IP from watchlist",
        parameters: [{ name: "ip", in: "path", required: true, schema: { type: "string" } }],
        responses: { 200: { description: "Removed" }, 404: { description: "Not found" } }
      }
    },

    "/watchlist/poll": {
      post: {
        tags: ["Watchlist"], summary: "Trigger immediate re-score of all watched IPs",
        responses: { 200: { description: "Poll triggered" } }
      }
    },

    // Audit 
    "/audit": {
      get: {
        tags: ["Audit"], summary: "Get audit log",
        parameters: [
          { name: "limit",  in: "query", schema: { type: "integer", default: 50, maximum: 200 } },
          { name: "offset", in: "query", schema: { type: "integer", default: 0 } }
        ],
        responses: { 200: { description: "Audit log" } }
      }
    },

    "/audit/search": {
      get: {
        tags: ["Audit"], summary: "Search and filter audit log",
        parameters: [
          { name: "q",          in: "query", schema: { type: "string" } },
          { name: "risk",       in: "query", schema: { type: "string", enum: ["CRITICAL","HIGH","MEDIUM","LOW"] } },
          { name: "minScore",   in: "query", schema: { type: "integer" } },
          { name: "maxScore",   in: "query", schema: { type: "integer" } },
          { name: "proxy",      in: "query", schema: { type: "boolean" } },
          { name: "tor",        in: "query", schema: { type: "boolean" } },
          { name: "datacenter", in: "query", schema: { type: "boolean" } },
          { name: "from",       in: "query", schema: { type: "string", format: "date-time" } },
          { name: "to",         in: "query", schema: { type: "string", format: "date-time" } },
          { name: "sort",       in: "query", schema: { type: "string", enum: ["date_desc","date_asc","score_desc","score_asc"], default: "date_desc" } },
          { name: "limit",      in: "query", schema: { type: "integer", default: 50 } },
          { name: "offset",     in: "query", schema: { type: "integer", default: 0 } }
        ],
        responses: { 200: { description: "Filtered results" } }
      }
    },

    "/audit/threats": {
      get: {
        tags: ["Audit"], summary: "Top CRITICAL/HIGH IPs",
        parameters: [{ name: "limit", in: "query", schema: { type: "integer", default: 20, maximum: 100 } }],
        responses: { 200: { description: "Top threats" } }
      }
    },

    // Scanning (v2 only)
    "/v2/scan/{ip}": {
      post: {
        tags: ["Scanning"], summary: "Launch an active scan (nmap + nuclei)",
        description: `Enqueues an active reconnaissance scan against the target IP. This is not a
passive lookup;it sends real packets and HTTP/TLS probes to the target.

Runs two scanners in parallel as a background job:
- nmap: port scan (1–10000), service/version detection, default safe scripts, CVE matching via vulners NSE
- nuclei: network, SSL/TLS and HTTP templates tagged \`network,ssl,tls,misconfig,exposure,default-login,takeover,tech\`. Destructive tags (\`fuzzing\`,\`dos\`,\`code\`,\`intrusive\`) are always excluded.

Requirements:
- Caller's API key role must be \`analyst\` or \`admin\` — \`readonly\` keys get 403
- \`consent: true\` must be present in the request body
- Target IP must be public, RFC-1918, loopback and link-local ranges are rejected

If a scan is already queued or running for this IP, returns 409 with the existing \`jobId\`
instead of starting a duplicate.

Rate limit: 5 requests / 10 minutes per key.`,
        security: [{ ApiKeyAuth: [] }],
        parameters: [
          { name: "ip", in: "path", required: true, schema: { type: "string" }, example: "45.33.32.156" }
        ],
        requestBody: {
          required: true,
          content: { "application/json": { schema: { "$ref": "#/components/schemas/ScanStartRequest" } } }
        },
        responses: {
          202: { description: "Scan enqueued", content: { "application/json": { schema: { "$ref": "#/components/schemas/ScanStartResponse" } } } },
          400: { description: "Invalid IP, private/reserved IP range, or missing consent" },
          403: { description: "This feature isn't included on the caller's current plan." },
          409: { description: "A scan is already in progress for this IP", content: { "application/json": { schema: {
            type: "object",
            properties: {
              error:  { type: "string", example: "A scan is already in progress for this IP" },
              jobId:  { type: "string", format: "uuid" },
              status: { type: "string", enum: ["queued","running"] }
            }
          }}}},
           429: {
        description: "Either the per-key rate limiter (5 req/10min) or the plan's daily active-scan quota was exceeded.",
        content: { "application/json": { schema: {
          oneOf: [
            { type: "object", properties: { error: { type: "string", example: "rate_limit_exceeded" }, message: { type: "string" }, retryAfter: { type: "integer" } } },
            { "$ref": "#/components/schemas/QuotaExceeded" }
          ]
        }}}
      },
        }
      }
    },

    "/v2/scan/job/{jobId}": {
      get: {
        tags: ["Scanning"], summary: "Poll scan job status and summarised results",
        description: `Poll this endpoint every few seconds until \`status\` is \`done\` or \`failed\`.
Returns summarised findings only, call \`GET /v2/scan/job/{jobId}/raw/{scanner}\` for the full
unfiltered output of either scanner.`,
        security: [{ ApiKeyAuth: [] }],
        parameters: [
          { name: "jobId", in: "path", required: true, schema: { type: "string", format: "uuid" } }
        ],
        responses: {
          200: { description: "Job status and summarised results", content: { "application/json": { schema: { "$ref": "#/components/schemas/ScanJob" } } } },
          404: { description: "Job not found" }
        }
      }
    },

    "/v2/scan/job/{jobId}/raw/{scanner}": {
      get: {
        tags: ["Scanning"], summary: "Get full raw output for a scanner (analyst only)",
        description: `Returns the complete unfiltered output for either scanner, full nmap port/CVE
data or the complete nuclei findings list. This payload can be large; only fetch it when you need
to inspect a specific finding in depth.`,
        security: [{ ApiKeyAuth: [] }],
        parameters: [
          { name: "jobId",   in: "path", required: true, schema: { type: "string", format: "uuid" } },
          { name: "scanner", in: "path", required: true, schema: { type: "string", enum: ["nmap","nuclei"] } }
        ],
        responses: {
          200: { description: "Full raw scanner output", content: { "application/json": { schema: { "$ref": "#/components/schemas/ScanRawResponse" } } } },
          400: { description: "scanner must be nmap or nuclei" },
          403: { description: "Analyst role or higher required" },
          404: { description: "Job not found or scanner has no result yet" }
        }
      }
    },

    "/v2/scan/history/{ip}": {
      get: {
        tags: ["Scanning"], summary: "Get the 5 most recent scans for an IP",
        security: [{ ApiKeyAuth: [] }],
        parameters: [
          { name: "ip", in: "path", required: true, schema: { type: "string" }, example: "45.33.32.156" }
        ],
        responses: {
          200: { description: "Recent scan history", content: { "application/json": { schema: {
            type: "object",
            properties: {
              ip:    { type: "string" },
              scans: { type: "array", items: { "$ref": "#/components/schemas/ScanHistoryEntry" } }
            }
          }}}},
          400: { description: "Invalid IP" }
        }
      }
    },

    // SIEM 
    "/siem/status": {
      get: { tags: ["System"], summary: "SIEM webhook configuration status", responses: { 200: { description: "SIEM status" } } }
    },

    "/siem/test": {
      post: {
        tags: ["System"], summary: "Send test event to SIEM",
        responses: { 200: { description: "Test result" } }
      }
    }
  }
};

module.exports = spec;