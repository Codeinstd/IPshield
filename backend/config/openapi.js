
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

## Authentication
All endpoints except \`/api/health\` and \`/api/docs\` require the \`x-api-key\` header.

\`\`\`
x-api-key: your_api_key_here
\`\`\`

## Rate Limits
| Endpoint | Limit |
|----------|-------|
| Global   | 200 requests / 15 minutes |
| /score   | 30 requests / minute |
| /whois   | 20 requests / minute |
| /report  | 10 requests / minute |
    `,
    version: "2.2.0",
    contact: { name: "IPShield", url: "https://ipshield-nk0w.onrender.com" }
  },

  servers: [
    { url: "/api", description: "Current server" },
    { url: "https://ipshield.live/", description: "Production (Render)" }
  ],

  components: {
    securitySchemes: {
      ApiKeyAuth: {
        type: "apiKey", in: "header", name: "x-api-key",
        description: "Your IPShield API key. Set via IPSHIELD_API_KEY env var on the server."
      }
    },
    schemas: {

      // ── Shared 
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
          country:  { type: "string", example: "Germany" },
          region:   { type: "string", example: "Bavaria" },
          city:     { type: "string", example: "Munich" },
          timezone: { type: "string", example: "Europe/Berlin" },
          lat:      { type: "number", example: 48.1374 },
          lon:      { type: "number", example: 11.5755 }
        }
      },

      NetworkInfo: {
        type: "object",
        properties: {
          isp:       { type: "string", example: "Deutsche Telekom AG" },
          asn:       { type: "string", example: "AS3320 Deutsche Telekom AG" },
          type:      { type: "string", enum: ["hosting","residential"], example: "hosting" },
          hostnames: { type: "array", items: { type: "string" } }
        }
      },

      RDNSInfo: {
        type: "object",
        properties: {
          hostnames: { type: "array", items: { type: "string" }, example: ["mail.example.com"] },
          primary:   { type: "string", nullable: true, example: "mail.example.com" },
          fcrdns:    { type: "boolean", nullable: true, description: "Forward-confirmed reverse DNS check result" },
          private:   { type: "boolean", description: "True if IP is RFC1918 private" }
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
            type: "object",
            nullable: true,
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
          ip:           { type: "string", example: "185.220.101.1" },
          score:        { type: "integer", minimum: 0, maximum: 100, example: 95 },
          baseScore:    { type: "integer" },
          scoreBoost:   { type: "integer" },
          riskLevel:    { type: "string", enum: ["CRITICAL","HIGH","MEDIUM","LOW"] },
          action:       { type: "string", enum: ["BLOCK","CHALLENGE","MONITOR","ALLOW"] },
          blacklisted: {
            type: "object", nullable: true,
            description: "Present if the IP is in the internal blacklist",
            properties: {
              id:         { type: "integer" },
              severity:   { type: "string" },
              category:   { type: "string", nullable: true },
              reason:     { type: "string", nullable: true },
              added_by:   { type: "string", nullable: true },
              added_at:   { type: "string" },
              expires_at: { type: "string", nullable: true },
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

      // ── Blacklist 
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
          expired:    { type: "boolean", description: "True if expires_at is in the past" }
        }
      },

      BlacklistStats: {
        type: "object",
        properties: {
          total:      { type: "integer" },
          active:     { type: "integer" },
          expired:    { type: "integer" },
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

      // ── Cases 
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
      }
    }
  },

  security: [{ ApiKeyAuth: [] }],

  tags: [
    { name: "Scoring",    description: "IP risk scoring — single and batch" },
    { name: "Intelligence", description: "Deep intelligence lookups (WHOIS, reverse DNS)" },
    { name: "Blacklist",  description: "Internal IP blocklist management" },
    { name: "Cases",      description: "Investigation case management" },
    { name: "Watchlist",  description: "IP monitoring and alerting" },
    { name: "Audit",      description: "Scoring history and search" },
    { name: "System",     description: "Health, stats and documentation" }
  ],

  paths: {

    // ── Health 
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
                version:     { type: "string", example: "2.2.0" },
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

    // ── Stats 
    "/stats": {
      get: {
        tags: ["System"], summary: "Runtime statistics",
        description: "Returns risk distribution, feed status, DB and memory info.",
        responses: {
          200: {
            description: "Stats",
            content: { "application/json": { schema: {
              type: "object",
              properties: {
                riskDistribution: { type: "object" },
                totalScored:      { type: "integer" },
                cacheSize:        { type: "integer" },
                dbAvailable:      { type: "boolean" },
                uptime:           { type: "integer" },
                memoryMB:         { type: "integer" },
                threatFeeds:      { type: "object" }
              }
            }}}
          }
        }
      }
    },

    // ── Scoring 
    "/score/{ip}": {
      get: {
        tags: ["Scoring"], summary: "Score a single IP",
        description: "Full risk intelligence for an IPv4 or IPv6 address. Checks AbuseIPDB, Shodan, VirusTotal, threat feeds, WHOIS, rDNS, and internal blacklist.",
        parameters: [{
          name: "ip", in: "path", required: true,
          schema: { type: "string" }, example: "185.220.101.1"
        }],
        responses: {
          200: { description: "Score result", content: { "application/json": { schema: { "$ref": "#/components/schemas/ScoreResult" } } } },
          400: { description: "Invalid IP", content: { "application/json": { schema: { "$ref": "#/components/schemas/Error" } } } },
          401: { description: "Missing or invalid API key" },
          429: { description: "Rate limit exceeded" }
        }
      }
    },

    "/score/batch": {
      post: {
        tags: ["Scoring"], summary: "Batch score up to 50 IPs",
        description: "Score multiple IPs in parallel. Maximum 50 per request.",
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
          200: { description: "Batch results", content: { "application/json": { schema: {
            type: "object",
            properties: {
              total:   { type: "integer" },
              scored:  { type: "integer" },
              failed:  { type: "integer" },
              results: { type: "array", items: { "$ref": "#/components/schemas/ScoreResult" } }
            }
          }}}}
        }
      }
    },

    "/report/{ip}": {
      get: {
        tags: ["Scoring"], summary: "Download PDF threat report",
        description: "Generates and streams a PDF threat intelligence report for the given IP.",
        parameters: [
          { name: "ip",     in: "path",  required: true, schema: { type: "string" } },
          { name: "cached", in: "query", schema: { type: "boolean", default: true }, description: "Use cached score if available" }
        ],
        responses: {
          200: { description: "PDF file", content: { "application/pdf": { schema: { type: "string", format: "binary" } } } },
          400: { description: "Invalid IP" }
        }
      }
    },

    // ── Intelligence 
    "/whois/{ip}": {
      get: {
        tags: ["Intelligence"], summary: "WHOIS / RDAP deep dive",
        description: "Full WHOIS registration data via RDAP. Tries ARIN → RIPE → APNIC. Includes risk signals for young registrations and missing abuse contacts.",
        parameters: [{ name: "ip", in: "path", required: true, schema: { type: "string" }, example: "8.8.8.8" }],
        responses: {
          200: { description: "WHOIS result" },
          400: { description: "Invalid IP" }
        }
      }
    },

    "/timeline/{ip}": {
      get: {
        tags: ["Intelligence"], summary: "Score history timeline",
        description: "Historical scoring data for a specific IP from the database.",
        parameters: [
          { name: "ip",    in: "path",  required: true, schema: { type: "string" } },
          { name: "limit", in: "query", schema: { type: "integer", default: 50, maximum: 200 } }
        ],
        responses: {
          200: { description: "Timeline data", content: { "application/json": { schema: {
            type: "object",
            properties: {
              ip:      { type: "string" },
              total:   { type: "integer" },
              history: { type: "array" },
              stats: {
                type: "object",
                properties: {
                  min:    { type: "integer" },
                  max:    { type: "integer" },
                  avg:    { type: "integer" },
                  latest: { type: "integer" },
                  trend:  { type: "string", enum: ["increasing","decreasing","stable"] },
                  change: { type: "integer" }
                }
              }
            }
          }}}}
        }
      }
    },

    // ── Blacklist 
    "/blacklist": {
      get: {
        tags: ["Blacklist"], summary: "List blacklisted IPs",
        description: "Returns the internal blacklist with optional filters. Active entries are IPs where `expires_at` is null or in the future.",
        parameters: [
          { name: "severity", in: "query", schema: { type: "string", enum: ["CRITICAL","HIGH","MEDIUM","LOW"] } },
          { name: "status",   in: "query", schema: { type: "string", enum: ["active","expired","all"] }, description: "Default: active" },
          { name: "q",        in: "query", schema: { type: "string" }, description: "Search IP, reason, or category" },
          { name: "limit",    in: "query", schema: { type: "integer", default: 200, maximum: 500 } },
          { name: "offset",   in: "query", schema: { type: "integer", default: 0 } }
        ],
        responses: {
          200: { description: "Blacklist entries", content: { "application/json": { schema: {
            type: "object",
            properties: {
              total:   { type: "integer" },
              entries: { type: "array", items: { "$ref": "#/components/schemas/BlacklistEntry" } },
              stats:   { "$ref": "#/components/schemas/BlacklistStats" }
            }
          }}}}
        }
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
          201: { description: "Added to blacklist", content: { "application/json": { schema: {
            type: "object",
            properties: {
              message: { type: "string" },
              entry:   { "$ref": "#/components/schemas/BlacklistEntry" }
            }
          }}}},
          409: { description: "IP already actively blacklisted" },
          400: { description: "Validation error" }
        }
      }
    },

    "/blacklist/stats": {
      get: {
        tags: ["Blacklist"], summary: "Blacklist statistics",
        responses: {
          200: { description: "Stats", content: { "application/json": { schema: { "$ref": "#/components/schemas/BlacklistStats" } } } }
        }
      }
    },

    "/blacklist/export": {
      get: {
        tags: ["Blacklist"], summary: "Export blacklist as firewall rules",
        description: "Export all active blacklisted IPs in various formats for direct use in firewalls and web servers.",
        parameters: [{
          name: "fmt", in: "query",
          schema: { type: "string", enum: ["txt","csv","json","nginx","iptables","cisco","paloalto","windows"], default: "txt" },
          description: "Export format"
        }],
        responses: {
          200: { description: "Exported file (content type depends on format)" }
        }
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
        responses: {
          200: { description: "Updated entry" },
          404: { description: "Entry not found" }
        }
      },
      delete: {
        tags: ["Blacklist"], summary: "Delete blacklist entry",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        responses: {
          200: { description: "Deleted" },
          404: { description: "Entry not found" }
        }
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
        responses: {
          200: { description: "Deleted count", content: { "application/json": { schema: {
            type: "object",
            properties: { message: { type: "string" }, count: { type: "integer" } }
          }}}}
        }
      }
    },

    // ── Cases 
    "/cases": {
      get: {
        tags: ["Cases"], summary: "List investigation cases",
        description: "Returns all cases with IP and note counts. Supports filtering by status, severity and search.",
        parameters: [
          { name: "status",   in: "query", schema: { type: "string", enum: ["Open","Investigating","Contained","Resolved","Closed"] } },
          { name: "severity", in: "query", schema: { type: "string", enum: ["CRITICAL","HIGH","MEDIUM","LOW"] } },
          { name: "q",        in: "query", schema: { type: "string" }, description: "Search title or description" },
          { name: "limit",    in: "query", schema: { type: "integer", default: 100, maximum: 200 } },
          { name: "offset",   in: "query", schema: { type: "integer", default: 0 } }
        ],
        responses: {
          200: { description: "Cases list", content: { "application/json": { schema: {
            type: "object",
            properties: {
              total: { type: "integer" },
              cases: { type: "array", items: { "$ref": "#/components/schemas/Case" } }
            }
          }}}}
        }
      },
      post: {
        tags: ["Cases"], summary: "Create investigation case",
        requestBody: {
          required: true,
          content: { "application/json": { schema: {
            type: "object", required: ["title"],
            properties: {
              title:       { type: "string",  example: "Tor Exit Node Campaign — May 2026" },
              description: { type: "string",  example: "Multiple Tor exit nodes scanning our infrastructure" },
              severity:    { type: "string",  enum: ["CRITICAL","HIGH","MEDIUM","LOW"], default: "MEDIUM" },
              status:      { type: "string",  enum: ["Open","Investigating","Contained","Resolved","Closed"], default: "Open" },
              assigned_to: { type: "string",  example: "analyst" },
              tags:        { type: "array",   items: { type: "string" }, example: ["tor","scanner"] }
            }
          }}}
        },
        responses: {
          201: { description: "Case created", content: { "application/json": { schema: { "$ref": "#/components/schemas/Case" } } } },
          400: { description: "Validation error" }
        }
      }
    },

    "/cases/stats": {
      get: {
        tags: ["Cases"], summary: "Case statistics",
        responses: {
          200: { description: "Stats", content: { "application/json": { schema: { "$ref": "#/components/schemas/CaseStats" } } } }
        }
      }
    },

    "/cases/{id}": {
      get: {
        tags: ["Cases"], summary: "Get case with full details",
        description: "Returns the case including all attached IPs and investigation notes.",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" }, example: 1 }],
        responses: {
          200: { description: "Full case", content: { "application/json": { schema: { "$ref": "#/components/schemas/Case" } } } },
          404: { description: "Case not found" }
        }
      },
      put: {
        tags: ["Cases"], summary: "Update case",
        description: "Update case metadata. Setting status to `Closed` or `Resolved` automatically sets `closed_at`.",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        requestBody: {
          content: { "application/json": { schema: {
            type: "object",
            properties: {
              title:       { type: "string" },
              description: { type: "string" },
              severity:    { type: "string", enum: ["CRITICAL","HIGH","MEDIUM","LOW"] },
              status:      { type: "string", enum: ["Open","Investigating","Contained","Resolved","Closed"] },
              assigned_to: { type: "string" },
              tags:        { type: "array", items: { type: "string" } }
            }
          }}}
        },
        responses: {
          200: { description: "Updated case" },
          404: { description: "Case not found" }
        }
      },
      delete: {
        tags: ["Cases"], summary: "Delete case",
        description: "Deletes the case and all associated IPs and notes (cascade).",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        responses: {
          200: { description: "Deleted" },
          404: { description: "Case not found" }
        }
      }
    },

    "/cases/{id}/ips": {
      post: {
        tags: ["Cases"], summary: "Attach IP to case",
        description: "Attaches an IP address to the case. Optionally includes the current score and risk level.",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        requestBody: {
          required: true,
          content: { "application/json": { schema: {
            type: "object", required: ["ip"],
            properties: {
              ip:         { type: "string", example: "185.220.101.1" },
              score:      { type: "integer", minimum: 0, maximum: 100, nullable: true },
              risk_level: { type: "string", enum: ["CRITICAL","HIGH","MEDIUM","LOW"], nullable: true },
              note:       { type: "string", example: "Confirmed Tor exit — Shodan verified" }
            }
          }}}
        },
        responses: {
          201: { description: "IP attached" },
          409: { description: "IP already attached to this case" },
          400: { description: "Invalid IP" }
        }
      }
    },

    "/cases/{id}/ips/{ipId}": {
      delete: {
        tags: ["Cases"], summary: "Remove IP from case",
        parameters: [
          { name: "id",   in: "path", required: true, schema: { type: "integer" } },
          { name: "ipId", in: "path", required: true, schema: { type: "integer" } }
        ],
        responses: { 200: { description: "IP removed" } }
      }
    },

    "/cases/{id}/notes": {
      post: {
        tags: ["Cases"], summary: "Add investigation note",
        description: "Adds a timestamped analyst note to the case.",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer" } }],
        requestBody: {
          required: true,
          content: { "application/json": { schema: {
            type: "object", required: ["note"],
            properties: {
              note:   { type: "string", maxLength: 2000, example: "IP confirmed as active C2 node based on Shodan tags and OTX pulses." },
              author: { type: "string", default: "analyst", example: "analyst" }
            }
          }}}
        },
        responses: {
          201: { description: "Note added", content: { "application/json": { schema: { "$ref": "#/components/schemas/CaseNote" } } } },
          400: { description: "Empty note" }
        }
      }
    },

    "/cases/{id}/notes/{noteId}": {
      delete: {
        tags: ["Cases"], summary: "Delete note",
        parameters: [
          { name: "id",     in: "path", required: true, schema: { type: "integer" } },
          { name: "noteId", in: "path", required: true, schema: { type: "integer" } }
        ],
        responses: { 200: { description: "Note deleted" } }
      }
    },

    // ── Watchlist 
    "/watchlist": {
      get: {
        tags: ["Watchlist"], summary: "Get all watched IPs",
        responses: {
          200: { description: "Watchlist", content: { "application/json": { schema: {
            type: "object",
            properties: {
              total:     { type: "integer" },
              monitor:   { type: "object" },
              watchlist: { type: "array", items: { "$ref": "#/components/schemas/WatchlistEntry" } }
            }
          }}}}
        }
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
              threshold:     { type: "integer", minimum: 0, maximum: 100, default: 30 },
              alertOnChange: { type: "boolean", default: true }
            }
          }}}
        },
        responses: {
          201: { description: "Added to watchlist" },
          400: { description: "Invalid IP or watchlist full" }
        }
      }
    },

    "/watchlist/{ip}": {
      delete: {
        tags: ["Watchlist"], summary: "Remove IP from watchlist",
        parameters: [{ name: "ip", in: "path", required: true, schema: { type: "string" } }],
        responses: { 200: { description: "Removed" }, 404: { description: "Not in watchlist" } }
      }
    },

    "/watchlist/poll": {
      post: {
        tags: ["Watchlist"], summary: "Trigger immediate re-score of all watched IPs",
        responses: { 200: { description: "Poll triggered (async)" } }
      }
    },

    // ── Audit 
    "/audit": {
      get: {
        tags: ["Audit"], summary: "Get audit log",
        parameters: [
          { name: "limit",  in: "query", schema: { type: "integer", default: 50, maximum: 200 } },
          { name: "offset", in: "query", schema: { type: "integer", default: 0 } }
        ],
        responses: {
          200: { description: "Audit log", content: { "application/json": { schema: {
            type: "object",
            properties: {
              total:   { type: "integer" },
              hasMore: { type: "boolean" },
              entries: { type: "array" }
            }
          }}}}
        }
      }
    },

    "/audit/search": {
      get: {
        tags: ["Audit"], summary: "Search and filter audit log",
        parameters: [
          { name: "q",          in: "query", schema: { type: "string" },                                            description: "Search IP, country, ISP" },
          { name: "risk",       in: "query", schema: { type: "string", enum: ["CRITICAL","HIGH","MEDIUM","LOW"] } },
          { name: "minScore",   in: "query", schema: { type: "integer", minimum: 0, maximum: 100 } },
          { name: "maxScore",   in: "query", schema: { type: "integer", minimum: 0, maximum: 100 } },
          { name: "proxy",      in: "query", schema: { type: "boolean" } },
          { name: "tor",        in: "query", schema: { type: "boolean" } },
          { name: "datacenter", in: "query", schema: { type: "boolean" } },
          { name: "from",       in: "query", schema: { type: "string", format: "date-time" } },
          { name: "to",         in: "query", schema: { type: "string", format: "date-time" } },
          { name: "sort",       in: "query", schema: { type: "string", enum: ["date_desc","date_asc","score_desc","score_asc"], default: "date_desc" } },
          { name: "limit",      in: "query", schema: { type: "integer", default: 50, maximum: 200 } },
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

    // ── SIEM 
    "/siem/status": {
      get: {
        tags: ["System"], summary: "SIEM webhook configuration status",
        responses: { 200: { description: "SIEM status" } }
      }
    },

    "/siem/test": {
      post: {
        tags: ["System"], summary: "Send test event to SIEM",
        description: "Sends a mock CRITICAL IP event to the configured SIEM webhook to verify connectivity.",
        responses: {
          200: { description: "Test result", content: { "application/json": { schema: {
            type: "object",
            properties: {
              success: { type: "boolean" },
              message: { type: "string" },
              reason:  { type: "string", nullable: true }
            }
          }}}}
        }
      }
    }
  }
};

module.exports = spec;