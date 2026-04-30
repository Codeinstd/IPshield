
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
- **Geo** — country, city, ISP, ASN via ip-api.com

## Authentication
All endpoints except \`/api/health\` require the \`x-api-key\` header.

## Rate Limits
- Global: 200 requests per 15 minutes
- Score: 30 requests per minute
- WHOIS: 20 requests per minute
    `,
    version:     "2.2.0",
    contact: {
      name:  "IPShield",
      url:   "https://ipshield.live/"
    }
  },

  servers: [
    { url: "/api", description: "Current server" },
    { url: "https://ipshield.live/", description: "Production (Render)" }
  ],

  components: {
    securitySchemes: {
      ApiKeyAuth: {
        type: "apiKey",
        in:   "header",
        name: "x-api-key",
        description: "Your IPShield API key. Set via IPSHIELD_API_KEY env var on the server."
      }
    },

    schemas: {
      GeoInfo: {
        type: "object",
        properties: {
          country:  { type:"string", example:"United States" },
          region:   { type:"string", example:"California" },
          city:     { type:"string", example:"San Francisco" },
          timezone: { type:"string", example:"America/Los_Angeles" },
          lat:      { type:"number", example:37.7749 },
          lon:      { type:"number", example:-122.4194 }
        }
      },

      NetworkInfo: {
        type: "object",
        properties: {
          isp:       { type:"string", example:"Cloudflare, Inc." },
          asn:       { type:"string", example:"AS13335 Cloudflare, Inc." },
          type:      { type:"string", enum:["hosting","residential"], example:"hosting" },
          hostnames: { type:"array", items:{ type:"string" }, example:["one.one.one.one"] }
        }
      },

      IntelligenceInfo: {
        type: "object",
        properties: {
          isDatacenter: { type:"boolean" },
          isProxy:      { type:"boolean" },
          isTor:        { type:"boolean" },
          velocity:     { type:"string", enum:["LOW","MEDIUM","HIGH"] },
          openPorts:    { type:"array", items:{ type:"integer" }, example:[80,443,22] },
          vulns:        { type:"array", items:{ type:"string" }, example:["CVE-2021-44228"] },
          shodanTags:   { type:"array", items:{ type:"string" }, example:["scanner","c2"] },
          virusTotal: {
            type: "object",
            properties: {
              malicious:  { type:"integer" },
              suspicious: { type:"integer" },
              harmless:   { type:"integer" },
              total:      { type:"integer" }
            }
          }
        }
      },

      ThreatFeedInfo: {
        type: "object",
        properties: {
          feodo:           { type:"boolean", description:"Listed on Feodo Tracker C2 blocklist" },
          spamhaus:        { type:"boolean", description:"Listed on Spamhaus DROP list" },
          emergingThreats: { type:"boolean", description:"Listed on Emerging Threats compromised IPs" },
          otx: {
            type: "object",
            properties: {
              pulseCount:  { type:"integer" },
              pulseNames:  { type:"array", items:{ type:"string" } },
              malwareCount:{ type:"integer" },
              tags:        { type:"array", items:{ type:"string" } }
            }
          }
        }
      },

      Signal: {
        type: "object",
        properties: {
          category: { type:"string", example:"ABUSE" },
          detail:   { type:"string", example:"Confidence score: 95/100 · 42 reports" },
          severity: { type:"string", enum:["critical","high","medium","low","info"] }
        }
      },

      ScoreResult: {
        type: "object",
        properties: {
          ip:          { type:"string", example:"185.220.101.1" },
          score:       { type:"integer", minimum:0, maximum:100, example:95 },
          baseScore:   { type:"integer", description:"Raw AbuseIPDB score before feed boost" },
          scoreBoost:  { type:"integer", description:"Additional score from threat feed hits" },
          riskLevel:   { type:"string", enum:["CRITICAL","HIGH","MEDIUM","LOW"] },
          action:      { type:"string", enum:["BLOCK","CHALLENGE","MONITOR","ALLOW"] },
          geo:         { "$ref":"#/components/schemas/GeoInfo" },
          network:     { "$ref":"#/components/schemas/NetworkInfo" },
          intelligence:{ "$ref":"#/components/schemas/IntelligenceInfo" },
          threatFeeds: { "$ref":"#/components/schemas/ThreatFeedInfo" },
          signals: {
            type: "array",
            items: { "$ref":"#/components/schemas/Signal" }
          },
          meta: {
            type: "object",
            properties: {
              processingMs: { type:"integer", example:842 },
              cached:       { type:"boolean" },
              scoredAt:     { type:"string", format:"date-time" }
            }
          }
        }
      },

      WhoisResult: {
        type: "object",
        properties: {
          ip:          { type:"string" },
          network:     { type:"string", example:"CLOUDFLARENET" },
          handle:      { type:"string", example:"NET-1-1-1-0-1" },
          cidr:        { type:"string", example:"1.1.1.0/24" },
          orgName:     { type:"string", example:"Cloudflare, Inc." },
          orgId:       { type:"string" },
          country:     { type:"string", example:"US" },
          abuseEmail:  { type:"string", example:"abuse@cloudflare.com" },
          registered:  { type:"string", format:"date-time" },
          lastChanged: { type:"string", format:"date-time" },
          agedays:     { type:"integer", example:5840 },
          registrar:   { type:"string" },
          type:        { type:"string" },
          remarks:     { type:"array", items:{ type:"string" } }
        }
      },

      WatchlistEntry: {
        type: "object",
        properties: {
          ip:             { type:"string", example:"185.220.101.1" },
          label:          { type:"string", example:"Known Tor Exit" },
          threshold:      { type:"integer", minimum:0, maximum:100, example:30 },
          last_score:     { type:"integer" },
          last_risk:      { type:"string" },
          last_checked:   { type:"integer", description:"Unix timestamp ms" },
          added_at:       { type:"integer" },
          alert_on_change:{ type:"integer", enum:[0,1] }
        }
      },

      Error: {
        type: "object",
        properties: {
          error:   { type:"string" },
          message: { type:"string" }
        }
      }
    }
  },

  security: [{ ApiKeyAuth: [] }],

  paths: {
    "/health": {
      get: {
        tags:        ["System"],
        summary:     "Health check",
        description: "Returns server status. No authentication required.",
        security:    [],
        responses: {
          200: {
            description: "Server is healthy",
            content: { "application/json": { schema: {
              type: "object",
              properties: {
                status:      { type:"string", example:"ok" },
                version:     { type:"string", example:"2.2.0" },
                environment: { type:"string", example:"production" },
                uptime:      { type:"integer", example:3600 },
                db:          { type:"string", example:"connected" },
                memoryMB:    { type:"integer", example:64 },
                timestamp:   { type:"string", format:"date-time" }
              }
            }}}
          }
        }
      }
    },

    "/score/{ip}": {
      get: {
        tags:        ["Scoring"],
        summary:     "Score a single IP",
        description: "Returns full risk intelligence for an IPv4 or IPv6 address including geo, threat intel, network classification, WHOIS signals, and behavioral signals.",
        parameters: [{
          name: "ip", in: "path", required: true,
          schema: { type:"string" },
          example: "185.220.101.1",
          description: "IPv4 or IPv6 address to score"
        }],
        responses: {
          200: { description:"Score result", content:{ "application/json":{ schema:{ "$ref":"#/components/schemas/ScoreResult" } } } },
          400: { description:"Invalid IP address", content:{ "application/json":{ schema:{ "$ref":"#/components/schemas/Error" } } } },
          401: { description:"Missing API key" },
          429: { description:"Rate limit exceeded" },
          503: { description:"Upstream service unavailable" }
        }
      }
    },

    "/score/batch": {
      post: {
        tags:        ["Scoring"],
        summary:     "Batch score up to 50 IPs",
        description: "Score multiple IPs in a single request. All calls are made in parallel. Maximum 50 IPs per request.",
        requestBody: {
          required: true,
          content: { "application/json": { schema: {
            type: "object",
            required: ["ips"],
            properties: {
              ips: {
                type: "array",
                items: { type:"string" },
                minItems: 1,
                maxItems: 50,
                example: ["8.8.8.8","1.1.1.1","185.220.101.1"]
              }
            }
          }}}
        },
        responses: {
          200: {
            description: "Batch results",
            content: { "application/json": { schema: {
              type: "object",
              properties: {
                total:   { type:"integer" },
                scored:  { type:"integer" },
                failed:  { type:"integer" },
                results: { type:"array", items:{ "$ref":"#/components/schemas/ScoreResult" } }
              }
            }}}
          },
          400: { description:"Validation error or too many IPs" }
        }
      }
    },

    "/whois/{ip}": {
      get: {
        tags:        ["Intelligence"],
        summary:     "WHOIS / RDAP deep dive",
        description: "Returns full WHOIS registration data via RDAP for an IP address. Tries ARIN, then RIPE, then APNIC. Includes risk signals for young registrations and missing abuse contacts.",
        parameters: [{
          name:"ip", in:"path", required:true,
          schema:{ type:"string" }, example:"8.8.8.8"
        }],
        responses: {
          200: {
            description: "WHOIS result",
            content: { "application/json": { schema: {
              type:"object",
              properties: {
                whois:   { "$ref":"#/components/schemas/WhoisResult" },
                signals: { type:"array", items:{ "$ref":"#/components/schemas/Signal" } }
              }
            }}}
          },
          400: { description:"Invalid IP" },
          503: { description:"All RDAP registries unavailable" }
        }
      }
    },

    "/watchlist": {
      get: {
        tags:        ["Watchlist"],
        summary:     "Get all watched IPs",
        description: "Returns the full watchlist with last known scores and monitor job status.",
        responses: {
          200: {
            description: "Watchlist",
            content: { "application/json": { schema: {
              type:"object",
              properties: {
                total:     { type:"integer" },
                monitor:   { type:"object" },
                watchlist: { type:"array", items:{ "$ref":"#/components/schemas/WatchlistEntry" } }
              }
            }}}
          }
        }
      },
      post: {
        tags:        ["Watchlist"],
        summary:     "Add IP to watchlist",
        description: "Adds an IP to the watchlist and immediately scores it to establish a baseline. Maximum 100 IPs.",
        requestBody: {
          required: true,
          content: { "application/json": { schema: {
            type:"object",
            required:["ip"],
            properties: {
              ip:            { type:"string", example:"185.220.101.1" },
              label:         { type:"string", example:"Known Tor Exit Node" },
              threshold:     { type:"integer", minimum:0, maximum:100, default:30, example:30 },
              alertOnChange: { type:"boolean", default:true }
            }
          }}}
        },
        responses: {
          201: { description:"Added to watchlist" },
          400: { description:"Invalid IP or watchlist full" }
        }
      }
    },

    "/watchlist/{ip}": {
      delete: {
        tags:        ["Watchlist"],
        summary:     "Remove IP from watchlist",
        parameters: [{
          name:"ip", in:"path", required:true,
          schema:{ type:"string" }, example:"185.220.101.1"
        }],
        responses: {
          200: { description:"Removed from watchlist" },
          404: { description:"IP not in watchlist" }
        }
      }
    },

    "/watchlist/poll": {
      post: {
        tags:        ["Watchlist"],
        summary:     "Trigger immediate poll",
        description: "Re-scores all watched IPs immediately. Runs asynchronously — response is returned before scoring completes.",
        responses: {
          200: { description:"Poll triggered" }
        }
      }
    },

    "/watchlist/status": {
      get: {
        tags:        ["Watchlist"],
        summary:     "Monitor job status",
        responses: {
          200: {
            description: "Monitor status",
            content: { "application/json": { schema: {
              type:"object",
              properties: {
                running:       { type:"boolean" },
                active:        { type:"boolean" },
                intervalMins:  { type:"integer" },
                watchlistSize: { type:"integer" }
              }
            }}}
          }
        }
      }
    },

    "/audit": {
      get: {
        tags:        ["Audit"],
        summary:     "Get audit log",
        description: "Paginated audit log of all scored IPs.",
        parameters: [
          { name:"limit",  in:"query", schema:{ type:"integer", default:50, maximum:200 } },
          { name:"offset", in:"query", schema:{ type:"integer", default:0 } }
        ],
        responses: {
          200: {
            description: "Audit log",
            content: { "application/json": { schema: {
              type:"object",
              properties: {
                total:   { type:"integer" },
                limit:   { type:"integer" },
                offset:  { type:"integer" },
                hasMore: { type:"boolean" },
                entries: { type:"array" }
              }
            }}}
          }
        }
      }
    },

    "/audit/search": {
      get: {
        tags:        ["Audit"],
        summary:     "Search and filter audit log",
        description: "Full-text search and multi-field filter across the scoring history database.",
        parameters: [
          { name:"q",           in:"query", schema:{ type:"string" },                                           description:"Search IP, country, or ISP" },
          { name:"risk",        in:"query", schema:{ type:"string", enum:["CRITICAL","HIGH","MEDIUM","LOW"] }, description:"Filter by risk level" },
          { name:"action",      in:"query", schema:{ type:"string", enum:["BLOCK","CHALLENGE","MONITOR","ALLOW"] } },
          { name:"country",     in:"query", schema:{ type:"string" },                                           description:"Filter by country name" },
          { name:"minScore",    in:"query", schema:{ type:"integer", minimum:0, maximum:100 } },
          { name:"maxScore",    in:"query", schema:{ type:"integer", minimum:0, maximum:100 } },
          { name:"proxy",       in:"query", schema:{ type:"boolean" },                                          description:"Filter proxy IPs" },
          { name:"tor",         in:"query", schema:{ type:"boolean" },                                          description:"Filter Tor exit nodes" },
          { name:"datacenter",  in:"query", schema:{ type:"boolean" },                                          description:"Filter datacenter IPs" },
          { name:"from",        in:"query", schema:{ type:"string", format:"date-time" },                       description:"Start date filter" },
          { name:"to",          in:"query", schema:{ type:"string", format:"date-time" },                       description:"End date filter" },
          { name:"sort",        in:"query", schema:{ type:"string", enum:["date_desc","date_asc","score_desc","score_asc"], default:"date_desc" } },
          { name:"limit",       in:"query", schema:{ type:"integer", default:50, maximum:200 } },
          { name:"offset",      in:"query", schema:{ type:"integer", default:0 } }
        ],
        responses: {
          200: { description:"Filtered results" }
        }
      }
    },

    "/audit/threats": {
      get: {
        tags:        ["Audit"],
        summary:     "Top CRITICAL/HIGH IPs",
        parameters: [{ name:"limit", in:"query", schema:{ type:"integer", default:20, maximum:100 } }],
        responses: { 200:{ description:"Top threats" } }
      }
    },

    "/stats": {
      get: {
        tags:        ["System"],
        summary:     "Runtime statistics",
        description: "Returns risk distribution, cache size, DB status, threat feed status, and memory usage.",
        responses: {
          200: {
            description: "Stats",
            content: { "application/json": { schema: {
              type:"object",
              properties: {
                riskDistribution: {
                  type:"object",
                  properties: { CRITICAL:{ type:"integer" }, HIGH:{ type:"integer" }, MEDIUM:{ type:"integer" }, LOW:{ type:"integer" } }
                },
                totalScored:  { type:"integer" },
                cacheSize:    { type:"integer" },
                dbAvailable:  { type:"boolean" },
                uptime:       { type:"integer" },
                memoryMB:     { type:"integer" },
                threatFeeds:  { type:"object" }
              }
            }}}
          }
        }
      }
    }
  },

  tags: [
    { name:"Scoring",      description:"IP risk scoring endpoints" },
    { name:"Intelligence", description:"Deep intelligence lookups" },
    { name:"Watchlist",    description:"IP monitoring and alerting" },
    { name:"Audit",        description:"Scoring history and search" },
    { name:"System",       description:"Health and statistics" }
  ]
};

module.exports = spec;