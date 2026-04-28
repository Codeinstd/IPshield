# IPShield — Real-Time IP Risk Scoring Platform

A production-ready MVP for real-time IP risk assessment. Scores IPv4/IPv6 addresses across multiple risk dimensions and returns a structured risk report in milliseconds.

## Quick Start

```bash
npm install
node index.js
```

Open http://localhost:3000 for the dashboard.

---

## API Reference

### Score a single IP
```http
GET /api/score/:ip
```
```bash
curl http://localhost:3000/api/score/185.220.101.1
```

**Response:**
```json
{
  "ip": "185.220.101.1",
  "score": 85,
  "riskLevel": "CRITICAL",
  "action": "BLOCK",
  "signals": [
    {
      "category": "threat_intel",
      "severity": "critical",
      "detail": "known tor_exit — 847 abuse reports"
    }
  ],
  "geo": {
    "country": "DE",
    "region": "Bavaria",
    "city": "Munich",
    "timezone": "Europe/Berlin",
    "coordinates": [48.1374, 11.5755]
  },
  "network": {
    "type": "ipv4",
    "isDatacenter": false
  },
  "behavior": {
    "requestsLast5Min": 1,
    "firstSeen": "2024-01-01T12:00:00.000Z",
    "velocityLabel": "normal velocity"
  },
  "threatIntel": {
    "type": "tor_exit",
    "severity": "critical",
    "reports": 847
  },
  "meta": {
    "scoredAt": "2024-01-01T12:00:00.000Z",
    "processingMs": 3,
    "version": "1.0.0"
  }
}
```

### Batch score (up to 50 IPs)
```http
POST /api/score/batch
Content-Type: application/json

{"ips": ["8.8.8.8", "185.220.101.1", "1.1.1.1"]}
```

### Audit log
```http
GET /api/audit?limit=50
```

### Runtime stats
```http
GET /api/stats
```

### Health check
```http
GET /api/health
```

---

## Risk Scoring Model

| Component       | Weight | Description                          |
|----------------|--------|--------------------------------------|
| Threat Intel    | 40%    | Known bad IPs, abuse reports         |
| Geolocation     | 20%    | Sanctioned/high-risk countries       |
| Network         | 20%    | IP type, datacenter detection        |
| Behavior        | 15%    | Request velocity over 5-min window   |
| Datacenter      | 5%     | Hosting/cloud provider ranges        |

### Risk Levels & Actions

| Score   | Level    | Action    |
|---------|----------|-----------|
| 75–100  | CRITICAL | BLOCK     |
| 50–74   | HIGH     | CHALLENGE |
| 25–49   | MEDIUM   | MONITOR   |
| 0–24    | LOW      | ALLOW     |

---
