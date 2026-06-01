# EpiccSafe API Documentation

## Overview
EpiccSafe API provides URL safety reporting, scanning, and management capabilities. Users can submit reports about suspicious URLs, check report status, and admins can manage reports and maintain blacklist/whitelist.

Base URL: `http://localhost:8000`

---

## User Functions

### 1. Submit Report
Submit a new report for a suspicious URL.

**Endpoint:** `POST /reports/submit`

**Request Body:**
```json
{
  "email": "user@example.com",
  "url": "http://suspicious-site.com",
  "description": "This site asks for login credentials",
  "source": "web"
}
```

**Response (201 Created):**
```json
{
  "ticket_id": "TICKET-A1B2C3D4",
  "status": "SUBMITTED",
  "risk_score": 75
}
```

**Notes:**
- Returns a unique `ticket_id` for tracking
- `risk_score` is calculated (0-100, dummy implementation until ML ready)
- URL is checked against blacklist/whitelist automatically

---

### 2. Check Report Status
Check the status of a submitted report using ticket ID.

**Endpoint:** `GET /reports/status/{ticket_id}`

**Parameters:**
- `ticket_id` (path): The ticket ID received when submitting

**Response (200 OK):**
```json
{
  "status": "IN_REVIEW",
  "final_status": null,
  "created_at": "2026-04-30T10:30:00",
  "resolved_at": null
}
```

**Status Values:**
- `SUBMITTED` - Report just submitted
- `IN_REVIEW` - Admin is reviewing
- `RESOLVED` - Report has been processed

**Final Status Values:**
- `BLACKLISTED` - URL added to blacklist
- `WHITELISTED` - URL added to whitelist
- `SAFE` - URL determined safe
- `NULL` - Not yet determined

---

## Admin Functions

### 3. Get All Reports
Get all reports with optional status filter.

**Endpoint:** `GET /admin/reports`

**Query Parameters:**
- `status` (optional): Filter by status (SUBMITTED, IN_REVIEW, RESOLVED)

**Response (200 OK):**
```json
[
  {
    "id": "TICKET-A1B2C3D4",
    "email": "user@example.com",
    "url": "http://suspicious-site.com",
    "description": "This site asks for login credentials",
    "risk_score": 75,
    "status": "IN_REVIEW",
    "final_status": null,
    "source": "web",
    "created_at": "2026-04-30T10:30:00",
    "updated_at": "2026-04-30T11:00:00",
    "resolved_at": null
  }
]
```

---

### 4. Get Reports with Filters
Get reports with multiple filtering options.

**Endpoint:** `GET /admin/reports/filter`

**Query Parameters:**
- `status` (optional): Filter by status
- `email` (optional): Filter by reporter email
- `source` (optional): Filter by source (web, extension)
- `date_from` (optional): Filter from date (YYYY-MM-DD)
- `date_to` (optional): Filter to date (YYYY-MM-DD)

**Response:** Same as Get All Reports

---

### 5. Update Report Status
Update a report's status (Admin only).

**Endpoint:** `PUT /admin/reports/status`

**Request Body:**
```json
{
  "report_id": "TICKET-A1B2C3D4",
  "new_status": "RESOLVED",
  "final_status": "BLACKLISTED",
  "admin_id": "admin-uuid-here",
  "note": "URL confirmed malicious, added to blacklist"
}
```

**Response (200 OK):**
```json
{
  "message": "Report status updated successfully"
}
```

---

### 6. Add to Blacklist
Add a URL to the blacklist (Admin only).

**Endpoint:** `POST /admin/blacklist`

**Request Body:**
```json
{
  "url": "http://malicious-site.com",
  "admin_id": "admin-uuid-here"
}
```

**Response (200 OK):**
```json
{
  "message": "URL added to blacklist successfully"
}
```

---

### 7. Add to Whitelist
Add a URL to the whitelist (Admin only).

**Endpoint:** `POST /admin/whitelist`

**Request Body:**
```json
{
  "url": "http://trusted-site.com",
  "admin_id": "admin-uuid-here"
}
```

**Response (200 OK):**
```json
{
  "message": "URL added to whitelist successfully"
}
```

---

### 8. Broadcast Phishing Warning
Send a broadcast warning email to all unique reporter emails about a phishing URL.

**Endpoint:** `POST /admin/broadcast`

**Request Body:**
```json
{
  "url": "http://phishing-site.com",
  "admin_id": "admin-uuid-here"
}
```

**Response (200 OK):**
```json
{
  "message": "Broadcast selesai. 10 email terkirim, 0 gagal",
  "total_unique_emails": 10,
  "sent": 10,
  "failed": 0
}
```

---

### 9. Get Admin by ID
Get admin details (name, email) by admin ID.

**Endpoint:** `GET /admin/{admin_id}`

**Parameters:**
- `admin_id` (path): Admin ID to look up

**Response (200 OK):**
```json
{
  "id": "admin-uuid-here",
  "name": "Admin Name",
  "email": "admin@example.com"
}
```

---

### 10. Get Report Logs
Get activity logs for a specific report.

**Endpoint:** `GET /admin/reports/{report_id}/logs`

**Parameters:**
- `report_id` (path): Report ID to get logs for

**Response (200 OK):**
```json
[
  {
    "id": "log-uuid",
    "report_id": "TICKET-A1B2C3D4",
    "old_status": "SUBMITTED",
    "new_status": "IN_REVIEW",
    "changed_by": "admin-uuid",
    "note": "Started review process",
    "created_at": "2026-04-30T11:00:00"
  }
]
```

---

## Scan Functions

### 11. Scan URL
Quick scan to check if URL is blacklisted or whitelisted.

**Endpoint:** `GET /scan/url?url=http://example.com`

**Query Parameters:**
- `url`: URL to scan

**Response (200 OK):**
```json
{
  "is_blacklisted": false,
  "is_whitelisted": true
}
```

---

### 12. Scan URL (Extension)
Extended scan for browser extension - includes risk score.

**Endpoint:** `GET /scan/url/extension?url=http://example.com`

**Query Parameters:**
- `url`: URL to scan

**Response (200 OK):**
```json
{
  "is_blacklisted": false,
  "is_whitelisted": false,
  "risk_score": 45
}
```

---

### 13. Check URL Status
Get status classification for a URL.

**Endpoint:** `GET /scan/url/status?url=http://example.com`

**Query Parameters:**
- `url`: URL to check

**Response (200 OK):**
```json
{
  "status": "SUSPICIOUS"
}
```

**Status Values:**
- `BLACKLISTED` - URL is in blacklist
- `WHITELISTED` - URL is in whitelist
- `SAFE` - Risk score < 30
- `SUSPICIOUS` - Risk score 30-70
- `DANGEROUS` - Risk score > 70

---

### 14. Call Scan API
Call external scan API (Dummy implementation).

**Endpoint:** `GET /scan/api`

**Response (200 OK):**
```json
{
  "risk_score": 65,
  "status": "suspicious"
}
```

---

## Helper Functions (Internal)

These functions are used internally and not exposed as API endpoints:

### generate_ticket_id()
Generates unique ticket ID in format: `TICKET-XXXXXXXX`

### is_blacklisted(url)
Checks if URL exists in blacklist_urls table.

### is_whitelisted(url)
Checks if URL exists in whitelist_urls table.

### log_report_activity(report_id, old_status, new_status, changed_by, note)
Logs status changes to report_logs table.

### calculate_risk_score(url)
Calculates risk score (0-100) using dummy heuristics.
- Returns 100 if blacklisted
- Returns 0 if whitelisted
- Uses pattern matching + random factor (ML pending)

---

## Database Schema

### reports
- `id` (text, PK) - Ticket ID
- `email` (text) - Reporter email
- `url` (text, NOT NULL) - Reported URL
- `description` (text) - Report description
- `risk_score` (integer) - Calculated risk score
- `status` (report_status) - Current status (default: SUBMITTED)
- `final_status` (text) - Final determination
- `source` (text) - Report source
- `created_at` (timestamp) - Creation time
- `updated_at` (timestamp) - Last update
- `resolved_at` (timestamp) - Resolution time

### admins
- `id` (text, PK) - Admin ID
- `name` (text) - Admin name
- `email` (text) - Admin email
- `password_hash` (text) - Hashed password
- `created_at` (timestamp) - Creation time

### blacklist_urls
- `id` (text, PK) - Entry ID
- `url` (text) - Blacklisted URL
- `added_by` (text, FK -> admins) - Admin who added
- `created_at` (timestamp) - Creation time

### whitelist_urls
- `id` (text, PK) - Entry ID
- `url` (text) - Whitelisted URL
- `added_by` (text, FK -> admins) - Admin who added
- `created_at` (timestamp) - Creation time

### report_logs
- `id` (text, PK) - Log ID
- `report_id` (text, FK -> reports) - Associated report
- `old_status` (text) - Previous status
- `new_status` (text) - New status
- `changed_by` (text, FK -> admins) - Admin who made change
- `note` (text) - Change note
- `created_at` (timestamp) - Log time

### notifications
- `id` (text, PK) - Notification ID
- `report_id` (text, FK -> reports) - Associated report
- `user_email` (text) - Recipient email
- `type` (text) - Notification type
- `status` (text) - Notification status
- `created_at` (timestamp) - Creation time

---

## Authentication

Currently, the API uses Supabase authentication. Include the JWT token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

Auth endpoints (from existing implementation):
- `POST /signup` - Register new user
- `POST /signin` - Login user
- `POST /signout` - Logout user
- `GET /me` - Get current user info

---

## Error Responses

All endpoints return appropriate HTTP status codes:

- `200` - Success
- `201` - Created (submit report)
- `400` - Bad Request (validation error)
- `401` - Unauthorized (invalid/missing token)
- `404` - Not Found
- `500` - Internal Server Error

Error response format:
```json
{
  "detail": "Error message here"
}
```

---

## Running the Server

```bash
uvicorn main:app --reload
```

Access API documentation:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
