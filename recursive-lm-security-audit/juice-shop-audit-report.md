# Security Vulnerability Assessment: OWASP Juice Shop

## Executive Summary

This application is the OWASP Juice Shop, a deliberately insecure web application built with Node.js/TypeScript, Express, Angular, and SQLite/Sequelize. The codebase contains numerous intentional security vulnerabilities spanning all OWASP Top 10 categories. This report catalogs the identified vulnerabilities, their locations, severity, and potential impact.

---

## Critical Vulnerabilities

### 1. SQL Injection (Multiple Locations)

#### 1a. Login SQL Injection
- **File**: `routes/login.ts`
- **Line**: `models.sequelize.query(\`SELECT * FROM Users WHERE email = '\${req.body.email || ''}' AND password = '\${security.hash(req.body.password || '')}' AND deletedAt IS NULL\`)`
- **Severity**: CRITICAL
- **Description**: User-supplied email is directly interpolated into a raw SQL query without parameterization or escaping. An attacker can bypass authentication entirely using payloads like `' OR 1=1--` or extract data from other tables using UNION-based injection.
- **Impact**: Complete authentication bypass, full database extraction, potential data modification/deletion.
- **Recommendation**: Use parameterized queries (`sequelize.query()` with bind parameters) or Sequelize model methods (e.g., `UserModel.findOne({ where: { email, password } })`).

#### 1b. Product Search SQL Injection
- **File**: `routes/search.ts`
- **Line**: `models.sequelize.query(\`SELECT * FROM Products WHERE ((name LIKE '%\${criteria}%' OR description LIKE '%\${criteria}%') AND deletedAt IS NULL) ORDER BY name\`)`
- **Severity**: CRITICAL
- **Description**: The search query parameter `q` is directly interpolated into a raw SQL query. Although truncated to 200 characters, this is still sufficient for UNION-based SQL injection to extract all database tables and data, including user credentials.
- **Impact**: Full database schema disclosure, extraction of all user credentials (emails and password hashes), access to all application data.
- **Recommendation**: Use parameterized queries or Sequelize's built-in `Op.like` operators.

### 2. Hardcoded RSA Private Key
- **File**: `lib/insecurity.ts`
- **Line**: `const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wg...'`
- **Severity**: CRITICAL
- **Description**: The RSA private key used for signing JWT tokens is hardcoded directly in the source code. Anyone with access to the source code (or the compiled application) can forge arbitrary JWT tokens, impersonating any user including administrators.
- **Impact**: Complete authentication bypass, arbitrary user impersonation, admin privilege escalation.
- **Recommendation**: Store private keys in environment variables, a secrets management system (e.g., HashiCorp Vault, AWS Secrets Manager), or encrypted key files outside the repository.

### 3. Remote Code Execution (RCE) via `vm.runInNewContext`
- **File**: `routes/b2bOrder.ts`
- **Line**: `res.json({ coppied: vm.runInNewContext(orderLinesData, { sapiline: Date.now() }, { timeout: 2000 }) })`
- **Severity**: CRITICAL
- **Description**: When JSON parsing of `orderLinesData` fails, the raw user input is executed as JavaScript code via `vm.runInNewContext()`. The Node.js `vm` module is NOT a security sandbox - it can be escaped to execute arbitrary system commands on the server.
- **Impact**: Full server compromise, arbitrary command execution, data exfiltration, lateral movement within the network.
- **Recommendation**: Never execute user-supplied input as code. Use strict JSON parsing only and return appropriate error responses for malformed input.

### 4. XML External Entity (XXE) Injection
- **File**: `routes/fileUpload.ts`
- **Line**: `const xmlDoc = libxml.parseXml(data, { noent: true, noblanks: true })`
- **Severity**: CRITICAL
- **Description**: XML file uploads are parsed with `noent: true`, which enables external entity resolution. An attacker can craft XML files with external entity declarations to read arbitrary files from the server (e.g., `/etc/passwd`, `C:\Windows\system.ini`) or perform Server-Side Request Forgery (SSRF).
- **Impact**: Arbitrary file read on the server, SSRF, potential denial of service via billion laughs attack.
- **Recommendation**: Parse XML with `noent: false` (or omit the option) and disable DTD processing entirely. Use `{ noent: false, dtdload: false, dtdattr: false }`.

### 5. Server-Side Request Forgery (SSRF)
- **File**: `routes/profileImageUrlUpload.ts`
- **Line**: `const imageResponse = await fetch(url)`
- **Severity**: HIGH
- **Description**: User-supplied URLs are fetched server-side without adequate validation. Although the code checks for `https?://` protocol, it does not restrict access to internal network resources (e.g., `http://localhost`, `http://169.254.169.254` for cloud metadata, internal services).
- **Impact**: Access to internal services, cloud metadata endpoints, port scanning of internal networks, potential data exfiltration from internal systems.
- **Recommendation**: Implement a URL allowlist, block requests to private IP ranges (RFC 1918), localhost, and cloud metadata endpoints. Use a dedicated proxy or network-level controls.

---

## High Severity Vulnerabilities

### 6. NoSQL Injection
- **File**: `routes/trackOrder.ts`
- **Line**: `db.ordersCollection.find({ $where: \`this.orderId === '\${id}'\` })`
- **Severity**: HIGH
- **Description**: The order tracking ID is interpolated into a MongoDB `$where` clause, which executes JavaScript. An attacker can inject JavaScript code to manipulate the query logic and extract all orders from the database.
- **Impact**: Data exfiltration of all order records, potential NoSQL injection to bypass query logic.
- **Recommendation**: Use standard MongoDB query operators instead of `$where`. For example: `db.ordersCollection.find({ orderId: id })`.

### 7. Weak Password Hashing (MD5)
- **File**: `lib/insecurity.ts`
- **Line**: `export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')`
- **Severity**: HIGH
- **Description**: Passwords are hashed using MD5, which is cryptographically broken. MD5 hashes can be reversed using rainbow tables or brute-forced extremely quickly with modern hardware. No salt is used, making all identical passwords produce identical hashes.
- **Impact**: Trivial password cracking if database is compromised, enabling account takeover for all users.
- **Recommendation**: Use bcrypt, scrypt, or Argon2 with proper salting and work factors.

### 8. Server-Side Template Injection (SSTI) / Path Traversal in Data Erasure
- **File**: `routes/dataErasure.ts`
- **Line**: `res.render(req.body.layout, { email }, ...)`
- **Severity**: HIGH
- **Description**: The `layout` parameter from user input is passed directly to `res.render()`. Although there is a check for `ftp`, `ctf.key`, and `encryptionkeys` in the resolved path, an attacker can still specify arbitrary template files to render, potentially leading to Server-Side Template Injection or information disclosure through rendering unintended templates.
- **Impact**: Information disclosure, potential code execution depending on the template engine configuration.
- **Recommendation**: Never use user input to determine which template to render. Use a fixed template name and pass only data parameters.

### 9. Broken Access Control - Missing Authorization on PUT for Products
- **File**: `server.ts`
- **Line**: `// app.put('/api/Products/:id', security.isAuthorized())` (commented out)
- **Severity**: HIGH
- **Description**: The authorization middleware for PUT requests on `/api/Products/:id` is commented out, allowing any user (even unauthenticated) to modify product data including names, descriptions, and prices.
- **Impact**: Product data manipulation, price tampering, defacement of product listings.
- **Recommendation**: Uncomment and enforce proper authorization with role-based access control (admin-only for product modifications).

### 10. Insecure Direct Object Reference (IDOR) - Basket Access
- **File**: `routes/basket.ts`
- **Description**: While baskets require authentication, the basket ID is exposed and may allow users to access other users' baskets if the ID is guessed or enumerated, depending on the authorization middleware implementation.
- **Severity**: HIGH

### 11. Reflected Cross-Site Scripting (XSS) via Order Tracking
- **File**: `routes/trackOrder.ts`
- **Line**: The order ID is reflected back in the response: `result.data[0] = { orderId: id }`
- **Severity**: HIGH
- **Description**: When the reflected XSS challenge is enabled, the order ID is only truncated (not sanitized) and reflected directly in the response. An attacker can inject `<iframe src="javascript:alert('xss')">` via the order ID parameter.
- **Impact**: Session hijacking, cookie theft, phishing, account takeover.
- **Recommendation**: Always HTML-encode user input before reflecting it in responses. Use Content Security Policy headers.

### 12. Stored XSS via HTTP Header (True-Client-IP)
- **File**: `routes/saveLoginIp.ts`
- **Line**: `user.update({ lastLoginIp: logIp?.toString() })`
- **Severity**: HIGH
- **Description**: The `True-Client-IP` header value is stored directly in the database without sanitization. When rendered on the user profile page, this enables stored XSS attacks.
- **Impact**: Persistent XSS affecting any user viewing the profile, session hijacking, account takeover.
- **Recommendation**: Sanitize header values before storage and HTML-encode all output.

### 13. Stored XSS via Username (Weak Sanitization)
- **File**: `routes/updateUserProfile.ts`
- **Line**: `user.username = security.sanitizeLegacy(username)`
- **Severity**: HIGH
- **Description**: The `sanitizeLegacy` function uses a weak regex (`/<(?:\w+)\W+?[\w]/gi`) that can be bypassed with crafted HTML payloads. The username is stored and rendered on profile pages, enabling persistent XSS.
- **Impact**: Stored XSS, session hijacking, account takeover.
- **Recommendation**: Use `sanitizeSecure()` (which recursively applies `sanitize-html`) instead of `sanitizeLegacy()`.

---

## Medium Severity Vulnerabilities

### 14. Open Redirect
- **File**: `routes/redirect.ts`
- **Line**: `if (allowedRedirectUrls.some((allowedUrl) => utils.startsWith(toUrl, allowedUrl)))`
- **Severity**: MEDIUM
- **Description**: The redirect allowlist uses `startsWith` matching, which can be bypassed. For example, `https://github.com/juice-shop.evil.com` would pass the check because it starts with `https://github.com/juice-shop`. An attacker can redirect users to malicious sites.
- **Impact**: Phishing attacks, credential theft via fake login pages.
- **Recommendation**: Perform strict URL parsing and validate the full domain, not just the prefix.

### 15. Broken Anti-Automation (Rate Limiting Bypass)
- **File**: `server.ts`
- **Line**: `keyGenerator ({ headers, ip }) { return headers['X-Forwarded-For'] ?? ip }`
- **Severity**: MEDIUM
- **Description**: The rate limiter for the password reset endpoint uses `X-Forwarded-For` header as the key generator. Since `trust proxy` is enabled, an attacker can bypass rate limiting by simply changing the `X-Forwarded-For` header on each request.
- **Impact**: Enables brute-force attacks on password reset (security question answers), credential stuffing.
- **Recommendation**: Do not trust client-supplied headers for rate limiting. Use a more robust key generation strategy.

### 16. Insecure Password Change (Missing Current Password Verification for GET)
- **File**: `routes/changePassword.ts`
- **Description**: The password change functionality accepts the current password, new password, and repeat password. However, the change password route may be vulnerable to CSRF or missing verification of the current password if it's passed as a query parameter in a GET request.
- **Severity**: MEDIUM

### 17. Forged Feedback (Broken Access Control)
- **File**: `routes/verify.ts` (forgedFeedbackChallenge)
- **Description**: The feedback POST endpoint accepts a `UserId` field in the request body. An attacker can submit feedback on behalf of any user by specifying another user's ID, since the server doesn't enforce that the `UserId` matches the authenticated user.
- **Severity**: MEDIUM
- **Impact**: Reputation manipulation, impersonation of other users in feedback.

### 18. Mass Assignment / Role Escalation
- **File**: `routes/verify.ts` (registerAdminChallenge)
- **Description**: The user registration endpoint accepts a `role` field in the request body. An attacker can register with `"role": "admin"` to gain administrative privileges, as the server doesn't strip or validate the role field before creating the user.
- **Severity**: HIGH
- **Impact**: Privilege escalation to admin, complete application takeover.
- **Recommendation**: Whitelist allowed fields during user registration and never accept role assignments from client input.

### 19. Weak Cryptography - Z85/Base85 Encoding for Coupons
- **File**: `lib/insecurity.ts`
- **Line**: `return z85.encode(coupon)` in `generateCoupon()`
- **Severity**: MEDIUM
- **Description**: Discount coupons are "encrypted" using Z85 (Base85) encoding, which is an encoding scheme, not encryption. Anyone who understands the format can generate valid coupons for arbitrary discount percentages.
- **Impact**: Financial fraud through forged discount coupons.
- **Recommendation**: Use HMAC-signed coupons or store valid coupon codes server-side.

### 20. Weak Hashids Salt for Continue Codes
- **File**: `routes/restoreProgress.ts`
- **Line**: `const hashids_ = new Hashids('this is my salt', 60, ...)`
- **Severity**: MEDIUM
- **Description**: The Hashids salt is a predictable string `'this is my salt'`. Hashids is also not designed for security - it's an obfuscation library. An attacker can decode/forge progress codes.
- **Impact**: Forge challenge completion progress.

### 21. JWT Algorithm Confusion Vulnerability
- **File**: `lib/insecurity.ts` and `routes/verify.ts`
- **Description**: The application uses RS256 for JWT signing but the verification may accept tokens with `alg: "none"` or `alg: "HS256"` (using the public key as the HMAC secret). The `jwtChallenges()` middleware in verify.ts explicitly checks for these attacks, confirming they are possible.
- **Severity**: HIGH
- **Impact**: Authentication bypass, arbitrary user impersonation.
- **Recommendation**: Explicitly specify allowed algorithms in JWT verification: `jwt.verify(token, publicKey, { algorithms: ['RS256'] })`.

---

## Low Severity Vulnerabilities

### 22. Sensitive Data Exposure - Hardcoded Credentials
- **File**: `routes/login.ts`
- **Lines**: `verifyPreLoginChallenges` function
- **Description**: Multiple user credentials are hardcoded in the source code (admin123, J6aVjTgOpRs@?5l!Zkq2AYnCE@RF$P, Mr. N00dles, etc.). While these are for challenge verification, they reveal actual user passwords.
- **Severity**: LOW (in context of intentionally vulnerable app)

### 23. Information Disclosure via Error Messages
- **File**: `routes/errorHandler.ts`, various routes
- **Description**: Detailed error messages including stack traces and internal system information may be exposed to users, aiding attackers in understanding the application internals.
- **Severity**: LOW

### 24. Null Byte Injection (Partially Mitigated)
- **File**: `lib/insecurity.ts`
- **Line**: `export const cutOffPoisonNullByte = (str: string) => {...}`
- **Description**: The poison null byte mitigation only checks for URL-encoded `%00` but may not handle actual null bytes in different encodings. Used in `fileServer.ts` and `videoHandler.ts`.
- **Severity**: LOW

### 25. Directory Traversal (Partially Mitigated)
- **File**: `routes/fileServer.ts`, `routes/videoHandler.ts`
- **Description**: File serving routes use `cutOffPoisonNullByte` and check for leading `/` but path traversal via `../` sequences may still be possible depending on the path resolution logic.
- **Severity**: MEDIUM

### 26. Insecure HMAC Secret
- **File**: `lib/insecurity.ts`
- **Line**: `export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')`
- **Severity**: MEDIUM
- **Description**: The HMAC secret key is hardcoded in the source code, allowing anyone with source access to forge HMAC signatures.

### 27. Missing CSRF Protection
- **File**: `server.ts`
- **Description**: The application does not implement CSRF tokens. The `updateUserProfile` route explicitly checks for cross-origin requests as part of a CSRF challenge, confirming that CSRF protection is absent.
- **Severity**: MEDIUM

### 28. Exposed Metrics Endpoint
- **File**: `routes/metrics.ts`
- **Description**: Application metrics (likely Prometheus) are exposed, potentially revealing sensitive operational data about the application including user counts, error rates, and internal statistics.
- **Severity**: LOW

### 29. FTP Directory Serving with Index
- **File**: `server.ts`
- **Description**: The FTP folder is served with directory listing enabled via `serve-index`, potentially exposing sensitive files.
- **Severity**: LOW

### 30. Sensitive Data in Data Export
- **File**: `routes/dataExport.ts`
- **Description**: Data exports are written to the publicly accessible `ftp/` directory as text files, potentially allowing other users to access exported data.
- **Severity**: MEDIUM

---

## Architectural & Configuration Concerns

### 31. `trust proxy` Enabled Globally
- **File**: `server.ts`
- **Line**: `app.enable('trust proxy')`
- **Description**: Enabling `trust proxy` globally means the application trusts `X-Forwarded-For` and similar headers from any source. This should only be enabled when the application is behind a trusted reverse proxy, and the trusted proxy count should be specified.

### 32. Public Key Exposed
- **File**: `lib/insecurity.ts`
- **Line**: `export const publicKey = fs.readFileSync('encryptionkeys/jwt.pub', 'utf8')`
- **Description**: The JWT public key is readable from a file and exported. Combined with the hardcoded private key, this completely undermines the JWT security model.

### 33. No Content Security Policy (Effective)
- **File**: `server.ts`
- **Description**: While `helmet` is imported, the CSP configuration may not be strict enough to prevent XSS attacks, given the multiple XSS vulnerabilities present.

### 34. Session Management
- **Description**: The application uses a custom in-memory token store (`authenticatedUsers`) rather than a standard session management library, which lacks features like session invalidation, concurrent session limits, and secure session storage.

---

## Summary Table

| # | Vulnerability | Severity | File | Category |
|---|---|---|---|---|
| 1a | SQL Injection (Login) | CRITICAL | routes/login.ts | A03:2021 Injection |
| 1b | SQL Injection (Search) | CRITICAL | routes/search.ts | A03:2021 Injection |
| 2 | Hardcoded Private Key | CRITICAL | lib/insecurity.ts | A02:2021 Cryptographic Failures |
| 3 | Remote Code Execution | CRITICAL | routes/b2bOrder.ts | A03:2021 Injection |
| 4 | XXE Injection | CRITICAL | routes/fileUpload.ts | A03:2021 Injection |
| 5 | SSRF | HIGH | routes/profileImageUrlUpload.ts | A10:2021 SSRF |
| 6 | NoSQL Injection | HIGH | routes/trackOrder.ts | A03:2021 Injection |
| 7 | Weak Password Hashing (MD5) | HIGH | lib/insecurity.ts | A02:2021 Cryptographic Failures |
| 8 | SSTI / Path Traversal | HIGH | routes/dataErasure.ts | A03:2021 Injection |
| 9 | Missing Authorization (Products) | HIGH | server.ts | A01:2021 Broken Access Control |
| 10 | IDOR (Baskets) | HIGH | routes/basket.ts | A01:2021 Broken Access Control |
| 11 | Reflected XSS (Order Tracking) | HIGH | routes/trackOrder.ts | A03:2021 Injection |
| 12 | Stored XSS (HTTP Header) | HIGH | routes/saveLoginIp.ts | A03:2021 Injection |
| 13 | Stored XSS (Username) | HIGH | routes/updateUserProfile.ts | A03:2021 Injection |
| 14 | Open Redirect | MEDIUM | routes/redirect.ts | A01:2021 Broken Access Control |
| 15 | Rate Limiting Bypass | MEDIUM | server.ts | A04:2021 Insecure Design |
| 16 | Insecure Password Change | MEDIUM | routes/changePassword.ts | A07:2021 Auth Failures |
| 17 | Forged Feedback | MEDIUM | API /Feedbacks | A01:2021 Broken Access Control |
| 18 | Mass Assignment (Role) | HIGH | API /Users | A01:2021 Broken Access Control |
| 19 | Weak Coupon Crypto | MEDIUM | lib/insecurity.ts | A02:2021 Cryptographic Failures |
| 20 | Weak Hashids Salt | MEDIUM | routes/restoreProgress.ts | A02:2021 Cryptographic Failures |
| 21 | JWT Algorithm Confusion | HIGH | lib/insecurity.ts | A02:2021 Cryptographic Failures |
| 22 | Hardcoded Credentials | LOW | routes/login.ts | A07:2021 Auth Failures |
| 23 | Information Disclosure | LOW | Various | A04:2021 Insecure Design |
| 24 | Null Byte Injection | LOW | lib/insecurity.ts | A03:2021 Injection |
| 25 | Directory Traversal | MEDIUM | routes/fileServer.ts | A01:2021 Broken Access Control |
| 26 | Hardcoded HMAC Secret | MEDIUM | lib/insecurity.ts | A02:2021 Cryptographic Failures |
| 27 | Missing CSRF Protection | MEDIUM | server.ts | A01:2021 Broken Access Control |
| 28 | Exposed Metrics | LOW | routes/metrics.ts | A05:2021 Security Misconfiguration |
| 29 | Directory Listing (FTP) | LOW | server.ts | A05:2021 Security Misconfiguration |
| 30 | Data Export to Public Dir | MEDIUM | routes/dataExport.ts | A01:2021 Broken Access Control |

---

## OWASP Top 10 Coverage

- **A01:2021 Broken Access Control**: Missing authorization on product updates, IDOR on baskets, forged feedback, mass assignment, open redirect, CSRF
- **A02:2021 Cryptographic Failures**: Hardcoded RSA private key, MD5 password hashing, Z85 encoding as "encryption", hardcoded HMAC secret, weak Hashids salt, JWT algorithm confusion
- **A03:2021 Injection**: SQL injection (login, search), NoSQL injection (order tracking), XSS (reflected, stored via headers, stored via username), XXE, RCE via vm.runInNewContext, SSTI
- **A04:2021 Insecure Design**: Rate limiting bypass, verbose error messages, security through obscurity for coupons
- **A05:2021 Security Misconfiguration**: Exposed metrics, directory listing, trust proxy misconfiguration
- **A07:2021 Identification and Authentication Failures**: Hardcoded credentials, weak passwords, insecure password change flow
- **A10:2021 Server-Side Request Forgery**: Profile image URL upload SSRF

---

## Recommendations

1. **Replace all raw SQL queries** with parameterized queries or ORM methods
2. **Remove hardcoded cryptographic keys** and use environment variables or secrets management
3. **Upgrade password hashing** from MD5 to bcrypt/scrypt/Argon2 with salting
4. **Remove `vm.runInNewContext`** usage and never execute user input as code
5. **Disable XML external entity processing** in XML parsers
6. **Implement strict URL validation** with allowlists for SSRF-prone endpoints
7. **Add CSRF protection** using tokens or SameSite cookies
8. **Implement proper input validation and output encoding** for all user-supplied data
9. **Use strict JWT algorithm verification** (RS256 only)
10. **Implement proper role-based access control** with server-side enforcement
11. **Remove directory listing** from publicly accessible directories
12. **Implement proper rate limiting** that cannot be bypassed via headers
13. **Use proper session management** with established libraries
14. **Apply Content Security Policy** headers to mitigate XSS
