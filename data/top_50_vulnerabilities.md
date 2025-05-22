# 50 Critical Security Rules for Python Code Analysis

## 1. OS Command Injection (CWE-78)

**Rule:** OS Command Injection occurs when a web application or system executes operating system commands constructed from untrusted input — such as data from a user or request — without properly sanitizing or validating it. If user input is directly inserted into shell commands, an attacker can inject arbitrary commands, leading to full system compromise.Avoid constructing OS command strings with unsanitized input. Dynamically building shell commands from user data can allow execution of unintended commands. Avoid using shell=True when using subprocess.run(). Use safer alternatives (e.g. subprocess.run with a list of arguments, and shell=False).
**Reference:** CWE-78 – Improper Neutralization of Special Elements in OS Command ￼

## 2. SQL Injection (CWE-89)

**Rule:** Never concatenate or format user input into SQL queries. Use parameterized queries or ORM query APIs. Building SQL commands with unescaped input can cause the input to be interpreted as SQL code.
**Reference:** CWE-89 – Improper Neutralization of Special Elements in SQL Command ￼

## 3. Code Injection (CWE-94)

**Rule:** Do not eval or exec untrusted input. Functions like eval(), exec(), or dynamic compile() on user data allow execution of arbitrary code. Use safer parsing or whitelisting for needed dynamic behavior.
**Reference:** CWE-94 – Improper Control of Generation of Code (Code Injection) ￼

## 4. Path Traversal (CWE-22)

**Rule:** Validate and sanitize file paths derived from user input. An application that uses user-provided path components (for file open, save, include, etc.) must prevent special path elements like .. that could resolve outside allowed directories. Use os.path.normpath and restrict to a known safe base directory.
**Reference:** CWE-22 – Improper Limitation of Pathname to Restricted Directory (Path Traversal) ￼

## 5. Improper Neutralization of Input During Web Page Generation, Cross-Site Scripting (CWE-79)

**Rule:** Cross-Site Scripting (XSS) is a prevalent security vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. This occurs when a web application includes untrusted data in its output without proper validation or escaping, leading to the execution of malicious scripts in the context of the user’s browser. Validate and sanitize all user inputs on both client and server sides. Encode data before rendering it in the browser, especially in HTML, JavaScript, and CSS contexts. Implement libraries such as OWASP’s ESAPI to handle encoding and validation. Implement CSP headers to restrict sources of executable scripts. Set cookies with the HttpOnly and Secure flags to prevent access via client-side scripts.
**Reference:** CWE-79 – Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) ￼

## 6. Improper Neutralization of Special Elements in Template Engine (CWE-1336)

**Rule:** Treat user input as data, not as template code. If using template engines like Jinja2, never disable auto-escaping or directly evaluate user-provided template expressions. Failing to neutralize special template syntax can allow attackers to inject template directives or code.
**Reference:** CWE-1336 – Improper Neutralization of Special Elements in Template Engine ￼

## 7. Cross-Site Request Forgery (CWE-352)

**Rule:** CSRF occurs when a malicious website tricks a user’s browser into making an unintended request to a target website where the user is already authenticated (e.g., via a session cookie or stored token). Because the request comes from the user’s browser, the application may mistakenly trust the request — even though the user didn’t intend to perform the action. CSRF is a vulnerability in the application’s trust of the user’s browser, not a flaw in the user’s browser itself. What to look for in Python code: State-changing HTTP methods (e.g., POST, PUT, DELETE) are used and CSRF protection used. Using raw request without validation. Enforce anti-CSRF tokens or SameSite cookies for state-changing requests. Without origin validation, attackers can trick a user’s browser into performing unwanted actions as the user. CSRF arises when an app “does not sufficiently ensure the request is from the expected source”. 
**Reference:** CWE-352 – Cross-Site Request Forgery (CSRF) ￼

## 8. Server-Side Request Forgery (CWE-918)

**Rule:** Server-Side Request Forgery (SSRF) occurs when an attacker tricks the server into making HTTP requests to arbitrary URLs, often using user-supplied input. The server acts as a proxy, potentially exposing internal services, metadata APIs, local files, or even other external targets.Be cautious when fetching URLs or resources based on user input. An app should restrict allowable targets (e.g. block internal IP ranges) when making server-side HTTP requests. An SSRF weakness occurs when a server fetches a user-specified URL without ensuring it’s the intended destination ￼. This can be abused to reach internal services.
**Reference:** CWE-918 – Server-Side Request Forgery (SSRF) ￼

## 9. Unrestricted File Upload (CWE-434)

**Rule:** Validate and constrain file uploads. If users can upload files without type/extension checks or path sanitization, an attacker might upload a malicious file (e.g. a script) and execute it. Allowing dangerous file types can lead to remote code execution ￼. Store uploads outside web roots and verify type.
**Reference:** CWE-434 – Unrestricted Upload of File with Dangerous Type ￼

## 10. Deserialization of Untrusted Data (CWE-502)

**Rule:** Deserialization of untrusted data occurs when an application deserializes (i.e., restores from a byte stream or string representation) input that comes from an untrusted source. If the deserialization process can instantiate arbitrary objects or execute code during object creation, an attacker may craft a malicious payload that triggers: Remote Code Execution (RCE), Denial of Service (DoS), Privilege Escalation, Authentication Bypass. Never deserialize untrusted data using pickle, marshal, or other serialization libraries that can instantiate arbitrary objects. Deserializing untrusted input without validation can result in malicious object creation and code execution ￼. Use safe serializers (JSON, etc.) or strict schema validation.
**Reference:** CWE-502 – Deserialization of Untrusted Data ￼

## 11. Unsafe YAML Loading (CVE-2017-18342)

**Rule:** Use yaml.safe_load instead of yaml.load on untrusted YAML input. The default yaml.load can construct arbitrary Python objects, potentially leading to code execution ￼. This was a known vulnerability (e.g. CVE-2017-18342). Always choose safe loaders for configuration files.
**Reference:** PyYAML CVE-2017-18342 – yaml.load() could execute arbitrary code with untrusted data ￼

## 12. XML External Entity (XXE) Injection (CWE-611)

**Rule:** Disable external entity processing in XML parsers. If an application accepts XML input, an attacker can define external entities (e.g., file URIs) that the parser will resolve, allowing file read or network requests from the server. Use parser options to forbid external entities (XMLParser(resolve_entities=False) or defusedxml libraries).
**Reference:** CWE-611 – Improper Restriction of XML External Entity Reference (XXE) ￼

## 13. Insecure Temporary File Handling (CWE-377)

**Rule:** Use secure functions for temp files (e.g. Python tempfile.NamedTemporaryFile). Creating temp files in an insecure manner (predictable name or incorrect permissions) can lead to race conditions or unauthorized file access. Avoid mktemp() and ensure temp files are not globally writable.
**Reference:** CWE-377 – Insecure Temporary File Creation ￼

## 14. Overly Permissive File Permissions (CWE-276)

**Rule:** Do not set world-writable or otherwise insecure permissions on files and directories. For example, avoid using os.chmod(..., 0o777). Software that sets insecure default permissions for sensitive resources can be exploited. Use least privilege (e.g. 0o600 for private files).
**Reference:** CWE-276 – Incorrect Default Permissions ￼

## 15. Use of Hard-Coded Credentials (CWE-798)

**Rule:** Never hard-code passwords, API keys, or other credentials in code. Secrets in source are often extracted by attackers. For example, a product containing a hard-coded password or cryptographic key is a significant risk ￼. Use secure storage (vaults, env variables) and pass credentials at runtime.
**Reference:** CWE-798 – Use of Hard-coded Credentials ￼

## 16. Hard-Coded Cryptographic Keys (CWE-321)

**Rule:** **Rule:** CWE-321 (Hard-Coded Cryptographic Keys) refers to any instance where cryptographic secrets such as encryption keys, passwords, or salts are directly embedded in source code in any form. This includes but is not limited to:1. String literals used as keys (e.g., "mykey123") 2. Byte strings (e.g., b'secret_key') 3. Hex-encoded strings (e.g., "a1b2c3d4e5f6") 4. Base64-encoded values 5. Any hardcoded value passed to cryptographic functions like encrypt(), decrypt(), AESGCM(), Cipher(), etc. The vulnerability occurs whenever these values are statically defined in the code rather than being retrieved from secure external sources like environment variables, secure vaults, or key management systems. Any key that is visible in the source code, regardless of its format or how it's used, represents a CWE-321 vulnerability. 
**Reference:** CWE-321 – Use of Hard-coded Cryptographic Key ￼

## 17. Use of Broken or Risky Cryptographic Algorithms (CWE-327)

**Rule:** Avoid outdated cryptography such as MD5, SHA-1, DES, or RC4. These algorithms are considered broken or weak and may lead to data compromise ￼. Use modern hashing (SHA-256/3, bcrypt/Argon2 for passwords) and encryption (AES/GCM, etc.).
**Reference:** CWE-327 – Use of a Broken or Risky Cryptographic Algorithm ￼

## 18. Inadequate Encryption Strength (CWE-326)

**Rule:** Use sufficiently strong keys and algorithms for encryption. Avoid using: RSA keys < 2048 bits, DES (56-bit), 3DES with 2 keys, RC4 (any key size), MD5, SHA-1, Blowfish < 128 bits, ECDSA < 224 bits, DSA < 2048 bits, Diffie-Hellman < 2048 bits, and any custom encryption algorithms. A weak encryption scheme can be brute-forced with current techniques. Follow current standards (e.g., AES-256 for symmetric encryption, RSA-3072 or greater for asymmetric, SHA-256 or better for hashing, and ECDSA with P-256 curves or stronger). The following encryption algorithms and key sizes are considered insecure by modern standards:Symmetric Encryption:DES (Data Encryption Standard) - 56-bit keys,3DES (Triple DES) with 2 keys - effectively 112-bit,RC4 (any key size) - broken due to statistical weaknesses,Blowfish with keys smaller than 128 bits,AES with 128-bit keys (becoming weaker, though not immediately broken),Asymmetric Encryption:RSA with keys smaller than 2048 bits,DSA with keys smaller than 2048 bits,Diffie-Hellman with groups smaller than 2048 bits,ECDSA/ECDH with curves smaller than 224 bits,ElGamal with keys smaller than 2048 bits,Hash Functions:MD5 (128-bit) - completely broken,SHA-1 (160-bit) - vulnerable to collision attacks,RIPEMD-160 - becoming vulnerable,
**Reference:** CWE-326 – Inadequate Encryption Strength ￼

## 19. Cryptographically Weak PRNG (CWE-338)

**Rule:** CWE-338 refers to the use of non-cryptographically secure random number generators (like Python’s random.random() or JavaScript’s Math.random()) in security-critical operations, such as: Generating session tokens, Reset tokens, CSRF tokens, Passwords, Cryptographic keys, Nonces. These standard PRNGs are fast but predictable — they are designed for simulations, not security. An attacker who can observe some outputs or guess the internal state of the generator may be able to predict future or past values, undermining the security of the system.Do not use random.random() or other non-cryptographic RNGs for security-sensitive values (passwords, tokens, etc.). Using a predictable pseudo-RNG in a security context can undermine security ￼. Instead, use Python’s secrets or os.urandom for cryptographic randomness.
**Reference:** CWE-338 – Use of Cryptographically Weak PRNG ￼

## 20. Disabling SSL/TLS Certificate Validation (CWE-295)

**Rule:** Never disable SSL certificate verification in HTTP clients (requests.get(..., verify=False) or custom SSL contexts without verification). Failing to validate certificates opens the door to man-in-the-middle attacks ￼. Use proper CA verification or pinning as needed.
**Reference:** CWE-295 – Improper Certificate Validation ￼

## 21. Ignoring SSH Host Key Verification (CWE-345)

**Rule:** Do not auto-add or ignore SSH host key verification (e.g. using Paramiko with AutoAddPolicy). Skipping host key checks can allow MITM attacks on SSH connections. This falls under insufficient authenticity verification ￼. Always verify server host keys via a known trusted store.
**Reference:** CWE-345 – Insufficient Verification of Data Authenticity ￼

## 22. Use of Insecure Telnet Protocol (Bandit-B401)

**Rule:** Avoid using Telnet (telnetlib or subprocess calls) for network communication. Telnet sends data (including credentials) in plaintext and is vulnerable to eavesdropping ￼. Use SSH or other encrypted protocols instead.
**Reference:** Bandit B401 – Telnet Usage (Telnet is insecure, no encryption) ￼

## 23. Use of Insecure FTP Protocol (Bandit-B321)

**Rule:** Do not use FTP or plain FTP libraries (ftplib) for transferring sensitive data. FTP credentials and data are transmitted in cleartext ￼. Prefer SFTP/FTPS or other secure file transfer methods to prevent interception.
**Reference:** Bandit B321 – FTP Usage (FTP is insecure, use SSH/SFTP) ￼

## 24. Cleartext Transmission of Sensitive Information (CWE-319)

**Rule:** Never send sensitive data (passwords, session tokens, personal info) over unencrypted channels (HTTP, SMTP without TLS, etc.). If an application transmits sensitive info in cleartext, attackers can sniff it ￼. Enforce HTTPS for all confidential communications.
**Reference:** CWE-319 – Cleartext Transmission of Sensitive Information ￼

## 25. Missing Authentication for Critical Function (CWE-306)

**Rule:** CWE-306 refers to a situation where an application fails to enforce authentication before allowing access to a sensitive or critical functionality. In other words, unauthenticated users are allowed to perform actions that should be restricted to authenticated (and often authorized) users. Enforce authentication on all sensitive endpoints. Protect critical functionalities with proper authentication. The application should not allow access to privileged actions without login. For example, admin interfaces or sensitive operations must require a verified identity. Ensure all critical endpoints check user auth status.
**Reference:** CWE-306 – Missing Authentication for Critical Function ￼

## 26. Improper Authentication (CWE-287)

**Rule:** Implement robust authentication checks. This covers logic flaws like accepting forged tokens or weak credential checks. If the software does not correctly prove a user’s identity (e.g. accepts an unverifed JWT or static token), an attacker can impersonate others. Use strong multi-factor verification and standard frameworks.
**Reference:** CWE-287 – Improper Authentication ￼

## 27. Missing Authorization (CWE-862)

**Rule:** CWE-862 refers to a security flaw where an application fails to check whether an authenticated user has permission to perform a certain action or access specific data. In other words: The user is logged in (authenticated).But the application doesn’t verify whether they are allowed to do what they’re trying to do. This is a missing authorization check, and it opens the door to privilege escalation or insecure direct object access (IDOR).Enforce authorization on sensitive actions and data. Every request to access resources should verify the requester’s permissions. Missing authorization checks (e.g. failing to verify role or ownership) allow privilege escalation. Use declarative access control (decorators, middleware) consistently on protected endpoints.
**Reference:** CWE-862 – Missing Authorization ￼

## 28. Incorrect Authorization (CWE-863)

**Rule:** Always perform authorization checks on the server side, never rely solely on client-side checks. Use a centralized authorization mechanism that is consistently applied across all application components. Implement the principle of least privilege - grant only the minimum necessary permissions. Leverage well-tested authorization frameworks and libraries rather than building custom solutions. Consider using RBAC (Role-Based Access Control), ABAC (Attribute-Based Access Control), or ReBAC (Relationship-Based Access Control) based on application needs. Use standardized OAuth 2.0 or OIDC flows for identity and authorization when applicable. Never trust client-supplied identity or role information. Always retrieve user roles, permissions, and attributes from trusted server-side sources. Implement a session management system that securely associates users with their verified permissions. Incorrect Authorization occurs when an application either skips a necessary authorization check, uses an inappropriate property to authorize an action or access, or otherwise misapplies its access control logic. This may result from: Trusting unsafe input (like role/user data supplied by the client-side request). Checking the "wrong" user property, identifier, or failing to check at all. Accepting unverified or easily forged credentials/tokens. Authorization checks present in some code paths but skipped in others. Relying on hidden fields, request payload parameters, or any property under user influence without strong validation. Making authorization decisions without reference to server-side, validated identity and permissions. 
**Reference:** 863 – Improper Authorization

## 29. Debug Mode Enabled in Production (CWE-489)

**Rule:** Never run production web applications with debug features enabled. For example, in Flask applications, app.run(debug=True) enables debug mode, which should never be used in production. Declaring debug=True in frameworks such as Flask, Django, or Werkzeug allows attackers to access powerful debugging consoles or stack traces, potentially leading to arbitrary code execution if the application is accessible over a network. Detection Clues: Code lines such as app.run(debug=True), flask run --debug, manage.py runserver --debug, or any use of a debug flag in application startup logic.
**Reference:** CWE-489 Active Debug Code ￼

## 30. Binding to All Network Interfaces (Bandit-B104)

**Rule:** Avoid binding server sockets to 0.0.0.0 (all interfaces) unless necessary. Binding indiscriminately can expose services on unintended networks ￼ (e.g. a development server accessible from the internet). Prefer localhost (127.0.0.1) for internal services or appropriately firewall the service.
**Reference:** Bandit B104 – Binding to all interfaces may open service to unintended access ￼

## 31. Logging Sensitive Information (CWE-532)

**Rule:** Don’t log secrets, credentials, or personal data in plaintext. Log files are often less protected and an attacker or insider could glean sensitive info from them ￼. For example, avoid printing passwords in exception traces or including full credit card numbers in logs. Use redaction or avoid logging sensitive fields.
**Reference:** CWE-532 – Insertion of Sensitive Information into Log Files ￼

## 32. Improper Input Validation (CWE-20)

**Rule:** Proper input validation should follow a "whitelist" approach that defines exactly what is acceptable and rejects anything that doesn't match these criteria. All data from external sources—including users, APIs, files, databases, and network communications—should be treated as untrusted and thoroughly validated. Improper Input Validation (CWE-20) is a widespread security vulnerability that occurs when an application fails to properly verify and validate data from external sources before processing it. This vulnerability can lead to various security issues including:SQL/NoSQL injection,Command injection,Path traversal,Cross-site scripting (XSS),Buffer overflows,Denial of service,Business logic bypasses. The fundamental issue is that the application processes user input without ensuring it meets expected properties such as type, range, format, length, or consistency. Attackers can exploit this by providing unexpected or malformed inputs that manipulate the application into performing unintended actions or bypassing security controls.
**Reference:** CWE-20 – Improper Input Validation ￼

## 33. LDAP Injection (CWE-90)

**Rule:** Escape or filter special characters in LDAP queries. In apps that construct LDAP query filters from user input, an attacker can insert special LDAP metacharacters to modify the query logic ￼. Use parameterized LDAP queries or safe filter-building APIs. (Example: sanitizing (* and ) in search filters).
**Reference:** CWE-90 – Improper Neutralization of Special Elements in an LDAP Query ￼

## 34. NoSQL Injection (CWE-943)

**Rule:** CWE-943 refers to improper neutralization of user input in NoSQL queries, which can lead to query manipulation or injection attacks — similar in spirit to traditional SQL injection, but targeting databases like MongoDB, CouchDB, Firebase, etc. NoSQL injection allows attackers to inject special query operators (like $ne, $gt, $or, etc.) or modify the structure of the query to bypass authentication, access unauthorized data, or corrupt the database.Be cautious with user input in NoSQL (e.g. MongoDB) queries. Even though NoSQL uses different syntax, injection is possible (e.g. supplying JSON/operators that alter query logic). Use query parameterization or ORM. The software should neutralize special query operators in untrusted input. For instance, uncontrolled input to a Mongo query may allow adding $operators. Improper neutralization in data queries can let attackers modify query logic ￼. Use ORM or query builders that handle this, or validate expected structure.
**Reference:** CWE-943 – Improper Neutralization in Data Query Logic (NoSQL/ORM Injection)

## 35. Open Redirect (CWE-601)

**Rule:** Validate or restrict URLs supplied to redirects. If your application takes a URL parameter and redirects to it (for example, redirect(next_url) after login), ensure next_url is an internal path or belongs to allowed domains. An open redirect occurs when the app redirects to an untrusted site based on user input, potentially leading users to phishing or malware ￼. Use allow-lists or reject external URLs.
**Reference:** CWE-601 – URL Redirection to Untrusted Site (Open Redirect) ￼

## 36. Use of assert for Security Checks (Bandit-B101)

**Rule:** Do not use the assert statement to enforce security-critical conditions. In Python, asserts can be compiled out with optimizations, removing those checks ￼. For example, using assert user_is_admin to gate admin actions is insecure. Use regular if/raise logic for validations that must always run.
**Reference:** Bandit B101 – Use of assert will be removed in optimized bytecode ￼

## 37. Regular Expression Denial of Service (CWE-1333)

**Rule:** Limit the complexity of regex patterns applied to user input. Certain regex patterns have catastrophic backtracking behavior, where crafted input can make them consume excessive CPU (DoS) ￼. Avoid patterns with nested repetition (e.g. (.+)+), or use regex timeout libraries or re2-style engines that are safe from backtracking.
**Reference:** CWE-1333 – Inefficient Regular Expression Complexity (ReDoS) ￼

## 38. Insecure Logging Configuration Listener (SEMGREP-listen-eval)

**Rule:** Do not use logging.config.listen() in production or in libraries handling untrusted input. The listen() function starts a local socket server that accepts new logging configurations and applies them via eval. This can lead to code execution if untrusted users can send data to it ￼. In general, accept logging configs only from trusted sources or disable the feature.
**Reference:** Semgrep Security Guide – logging.config.listen() can lead to code execution via eval. ￼

## 39. Improperly Controlled Modification of Object Attributes (CWE-915)

**Rule:** Mass Assignment occurs when a web application automatically binds user-supplied input to fields in an object (e.g., database model, form, DTO) without restricting which fields are allowed to be set. This allows attackers to manipulate internal or sensitive fields that should not be user-controllable — like admin status, user roles, or passwords.When binding request data to objects or ORM models, limit the fields that can be set. Improperly controlling which object attributes can be modified can lead to Mass Assignment vulnerabilities ￼. For example, in Django, use ModelForm fields or exclude to whitelist allowed fields. This prevents attackers from updating fields like user roles or passwords by including them in request payloads.
**Reference:** CWE-915 – Improperly Controlled Modification of Object Attributes (Mass Assignment) ￼

## 40. Missing HttpOnly on Session Cookies (CWE-1004)

**Rule:** Mark session cookies with the HttpOnly flag. This flag prevents client-side scripts from accessing the cookie, mitigating XSS exploits from stealing sessions. If a cookie with sensitive info is not marked HttpOnly, it can be exposed to JavaScript and stolen by attackers ￼. Ensure your framework or code sets HttpOnly=True for session cookies.
**Reference:** CWE-1004 – Sensitive Cookie Without ‘HttpOnly’ Flag ￼

## 41. Missing Secure Flag on Cookies (CWE-614)

**Rule:** Mark cookies containing sensitive (like session tokens or authentication information) data as Secure. The Secure flag is a directive that tells browsers to only send the cookie over HTTPS connections.When this flag is missing:Cookies may be transmitted over unencrypted HTTP connections. This exposes the cookie data to packet sniffing/network eavesdropping. Attackers on the same network (or with access to network traffic) can intercept these cookies. The intercepted cookies can be used for session hijacking and account takeover. This vulnerability is particularly dangerous because many sites support both HTTP and HTTPS connections. Even if a user initially connects via HTTPS, a subsequent HTTP request to any resource on the same domain will include all cookies that don't have the Secure flag set.
**Reference:** CWE-614 – Sensitive Cookie in HTTPS Session Without ‘Secure’ Attribute ￼

## 42. Unsalted or Weak Password Hash (CWE-759)

**Rule:** Never store passwords in plaintext, and when hashing, use a salt and a strong, slow hash function. If you hash passwords without a salt or with a fast hash like MD5/SHA1, you greatly increase the risk of cracking via precomputed rainbow tables or brute force ￼. Use bcrypt/Argon2/PBKDF2 with unique salts to securely store passwords.
**Reference:** CWE-759 – Use of One-Way Hash Without a Salt ￼

## 43. Information Exposure Through Error Messages (CWE-209)

**Rule:** Don’t leak sensitive info in exception or error messages. Errors should be generic for users. Detailed stack traces or environment info should be logged internally but not returned to end-users. An overly verbose error can reveal implementation details, file paths, or user data ￼. Catch exceptions and return sanitized messages.
**Reference:** CWE-209 – Information Exposure Through an Error Message ￼

## 44. Use of Insecure Cipher Mode (CWE-327)

**Rule:** Avoid using Electronic Codebook (ECB) or other insecure modes for block cipher encryption. ECB mode is insecure because identical plaintext blocks produce identical ciphertext blocks, revealing patterns. Use CBC with random IV plus integrity (or GCM/CCM modes) for symmetric encryption to ensure confidentiality.
**Reference:** GuardRails Security – Insecure cipher modes like ECB are not semantically secure. CWE-327: Inadequate Encryption Strength

## 45. Deprecated SSL/TLS Protocols (Deprecated-Protocols)

**Rule:** Disable old protocol versions (SSL 2.0/3.0, TLS 1.0/1.1) in your TLS settings. Using deprecated protocols can expose the application to known attacks (e.g. POODLE on SSL3.0). For instance, SSL 3.0 has known weaknesses where an attacker can decrypt or alter communications ￼ ￼. Use only up-to-date TLS (1.2+ as of 2025) and configure strong cipher suites.
**Reference:** CISA Alert (POODLE) – SSL 3.0 is an old standard vulnerable to attack (Padding Oracle on Downgraded Legacy Encryption) ￼ ￼

## 46. Weak Password Policy (CWE-521)

**Rule:** Enforce strong password requirements for user accounts. If the application allows trivial passwords (short, common, or no complexity), it becomes easier for attackers to compromise accounts ￼. Implement minimum length (e.g. 8+), complexity or blacklist of common passwords, and possibly rate-limit or lockout on multiple failed attempts (to mitigate online guessing).
**Reference:** CWE-521 – Weak Password Requirements ￼

## 47. HTTP Response Splitting (CWE-113)

**Rule:** HTTP Response Splitting occurs when user input is included directly in an HTTP response header without proper sanitization, particularly without removing CR (\r) and LF (\n) characters. These characters are used to delimit headers and mark the end of the HTTP response headers and the start of the body. If an attacker can inject them, they can manipulate the structure of the HTTP response. Sanitize carriage return and line feed characters in any input that gets reflected into HTTP headers (e.g., in redirect or Set-Cookie headers). Use framework utilities for setting headers or explicitly strip \r \n from any header values.
**Reference:** CWE-113 – Improper Neutralization of CRLF in HTTP Headers (HTTP Response Splitting) ￼

## 48. Insufficient Session Expiration (CWE-613)

**Rule:** CWE-613 refers to a situation where an application fails to properly expire user sessions after logout, inactivity, or certain sensitive events. This leaves session tokens active for too long, creating a window of opportunity for attackers to hijack or reuse them. Ensure that user sessions timeout or invalidate appropriately (e.g. on logout or after inactivity). If session tokens remain valid indefinitely, stolen or cached tokens could be reused by attackers. Allowing reuse of old session IDs or credentials for too long increases risk ￼. Implement reasonable session lifetimes and invalidate all sessions upon sensitive changes (password reset, privilege change).
**Reference:** CWE-613 – Insufficient Session Expiration

## 49. Incorrect Usage of Seeds in Pseudo-Random Number Generator (CWE-335)
**Rule:** Never use predictable values (timestamps, user input, or fixed constants) as seeds for random number generators in security-sensitive contexts. If the seed value can be guessed, the entire output of the PRNG may be predictable, enabling attackers to bypass tokens or session mechanisms. Use the system default seeding for non-cryptographic PRNGs, and for security/cryptographic purposes, prefer cryptographic random sources (such as secrets or os.urandom) which do not require manual seeding.
**Reference:** CWE-335 – Incorrect Usage of Seeds in Pseudo-Random Number Generator ￼

## 50. Use of Predictable Algorithm in Random Number Generator (CWE-1241)
**Rule:** Avoid using predictable pseudo-random number generator (PRNG) algorithms for security-sensitive operations. PRNGs such as random.random(), Mersenne Twister, or other deterministic generators have a finite number of internal states and will eventually produce repeatable sequences. If an attacker can observe enough outputs or infer the internal state, they may be able to predict future values, compromising security. This is particularly dangerous in contexts like token generation, password resets, cryptographic key material, or session identifiers. Instead, use cryptographically secure randomness APIs such as secrets, os.urandom(), or hardware-based true random number generators (TRNGs), which are designed to produce unbiased, independent, and unpredictable values. TRNGs rely on physical entropy sources like electrical noise, which are resistant to reverse engineering and tampering.
**Reference:** CWE-1241 – Use of Predictable Algorithm in Random Number Generator
￼