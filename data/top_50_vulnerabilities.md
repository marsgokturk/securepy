# 50 Critical Security Rules for Python Code Analysis

## 1. OS Command Injection (CWE-78)

**Rule:** Avoid constructing OS command strings with unsanitized input. Dynamically building shell commands from user data can allow execution of unintended commands ￼. Use safer alternatives (e.g. subprocess.run with a list of arguments, and shell=False).
**Reference:** CWE-78 – Improper Neutralization of Special Elements in OS Command ￼

## 2. SQL Injection (CWE-89)

**Rule:** Never concatenate or format user input into SQL queries. Use parameterized queries or ORM query APIs. Building SQL commands with unescaped input can cause the input to be interpreted as SQL code ￼.
**Reference:** CWE-89 – Improper Neutralization of Special Elements in SQL Command ￼

## 3. Code Injection (CWE-94)

**Rule:** Do not eval or exec untrusted input. Functions like eval(), exec(), or dynamic compile() on user data allow execution of arbitrary code ￼. Use safer parsing or whitelisting for needed dynamic behavior.
**Reference:** CWE-94 – Improper Control of Generation of Code (Code Injection) ￼

## 4. Path Traversal (CWE-22)

**Rule:** Validate and sanitize file paths derived from user input. An application that uses user-provided path components (for file open, save, include, etc.) must prevent special path elements like .. that could resolve outside allowed directories ￼. Use os.path.normpath and restrict to a known safe base directory.
**Reference:** CWE-22 – Improper Limitation of Pathname to Restricted Directory (Path Traversal) ￼

## 5. Cross-Site Scripting (XSS, CWE-79)

**Rule:** Escape or sanitize user-supplied text before embedding it in HTML responses. Unneutralized user input in web pages can execute as script in the browser ￼. Use templating with auto-escaping or frameworks’ escaping functions to prevent XSS.
**Reference:** CWE-79 – Improper Neutralization of Input During Web Page Generation (Cross-site Scripting) ￼

## 6. Server-Side Template Injection (CWE-1336)

**Rule:** Treat user input as data, not as template code. If using template engines like Jinja2, never disable auto-escaping or directly evaluate user-provided template expressions. Failing to neutralize special template syntax can allow attackers to inject template directives or code ￼.
**Reference:** CWE-1336 – Improper Neutralization of Special Elements in Template Engine ￼

## 7. Cross-Site Request Forgery (CSRF, CWE-352)

**Rule:** Enforce anti-CSRF tokens or SameSite cookies for state-changing requests. Without origin validation, attackers can trick a user’s browser into performing unwanted actions as the user. CSRF arises when an app “does not sufficiently ensure the request is from the expected source” ￼.
**Reference:** CWE-352 – Cross-Site Request Forgery (CSRF) ￼

## 8. Server-Side Request Forgery (SSRF, CWE-918)

**Rule:** Be cautious when fetching URLs or resources based on user input. An app should restrict allowable targets (e.g. block internal IP ranges) when making server-side HTTP requests. An SSRF weakness occurs when a server fetches a user-specified URL without ensuring it’s the intended destination ￼. This can be abused to reach internal services.
**Reference:** CWE-918 – Server-Side Request Forgery (SSRF) ￼

## 9. Unrestricted File Upload (CWE-434)

**Rule:** Validate and constrain file uploads. If users can upload files without type/extension checks or path sanitization, an attacker might upload a malicious file (e.g. a script) and execute it. Allowing dangerous file types can lead to remote code execution ￼. Store uploads outside web roots and verify type.
**Reference:** CWE-434 – Unrestricted Upload of File with Dangerous Type ￼

## 10. Deserialization of Untrusted Data (CWE-502)

**Rule:** Never deserialize untrusted data using pickle, marshal, or other serialization libraries that can instantiate arbitrary objects. Deserializing untrusted input without validation can result in malicious object creation and code execution ￼. Use safe serializers (JSON, etc.) or strict schema validation.
**Reference:** CWE-502 – Deserialization of Untrusted Data ￼

## 11. Unsafe YAML Loading

**Rule:** Use yaml.safe_load instead of yaml.load on untrusted YAML input. The default yaml.load can construct arbitrary Python objects, potentially leading to code execution ￼. This was a known vulnerability (e.g. CVE-2017-18342). Always choose safe loaders for configuration files.
**Reference:** PyYAML CVE-2017-18342 – yaml.load() could execute arbitrary code with untrusted data ￼

## 12. XML External Entity (XXE) Injection (CWE-611)

**Rule:** Disable external entity processing in XML parsers. If an application accepts XML input, an attacker can define external entities (e.g., file URIs) that the parser will resolve, allowing file read or network requests from the server ￼. Use parser options to forbid external entities (XMLParser(resolve_entities=False) or defusedxml libraries).
**Reference:** CWE-611 – Improper Restriction of XML External Entity Reference (XXE) ￼

## 13. Insecure Temporary File Handling (CWE-377)

**Rule:** Use secure functions for temp files (e.g. Python tempfile.NamedTemporaryFile). Creating temp files in an insecure manner (predictable name or incorrect permissions) can lead to race conditions or unauthorized file access ￼. Avoid mktemp() and ensure temp files are not globally writable.
**Reference:** CWE-377 – Insecure Temporary File Creation ￼

## 14. Overly Permissive File Permissions (CWE-276)

**Rule:** Do not set world-writable or otherwise insecure permissions on files and directories. For example, avoid using os.chmod(..., 0o777). Software that sets insecure default permissions for sensitive resources can be exploited ￼. Use least privilege (e.g. 0o600 for private files).
**Reference:** CWE-276 – Incorrect Default Permissions ￼

## 15. Use of Hard-Coded Credentials (CWE-798)

**Rule:** Never hard-code passwords, API keys, or other credentials in code. Secrets in source are often extracted by attackers. For example, a product containing a hard-coded password or cryptographic key is a significant risk ￼. Use secure storage (vaults, env variables) and pass credentials at runtime.
**Reference:** CWE-798 – Use of Hard-coded Credentials ￼

## 16. Hard-Coded Cryptographic Keys (CWE-321)

**Rule:** Do not hard-code encryption keys or salts. A hard-coded cryptographic key greatly increases the chance that encrypted data can be recovered by attackers ￼. Keys should be generated at runtime or stored securely outside the source code (and rotated as needed).
**Reference:** CWE-321 – Use of Hard-coded Cryptographic Key ￼

## 17. Use of Broken or Risky Cryptographic Algorithms (CWE-327)

**Rule:** Avoid outdated cryptography such as MD5, SHA-1, DES, or RC4. These algorithms are considered broken or weak and may lead to data compromise ￼. Use modern hashing (SHA-256/3, bcrypt/Argon2 for passwords) and encryption (AES/GCM, etc.).
**Reference:** CWE-327 – Use of a Broken or Risky Cryptographic Algorithm ￼

## 18. Inadequate Encryption Strength (CWE-326)

**Rule:** Use sufficiently strong keys for encryption. For instance, RSA keys < 2048 bits or old 56-bit ciphers are too weak. A weak encryption scheme can be brute-forced with current techniques ￼. Follow current standards (e.g. 256-bit symmetric keys, >=2048-bit RSA).
**Reference:** CWE-326 – Inadequate Encryption Strength ￼

## 19. Cryptographically Weak PRNG (CWE-338)

**Rule:** Do not use random.random() or other non-cryptographic RNGs for security-sensitive values (passwords, tokens, etc.). Using a predictable pseudo-RNG in a security context can undermine security ￼. Instead, use Python’s secrets or os.urandom for cryptographic randomness.
**Reference:** CWE-338 – Use of Cryptographically Weak PRNG ￼

## 20. Disabling SSL/TLS Certificate Validation (CWE-295)

**Rule:** Never disable SSL certificate verification in HTTP clients (requests.get(..., verify=False) or custom SSL contexts without verification). Failing to validate certificates opens the door to man-in-the-middle attacks ￼. Use proper CA verification or pinning as needed.
**Reference:** CWE-295 – Improper Certificate Validation ￼

## 21. Ignoring SSH Host Key Verification

**Rule:** Do not auto-add or ignore SSH host key verification (e.g. using Paramiko with AutoAddPolicy). Skipping host key checks can allow MITM attacks on SSH connections. This falls under insufficient authenticity verification ￼. Always verify server host keys via a known trusted store.
**Reference:** CWE-345 – Insufficient Verification of Data Authenticity ￼

## 22. Use of Insecure Protocol – Telnet

**Rule:** Avoid using Telnet (telnetlib or subprocess calls) for network communication. Telnet sends data (including credentials) in plaintext and is vulnerable to eavesdropping ￼. Use SSH or other encrypted protocols instead.
**Reference:** Bandit B401 – Telnet Usage (Telnet is insecure, no encryption) ￼

## 23. Use of Insecure Protocol – FTP

**Rule:** Do not use FTP or plain FTP libraries (ftplib) for transferring sensitive data. FTP credentials and data are transmitted in cleartext ￼. Prefer SFTP/FTPS or other secure file transfer methods to prevent interception.
**Reference:** Bandit B321 – FTP Usage (FTP is insecure, use SSH/SFTP) ￼

## 24. Cleartext Transmission of Sensitive Information (CWE-319)

**Rule:** Never send sensitive data (passwords, session tokens, personal info) over unencrypted channels (HTTP, SMTP without TLS, etc.). If an application transmits sensitive info in cleartext, attackers can sniff it ￼. Enforce HTTPS for all confidential communications.
**Reference:** CWE-319 – Cleartext Transmission of Sensitive Information ￼

## 25. Missing Authentication for Critical Function (CWE-306)

**Rule:** Protect critical functionalities with proper authentication. The application should not allow access to privileged actions without login ￼. For example, admin interfaces or sensitive operations must require a verified identity. Ensure all critical endpoints check user auth status.
**Reference:** CWE-306 – Missing Authentication for Critical Function ￼

## 26. Improper Authentication (CWE-287)

**Rule:** Implement robust authentication checks. This covers logic flaws like accepting forged tokens or weak credential checks. If the software does not correctly prove a user’s identity (e.g. accepts an unverifed JWT or static token), an attacker can impersonate others ￼. Use strong multi-factor verification and standard frameworks.
**Reference:** CWE-287 – Improper Authentication ￼

## 27. Missing Authorization (CWE-862)

**Rule:** Enforce authorization on sensitive actions and data. Every request to access resources should verify the requester’s permissions. Missing authorization checks (e.g. failing to verify role or ownership) allow privilege escalation ￼. Use declarative access control (decorators, middleware) consistently on protected endpoints.
**Reference:** CWE-862 – Missing Authorization ￼

## 28. Incorrect Authorization (CWE-863)

**Rule:** Ensure authorization logic is correct and cannot be bypassed. For example, do not solely trust client-provided role identifiers or assume hidden fields can’t be tampered. If the app incorrectly performs an authorization check, users might access data or functions beyond their rights ￼. Test authorization thoroughly for each role.
**Reference:** CWE-285/863 – Improper Authorization ￼

## 29. Debug Mode Enabled in Production

**Rule:** Never run production web applications with debug features enabled (e.g. Flask(debug=True)). Framework debug modes (Werkzeug, etc.) often provide interactive consoles that allow arbitrary code execution ￼. Ensure debug/test backdoors are removed or disabled in deployed code.
**Reference:** Flask Debug Mode leads to Werkzeug remote console (code exec) ￼

## 30. Binding to All Network Interfaces

**Rule:** Avoid binding server sockets to 0.0.0.0 (all interfaces) unless necessary. Binding indiscriminately can expose services on unintended networks ￼ (e.g. a development server accessible from the internet). Prefer localhost (127.0.0.1) for internal services or appropriately firewall the service.
**Reference:** Bandit B104 – Binding to all interfaces may open service to unintended access ￼

## 31. Logging Sensitive Information (CWE-532)

**Rule:** Don’t log secrets, credentials, or personal data in plaintext. Log files are often less protected and an attacker or insider could glean sensitive info from them ￼. For example, avoid printing passwords in exception traces or including full credit card numbers in logs. Use redaction or avoid logging sensitive fields.
**Reference:** CWE-532 – Insertion of Sensitive Information into Log Files ￼

## 32. Improper Input Validation (CWE-20)

**Rule:** Validate all inputs for type, format, length, and range. Many vulnerabilities stem from assuming inputs are well-formed. If the software does not validate or incorrectly validates input data ￼, this can lead to injections, crashes, or logic issues. Employ whitelisting, strong typing, or schema validation for inputs from any external source (users, APIs, files).
**Reference:** CWE-20 – Improper Input Validation ￼

## 33. LDAP Injection (CWE-90)

**Rule:** Escape or filter special characters in LDAP queries. In apps that construct LDAP query filters from user input, an attacker can insert special LDAP metacharacters to modify the query logic ￼. Use parameterized LDAP queries or safe filter-building APIs. (Example: sanitizing (* and ) in search filters).
**Reference:** CWE-90 – Improper Neutralization of Special Elements in an LDAP Query ￼

## 34. NoSQL Injection

**Rule:** Be cautious with user input in NoSQL (e.g. MongoDB) queries. Even though NoSQL uses different syntax, injection is possible (e.g. supplying JSON/operators that alter query logic). The software should neutralize special query operators in untrusted input. For instance, uncontrolled input to a Mongo query may allow adding $operators. Improper neutralization in data queries can let attackers modify query logic ￼. Use ORM or query builders that handle this, or validate expected structure.
**Reference:** CWE-943 – Improper Neutralization in Data Query Logic (NoSQL/ORM Injection) ￼

## 35. Trojan Source (Invisible Character Attack)

**Rule:** Be aware of hidden Unicode control characters in source code. Attackers could embed bidirectional overrides or other non-printable chars in code to make malicious code invisible or appear benign to reviewers. This “Trojan Source” attack allows injection of logic that is not apparent visually ￼. Use static analysis or compilers with warnings for bidi characters and normalize source files.
**Reference:** Trojan Source Attack – Invisible bidirectional chars can hide code ￼

## 36. Open Redirect (CWE-601)

**Rule:** Validate or restrict URLs supplied to redirects. If your application takes a URL parameter and redirects to it (for example, redirect(next_url) after login), ensure next_url is an internal path or belongs to allowed domains. An open redirect occurs when the app redirects to an untrusted site based on user input, potentially leading users to phishing or malware ￼. Use allow-lists or reject external URLs.
**Reference:** CWE-601 – URL Redirection to Untrusted Site (Open Redirect) ￼

## 37. Use of assert for Security Checks

**Rule:** Do not use the assert statement to enforce security-critical conditions. In Python, asserts can be compiled out with optimizations, removing those checks ￼. For example, using assert user_is_admin to gate admin actions is insecure. Use regular if/raise logic for validations that must always run.
**Reference:** Bandit B101 – Use of assert will be removed in optimized bytecode ￼

38. Regular Expression Denial of Service (ReDoS, CWE-1333)

**Rule:** Limit the complexity of regex patterns applied to user input. Certain regex patterns have catastrophic backtracking behavior, where crafted input can make them consume excessive CPU (DoS) ￼. Avoid patterns with nested repetition (e.g. (.+)+), or use regex timeout libraries or re2-style engines that are safe from backtracking.
**Reference:** CWE-1333 – Inefficient Regular Expression Complexity (ReDoS) ￼

## 39. Insecure Logging Configuration Listener

**Rule:** Do not use logging.config.listen() in production or in libraries handling untrusted input. The listen() function starts a local socket server that accepts new logging configurations and applies them via eval. This can lead to code execution if untrusted users can send data to it ￼. In general, accept logging configs only from trusted sources or disable the feature.
**Reference:** Semgrep Security Guide – logging.config.listen() can lead to code execution via eval ￼

## 40. Mass Assignment (Over-binding, CWE-915)

**Rule:** When binding request data to objects or ORM models, limit the fields that can be set. Improperly controlling which object attributes can be modified can lead to Mass Assignment vulnerabilities ￼. For example, in Django, use ModelForm fields or exclude to whitelist allowed fields. This prevents attackers from updating fields like user roles or passwords by including them in request payloads.
**Reference:** CWE-915 – Improperly Controlled Modification of Object Attributes (Mass Assignment) ￼

## 41. Missing HttpOnly on Session Cookies (CWE-1004)

**Rule:** Mark session cookies with the HttpOnly flag. This flag prevents client-side scripts from accessing the cookie, mitigating XSS exploits from stealing sessions. If a cookie with sensitive info is not marked HttpOnly, it can be exposed to JavaScript and stolen by attackers ￼. Ensure your framework or code sets HttpOnly=True for session cookies.
**Reference:** CWE-1004 – Sensitive Cookie Without ‘HttpOnly’ Flag ￼

## 42. Missing Secure Flag on Cookies (CWE-614)

**Rule:** Mark cookies containing sensitive data as Secure. The Secure attribute ensures cookies are only sent over HTTPS. If not set, the cookie might be sent over plaintext HTTP if the site is accessed via HTTP, exposing it to sniffing ￼. Always set Secure=True on session cookies and any auth tokens.
**Reference:** CWE-614 – Sensitive Cookie in HTTPS Session Without ‘Secure’ Attribute ￼

## 43. Unsalted or Weak Password Hash (CWE-759)

**Rule:** Never store passwords in plaintext, and when hashing, use a salt and a strong, slow hash function. If you hash passwords without a salt or with a fast hash like MD5/SHA1, you greatly increase the risk of cracking via precomputed rainbow tables or brute force ￼. Use bcrypt/Argon2/PBKDF2 with unique salts to securely store passwords.
**Reference:** CWE-759 – Use of One-Way Hash Without a Salt ￼

## 44. Information Exposure Through Error Messages (CWE-209)

**Rule:** Don’t leak sensitive info in exception or error messages. Errors should be generic for users. Detailed stack traces or environment info should be logged internally but not returned to end-users. An overly verbose error can reveal implementation details, file paths, or user data ￼. Catch exceptions and return sanitized messages.
**Reference:** CWE-209 – Information Exposure Through an Error Message ￼

## 45. Use of Insecure Cipher Mode (e.g. ECB)

**Rule:** Avoid using Electronic Codebook (ECB) or other insecure modes for block cipher encryption. ECB mode is insecure because identical plaintext blocks produce identical ciphertext blocks, revealing patterns ￼. Use CBC with random IV plus integrity (or GCM/CCM modes) for symmetric encryption to ensure confidentiality.
**Reference:** GuardRails Security – Insecure cipher modes like ECB are not semantically secure ￼

## 46. Deprecated SSL/TLS Protocols

**Rule:** Disable old protocol versions (SSL 2.0/3.0, TLS 1.0/1.1) in your TLS settings. Using deprecated protocols can expose the application to known attacks (e.g. POODLE on SSL3.0). For instance, SSL 3.0 has known weaknesses where an attacker can decrypt or alter communications ￼ ￼. Use only up-to-date TLS (1.2+ as of 2025) and configure strong cipher suites.
**Reference:** CISA Alert (POODLE) – SSL 3.0 is an old standard vulnerable to attack (Padding Oracle on Downgraded Legacy Encryption) ￼ ￼

## 47. Using Components with Known Vulnerabilities

**Rule:** Keep third-party packages updated. An application that includes libraries or frameworks with known CVEs is at risk if not patched. The OWASP Top 10 highlights the danger of using components with known vulnerabilities – these can be exploited in your app if left unchanged ￼. Continuously monitor dependencies (use tools like Safety or Snyk) and update/patch them.
**Reference:** OWASP Top 10 – Use of Components with Known Vulnerabilities ￼

## 48. Weak Password Policy (CWE-521)

**Rule:** Enforce strong password requirements for user accounts. If the application allows trivial passwords (short, common, or no complexity), it becomes easier for attackers to compromise accounts ￼. Implement minimum length (e.g. 8+), complexity or blacklist of common passwords, and possibly rate-limit or lockout on multiple failed attempts (to mitigate online guessing).
**Reference:** CWE-521 – Weak Password Requirements ￼

## 49. HTTP Response Splitting (CWE-113)

**Rule:** Sanitize carriage return and line feed characters in any input that gets reflected into HTTP headers (e.g., in redirect or Set-Cookie headers). If an application inserts user input into headers without removing CR/LF, an attacker can inject header terminators and forge additional headers or split responses ￼. Use framework utilities for setting headers or explicitly strip \r \n from any header values.
**Reference:** CWE-113 – Improper Neutralization of CRLF in HTTP Headers (HTTP Response Splitting) ￼

## 50. Insufficient Session Expiration (CWE-613)

**Rule:** Ensure that user sessions timeout or invalidate appropriately (e.g. on logout or after inactivity). If session tokens remain valid indefinitely, stolen or cached tokens could be reused by attackers. Allowing reuse of old session IDs or credentials for too long increases risk ￼. Implement reasonable session lifetimes and invalidate all sessions upon sensitive changes (password reset, privilege change).
**Reference:** CWE-613 – Insufficient Session Expiration ￼