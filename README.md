# Web Security 

Contents:
- [OWASP Top 10 Web Application Security](#owasp-top-10-web-application-security)
- [Website hacking penetration](#penetration-testing)
- [React specific security](#react-specific-security)

---

## OWASP Top 10 Web Application Security 
the 10 most common web application attacks, their impact and how they can be prevented or mitigated

Quick way to test your web app security: https://www.ssllabs.com/ssltest/index.html

### 2021 top 10
1. [Injection](#injection)
2. [Broken Authentication](#broken-authentication-and-session-management)
3. [Sensitive Data Exposure](#sensitive-data-exposure)
4. [XML Eternal Entities](#xml-external-entities)
5. [Broken Access Control](#broken-access-control)
6. [Security Misconfiguration](#security-misconfiguration)
7. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
8. [Insecure Deserialization](#insecure-deserialization)
9. [Using Components with Known vulnerabilities](#using-components-with-known-vulnerabilities)
10. [Insufficient logging & monitoring](#insufficient-logging--monitoring)
Other previous top 10:
- [insufficent attack protection](#insufficient-attack-protection)
- [cross-site request forgery](#cross-site-request-forgery-csrf)
- [underprotected apis](#underprotected-apis)
- [cryptographic failures](#cryptographic-failures)
- [insecure design](#insecure-design)
- [software and data integrity failures](#)

---

### Injection 
- What is it? Untrusted user input is interpreted by server and executed 
- Impact? Data can be stolen, modified or deleted 
- How to prevent? 
  - Reject untrusted / invalid input data 
  - Use latest frameworks 
  - Typically found by penetration testers / secure code review 

The most common type of injection is 'SQL Injection' 
- never trust user input, always 'sanitise' it. 

---

### Broken Authentication and Session management
- What is it? Incorrectly build auth and session management scheme that allows an attacker to impersonate another user 
- Impact? Attacker can take the identity of the victim
- How to prevent?
  - Don't develop your own authentication schemes 

What to do?
- Use open source frameworks actively maintained by the community
- Use strong passwords (incl. upper, lower, number, special characters)
- Require current credential when sensitive information is requested or changed 
- MFA authentication (eg sms, password, fingerprint, iris scan etc)
- Log out or expire session after X amount of time 
- Be careful with the 'remember me' functionality

---

### Sensitive Data Exposure
- What is it? Sensitive data is exposed, e.g. social security numbers, passwords, health records
- What is the impact? Data that is lost, exposed or corrupted can have severe impact on business continuity
- How to prevent?
  - Always obscure data (credit card numbers for example are almost always obscured)
  - Update cryptographic algorithm (MD5, DES, SHA-0 and SHA-1 are insecure)
  - Use salted encryption on storage of passwords 

---

### Broken Access Control
- What is it? Restrictions on what authenticated users are allowed to do are not properly enforced 
- What is the impact? Attackers can assess data, view sensitive files and modify data
- How to prevent? 
  - Application should not solely rely on user input; check access rights on UI level and server level for requests to resources (e.g. data)
  - Deny access by default 

Example:
- patient visits doctor 
- patient belongs to hospital.com/patients/account 
- when patient visits doctor, doctor is logged in. patient remembers doctors url: hospital.com/doctor/account
- patient remembers doctors url, they authenticate themselves with their account, then input the doctors url 
- patient can then see all the doctors patients info - patient is logged in as doctor 

--- 

### Security Misconfiguration
- What is it? Human mistake of misconfiguring the system (e.g. providing a user with a default password) - very broad 
- What is the impact? Depends on the misconfiguration. Worst misconfiguration could result in loss of the system
- How to prevent? 
  - Force change of default credentials
  - Least privilege: turn everything off by default in production (debugging, admin interface, etc)
  - Static tools that scan code for default settings
  - Keep patching, updating and testing the system
  - Regularly audit system deployment in production

--- 

### Cross-site Scripting (XSS)
- What is it? Untrusted user input is interpreted by browser and executed 
- Impact? Hijack user sessions, deface websites, change content (redirecting to malicious website)
- Prevention? 
  - escape untrasted input data
  - latest UI framework

OWASP has a cheatsheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

Example:
- Social media page of Bob
- Bob has a photo, text, a malicious script, and more text
- called a "persistent XSS attack" as its persisted in the DB of the social media page 
- Alice views Bobs page, and now Alice and her page is affected. Eve views Alices page, and shes infected now too 

Another example:
- non-persistent 
- Attacker creates URL with malicious code 
- someone clicks this URL and is effected 

---

### Insecure Deserialization
- What is it? Error in translations between objects
- What is the impact? Remote code execution, denial of service. Impact depends on type of data on that server 
- How to prevent? 
  - Validate user input
  - Implement digital signatures on serialized objects to enforce integrity
  - Restrict usage and monitor deserialization and log exceptions and failure

---

### Using Components with Known Vulnerabilities
- What is it? Third-party components that the focal system uses (e.g. authentication frameworks)
- What is the impact? Depending on the vulnerability it could range from subtle to seriously bad 
- How to prevent?
  - Always stay current with third-party components
  - If possible, follow best practice of virtual patching

---

### XML External Entities 
- What is it? Many older or poorly configured XML processors/parsers evaluate external entity references within XML documents 
- What is the impact? Extraction of data, remote code execution and denial of service attack 
- How to prevent?
  - Use JSON to avoid serialization of sensitive data 
  - Patch or upgrade all XML processors and libraries 
  - Disable XXE and implement whitelisting 
  - Detect, resolve and verify XXE with static application security testing tools 

---

### Insufficient logging & monitoring
- Average time of noticing when an attacker is in your system: 190 days!
- What is it? Not able to witness or discover an attack when it happens or happened
- What is the impact? Allows attacker to persist and tamper, extract or destroy your data without you noticing it 
- How to prevent? 
  - Log login, access control and server-side input validation failures
  - Ensure logs can be consumed easily, but annot be tampered with
  - Continuously improve monitoring and alerting process
  - Mitigate impact of breach: Rotate, repave and Repair

---

### Insufficient Attack Protection
- What is it? Applications that are attacked but do not recognize it as an attack, letting the attacker attack again and again
- What is the impact? Leak of data, decrease application availability
- How to prevent?
  - Detect and log normal and abnormal use of application
  - Respond by automatically blocking abnormal users or range of IP addresses
  - Patch abnormal use quickly 

  e.g. 
  - Bob is a malicious user, he logs on 100 times per minute 
  - the backend tries to process log of attempts of Bob and fails 
  - Alice can't log on because the system is now unavailable 

---

### Cross-site Request Forgery (CSRF)
- What is it? An attack that forces a victim to execute unwanted actions on a web application in which they're currently authenticated 
- What is the impact? Victim unknowingly executes transaction 
- How to prevent?
  - Reauthenticate for all critical actions (e.g. transfer money)
  - Include hidden token in request 
  - Most web frameworks have built-in CSRF protection, but it isn't enabled by default!

---

### Underprotected APIs
- What is it? Applications expose rich connectivitiy options through APIs, in the browser to a user. These APIs are often unprotected and contain numerous vulnerabilities
- What is the impact? Data theft, corruption, unauthorized access, etc 
- How to prevent? 
  - Ensure secure communication between client browser and server API
  - Reject untrusted/invalid input data
  - Use latest framework
  - Vulnerabilities are typically found by penetration testers and secure code reviewers 

---

## Cryptographic Failures
- What is it? Ineffective execution & configuration of cryptography (e.g. Telnet, FTP, HTTP, MD5, WEP) - old protocols 
- What is the impact? Sensitive data exposure 
- How to prevent?
  - Never roll your own crypto! Use well-known open source libraries
  - Static code analysis tools can discover this issue 
  - Key management (creation, destruction, distribution, storage and use)

---

### Insecure Design 
- What is it? A failure to use security by design methods / principles resulting in a weak or insecure design
- What is the impact? Breach of confidentiality, integrity and availability
- How to prevent?
  - Secure lifecycle (embed security in each phase; requirements, design, development, test, deployment, maintenance and decomissioning)
  - Use manual (e.g. code review, threat modelling) and automated (e.g. SAST and DAST) methods to improve security

---

### Software and Data Integrity Failures
- What is it? E.g. an application that relies on updates from a trusted external source, however the update mechanism is compromised
- What is the impact? Supply chain attack; data exfiltration, ransomeware, etc 
- How to prevent?
  - Verify input (in this case software updates with digital signatures)
  - Continuously check for vulnerabilities in dependencies 
  - Use software bill of materials 
  - unconnected backups 

e.g. Supplier alice sents update package to suppliers distributing software server, which sends update packages to multiple clients (good) but instead Malicious Bob sends malicious update package to supplier server, and this server then sends the malicious update package to multiple clients who are now all compromised. 

---

### Server-side request forgery 
- What is it? Misuse of prior established trust to access other resources. A web application is fetching a remote resource without validating the user-supplied URL
- What is the impact? Scan and connect to internal services. In some cases the attacker could access sensitive data
- How to prevent?
  - Sanitize and validate all client-supplied data
  - Segment remote server access functionality in separate networks to reduce the impact
  - Limitng connections to specific ports only (e.g. 443 for https)

i.e. Bob sends malformed request to impersonate the web server, web server sends requests to internal server. The DB server trusts the web server, doesn't sanitise anything, then executes the request from Bob (thus bob could access sensitive data)

---

## Penetration Testing 

---

## React Specific Security