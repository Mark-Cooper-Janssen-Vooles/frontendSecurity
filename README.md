# Web Security 

## OWASP Top 10 Web Application Security 
the 10 most common web application attacks, their impact and how they can be prevented or mitigated

### 2021 top 10
1. [Injection](#injection)
2. [Broken Authentication](#broken-authentication-and-session-management)
3. Sensitive Data Exposure
4. XML Eternal Entities
5. [Broken Access Control](#broken-access-control)
6. Security Misconfiguration
7. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
8. Insecure Deserialization
9. Using Components with Known vulnerabilities
10. Insufficient logging & monitoring

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