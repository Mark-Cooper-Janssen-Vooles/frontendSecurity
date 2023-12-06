# Web Security 

## OWASP Top 10 Web Application Security 
the 10 most common web application attacks, their impact and how they can be prevented or mitigated

### 2021 top 10
1. [Injection](#injection)
2. [Broken Authentication](#broken-authentication-and-session-management)
3. Sensitive Data Exposure
4. XML Eternal Entities
5. Broken Access Control
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