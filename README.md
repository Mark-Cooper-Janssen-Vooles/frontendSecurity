# Web Security 

Contents:
- [OWASP Top 10 Web Application Security](#owasp-top-10-web-application-security)
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

### Cryptographic Failures
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

## React Specific Security

### JSON Web tokens 
- you can use json web tokens over something like cookies and sessions 
- over at jwt.io we can put our json web token in 
- a json web token is a away to transfer information between two parties (i.e. one party is the frontend react app, the other party is your api)
  - they include a security feature that makes sure it wasn't tampered with along the way
- there are 3 portions: the header, the payload and the signature. 
  - the signature is a combination of the header, the payload and a secret combined to create a hash. If the header or payload is changed, the secret becomes invalid because it relie on them. 

- when we need to sign json web tokens, i.e. when a user signs-in, we can use a library like jsonwebtoken. 

````js
import * as jsonwebtoken;

const secretKey = 'secret123' // never use something simple and guessable like this 

const payload = {
  sub: '123', // sub claim, sub for subject, i.e. userId 123
  iss: 'example.com', // the issuer
  aud: 'api.example.com' // the audience
}

const token = jwt.sign(payload, secretKey, {
  expiresIn: '1h'
})
````
Do's and Don'ts: JSON Web Tokens 

Don'ts:
- you can store your tokens in local storage to see how they work, but once they're working you need to move them to an http-only cookie or keep them in the react state (browser memory)
  - risky to keep them in local storage, since its easily scriptable 
- don't keep secret keys that sign the tokens in the browser, only keep them in the backend and verify them there
- don't redecode tokens in the client 

Do's:
- keep long, strong, unguessable secrets. we use `secret123` for example only - don't do this in prod
- keep token payload small 
- use HTTPS - if not, then if someone intercepts your request people can find the tokens on the authorisation headers 

### Managing users authenticated state in frontend 
- This is necessary for you to be able to tell app how it can be used 
  - i.e. a dropdown menu that is set when the user is logged in (i.e 'logged out' etc)

1. Need to store the users authentication details in state 
    - Some prefer 'composition', this guy likes to use reacts 'context' api (avoid prop-drilling, similar to redux)
````js
function App() {
  return (
    <Router>
      <AuthProvider> // this is the 'context'
        <FetchProvider> // this is another 'context' 
          <div className="bg-gray-100">
            <AppRoutes />
          </div>
        </FetchProvider>
      </AuthProvider>
    </Router>
  );
}
````

2. Need to persist on refresh 
    - one way to do this is storing auth information in local storage
    - you should not be storing json web tokens in local storage (we're just doing this temporarily)
      - not safe a local storage is susceptible to cross site scripting attacks 

````js
  const token = localStorage.getItem('token');
  const userInfo = localStorage.getItem('userInfo');
  const expiresAt = localStorage.getItem('expiresAt');
  const [authState, setAuthState] = useState({
    token,
    expiresAt,
    userInfo: userInfo ? JSON.parse(userInfo) : {}
  });

  const setAuthInfo = ({ token, userInfo, expiresAt}) => {
    localStorage.setItem('token', token)
    localStorage.setItem('userInfo', JSON.stringify(userInfo))
    localStorage.setItem('expiresAt', expiresAt)
    setAuthState({
      token, 
      userInfo, 
      expiresAt
    })
  }
````

3. We need auth tools to help app make decisions about showing content to the user, or allowing navigation to particular places.
    - i.e. is the user authenticated or not? 
    - this is a big difference between round-trip applicaitons or single page applications when it comes to application state 
    - round-trip: every move goes to the backend, constructs html and returns it to the client. should be pretty simple.
    - when dealing with a SPA: those decisions need to be made on the SPA 
    - authentication on the client side: there is nothing you can do to prevent the user from setting localStorage etc to whatever they wanted to get authenticated 
    ` const isAuthenticated = () => localStorage.getItem('isAuthenticated') === true;`
    - slightly better way to do this: 
    ````js
    const isAuthenticated = () => {
      if (!authState.token || !authState.expiresAt) {
        return false;
      }
      return new Date().getTime() / 1000 < authState.expiresAt; 
    }

    const isAdmin = () => {
      return authState.userInfo.role === 'admin';
    }
    ````
    - you can also use 'isAdmin' to conditionally expose parts of the UI, or just check the auth state:

    ````js
    const navItems = [
      {
        label: 'Dashboard',
        path: 'dashboard',
        icon: faChartLine,
        allowedRoles: ['user', 'admin']
      },
      {
        label: 'Inventory',
        path: 'inventory',
        icon: faChartPie,
        allowedRoles: ['admin']
      },
    ]

    const Sidebar = () => {
      const authContext = useContext(AuthContext);
      const { role } = authContext.authState.userInfo;

      return (
        <section className="h-screen">
          <div className="w-16 sm:w-24 m-auto">
            <img src={logo} rel="logo" alt="Logo" />
          </div>
          <div className="mt-20">
            {navItems.map((navItem, i) =>
              <>
              {navItem.allowedRoles.includes(role) && (
                <NavItemContainer key={i}>
                  <NavItem navItem={navItem} />
                </NavItemContainer>
              )}
              </>
            )}
          </div>
        </section>
      );
    };
    ````
    - another application of this would be guarding client side routes based on auth states:
    ````js
    // in this code we use AuthenticatedRoutes for any routes that need to be authenticated.
    // if the user is not autheticated, they are redirected back to homepage  
    const AuthenticatedRoute = ({ children, ...rest }) => {
      const authContext = useContext(AuthContext);
      return (
        <Route {...rest} render={() =>
          authContext.isAuthenticated() ? (
            <AppShell>
              {children}
            </AppShell> 
          ) : (
            <Redirect to="/" />
          )
        } 
        />
      )
    }

    const AppRoutes = () => {

      return (
        <Switch>
          <Route path="/login">
            <Login />
          </Route>
          <Route path="/signup">
            <Signup />
          </Route>
          <Route exact path="/">
            <Home />
          </Route>
          <AuthenticatedRoute path="/dashboard" >
            <Dashboard />
          </AuthenticatedRoute>
          <AuthenticatedRoute path="/inventory">
              <Inventory />
          </AuthenticatedRoute>
          <AuthenticatedRoute path="/account">
            <Account />
          </AuthenticatedRoute>
          <AuthenticatedRoute path="/settings">
            <Settings />
          </AuthenticatedRoute>
          <AuthenticatedRoute path="/users">
            <Users />
          </AuthenticatedRoute>
          <Route path="*">
            <FourOFour />
          </Route>
        </Switch>
      );
    };
    ````
    - in some cases we may want certain routes accessible for certain roles only, i.e. maybe inventory is accessible only for those with admin access.
    

4. Logging out
    - When a user logs into a website that users cookies and sessions, there is a session that gets stored on the server for the user, and a cookie that gets sent back to the browser. 
      - When they want to log out, its a matter of clearning that session in the server and the cookie on the browser 
    - we're using stateless authentication using json web tokens so it works a little differently: 
      - theres nothing on the server to identify the state of the user
      - when the user goes to logout, we just need to clear local storage and reset auth state 