## OWASP Top 10  
Identification and Authentication failures - missing mfa, weak pass  
Broken access control - idor  
Injection - SQL, XSS  
Server-side request forgery  - make server communicate internal/external services  
Cryptographic failures  - no https, weak algo, secrets in cleartext  
Insecure design  - no rate limit, management console on proxy port ?    
Security Misconfiguration - default creds, public buckets, debug mode on  
Vulnerable and outdated components - outdated javascript libraries    
Software and Data integrity failures -- insecure ci/cd, installing without signature checks, k8 repo compromises  
Security logging and monitoring failures -- no logs/alerts  

## Headers:  
**X-Frame-Options**: tells whether a web browser can load site within iframe, embed or object tags,   
Deny: denies framing altogether, sameorigin: framing from same origin of url – both good.  
But it cannot allow from multiple domains, hence csp is much better with  
Content-Security-Policy: frame-ancestors 'none'; or frame-ancestors 'self' https://partner-site.com https://trusted.example.org;  

**cache-control**: no-store, no-cache, must-revalidate  

**referrer-policy**:   no-referrer, same-orgin:sends full url to same origin,  
origin: sends only origin no path and query strings,  
strict-origin-when-cross-origin: full url to same-origin, just origin https://soda.com to cross origins and no referer to http. -- so this is the recommended one.  

**X-Content-Type-Options**: helps prevent XSS mainly, tells browser to strictly adhere to content-type declated in the response,  
say text/plain and if the response content is js, it should not be processed and execute js. Instead just render it as stated in the content-type.  

**CSP**: can prevent both  xss, click-jacks.  for inline scripts to allow use nonce! -- use csp evaluator  

**SOP**: hostaname port and protocol should match to be considered same origin,  
Same origin policy – default security mechanim in moden web browsers,  
It stops a script from one site from accessing the Document Object Model (DOM) of another site loaded in an iframe,  
or reading data retrieved via JavaScript APIs like XMLHttpRequest and fetch().. It cannot prevnet CSRF as doesn’t prevent attacker from sending cross origin requests.  

**CORS**: to relax same origin policy(SOP) -  
if application needs to allow cross origin access from a specific domain, then it can be defined with specific port and protocol.  
For this to work along with allow creds same site should not be strict, as cors and samesite are different   
even If cors allow and same-site blocks cookie – cors won't work for accessing authenticated resources !!   
if * or allow-credentials seen for any arbitrary origin header sent – then it’s an issue. !!   

**HSTS header**: Once a browser sees the HSTS header, it will no longer be able to load anything from your domain on regular HTTP.  
Something called hsts preload list in browsers – if domain is in it – even the first connection won't happen over 80.  
You can submit it to chrome https://hstspreload.org.  
Otherwise browser needs to see that first hsts header in the https response to prevent requests on 80.  
If not on pre-load list – mitm is still possible..   
hsts eliminates the need for redirection, ensures https only browsing, insecure cookies won't be sent on http,  
and improves performane eliminating need for redirection from http to https.  

## Cookie security  
secure: doesn’t send cookie on http, httpOnly=prevents js from accessing a cookie,  
_HOST-Cookie-Name: browser stores cookie only if secure, no domain attritbute, Path set to /  
Domain: default is set to exact host, but If domain is set – cookie will be sent to domain and its subdomains. 
Max-age and expires: if both set max-age takes preference in modern browsers !  
PATH: default is the path of resource that set the cookie, otherwise can be /admin, /dashboard etc 
samesite: none: allows cross-site but only over https, Lax: allows cross-site get only. Strict: no cross-site allowed – meaning cookie won't be sent in cross site requests.  
On modern browsers default is Lax 

## CSRF:  
attack within logged in users session, eg: bank trasfer url sendto=soda&amount=1000, if sending this to victim works.  
Check for csrf tokens – unique tokens per page request !  
csrf cookies are common to be referenced in js, as it prevents client-side scripts from reading the cookie hence no http-only attribute necessary.  
Same-site=lax/strict prevents csrf – because cookie won't be sent in strict, in lax only get requests supported. As long as no action in GET – it is suffice  
strict -- sends cookies when user is directly navigating within the same site - not sent when requess comes from other site, form from other domain  
Threrefore If site is vulnerable to XSS – then csrf from within same site will be possible with both strict and csrf protection !  

## Session Fixation:  
session identifier doesn’t change after successful login. Ex: cookie value.  

## Parameter tampering:  
playing with parameter values.. example.. from ?user=standard to ?user=admin  
## Parameter pollution:  
adding a duplicate parameter with a new value, an attacker can manipulate the application's logic,  
potentially leading to attacks like Cross-Site Scripting (XSS), data retrieval, or bypassing security controls.  
Client side: eg: xss:   https://example.com/search?q=shoes&q=<script>alert('hacked')  
Server side: eg:https://test.com?discount=10&discount=50  //server might use second instead of first or add both and give 60% discount.  

## Prototype Pollution:  
javascript specific vulnerability - DOM invader - 
to prevent: just block __proto__ in the input -- is kind of magic property whose value we define gets auto inherited to all other objects  
if user controlled input is used in js object modification then attacker can add __prototype__ property to the object which gets inherited by all objects.  
https://www.netspi.com/blog/technical-blog/web-application-pentesting/ultimate-guide-to-prototype-pollution/  
server side is more severe and high impact compared to client side pollution  
identity source and send the payload    

Prototype Pollution = Injecting properties into the base object globally  
Insecure Deserialization = Injecting or modifying object state during reconstruction  

## Insecure deserialization  
ysoserial  unserialize dont deserialize user controlled data burp scanner can identify if any serialized data   
when app accepts serialized data and deserializes it without validation  
react2shell payload tested from assetnote  
java php  data is base64 encoded  
try modifying serialized objects isAdmin:1 make sure to update string length   
access_token=0 or password=0  //auth byass on older php due to string defualt is 0 in == operation  
magic methods that are automatically available during derserailiztion  


## SQL Injection  
user input placed in backend sql queries without sanitization..  
input validation and pameterized queries  -- db treats the input as data not code  
 
in-band - errors/results to user eg: auth bypass,union,  
blind - no output but behaviour changes - time based, boolean based  
out-of-band - external comm very rare  

## Insecure Direct Object Reference-IDOR  
accesscontrol vuln allowing attackers to access/update/delete data by referencing an internal objects such as user id, file id, order num etc  

API specific:  
## BOLA(broken object level authorization)  
API security verion of IDOR, same as IDOR fetch or update objects we shouldn’t be allowed to.  

## Mass assignment:  
in an api  If the application blindly binds all provided fields to the object without an allowlist or proper validation,  
the attacker can successfully elevate their privileges eg:say updating user /profile?user=1 –  
adding admin=true – unknown parameter just guessing it, might make the user admin !!  

 

 

 
