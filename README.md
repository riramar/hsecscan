# hsecscan

A security scanner for HTTP response headers.</p>

# Requirements

Python 2.x

# Usage

```
$ ./hsecscan.py 
usage: hsecscan.py [-h] [-P] [-p] [-u URL] [-R]

A security scanner for HTTP response headers.

optional arguments:
  -h, --help         show this help message and exit
  -P, --database     Print the entire response headers database.
  -p, --headers      Print only the enabled response headers from database.
  -u URL, --URL URL  The URL to be scanned.
  -R, --redirect     Print redirect headers.
```

# Example

```
$ ./hsecscan.py -u https://google.com -R
>> REDIRECT INFO <<
URL: https://google.com
Code: 302
Headers:
 Cache-Control: private
 Content-Type: text/html; charset=UTF-8
 Location: https://www.google.com.br/?gfe_rd=cr&ei=lkEtVr6sLqaX8QfVgIGYCA
 Content-Length: 263
 Date: Sun, 25 Oct 2015 20:54:46 GMT
 Server: GFE/2.0
 Alternate-Protocol: 443:quic,p=1
 Alt-Svc: quic=":443"; p="1"; ma=604800
 Connection: close

>> REDIRECT HEADERS DETAILS <<
Header Field Name: Content-Length
Reference: https://tools.ietf.org/html/rfc7230#section-3.3.2
Security Description: 
Recommendations: 
CWE: 
CWE URL: 

Header Field Name: Server
Reference: https://tools.ietf.org/html/rfc7231#section-7.4.2
Security Description: Overly long and detailed Server field values increase response latency and potentially reveal internal implementation details that might make it (slightly) easier for attackers to find and exploit known security holes.
Recommendations: An origin server SHOULD NOT generate a Server field containing needlessly fine-grained detail and SHOULD limit the addition of subproducts by third parties.
CWE: CWE-200: Information Exposure
CWE URL: https://cwe.mitre.org/data/definitions/200.html

Header Field Name: Connection
Reference: https://tools.ietf.org/html/rfc7230#section-6.1
Security Description: 
Recommendations: 
CWE: 
CWE URL: 

Header Field Name: Location
Reference: https://tools.ietf.org/html/rfc7231#section-7.1.2
Security Description:  Although fragment identifiers used within URI references are not sent in requests, implementers ought to be aware that they will be visible to the user agent and any extensions or scripts running as a result of the response. In particular, when a redirect occurs and the original request's fragment identifier is inherited by the new reference in Location, this might have the effect of disclosing one site's fragment to another site.
Recommendations: If the first site uses personal information in fragments, it ought to ensure that redirects to other sites include a (possibly empty) fragment component in order to block that inheritance.
CWE: CWE-200: Information Exposure
CWE URL: https://cwe.mitre.org/data/definitions/200.html

Header Field Name: Cache-Control
Reference: https://tools.ietf.org/html/rfc7234#section-5.2
Security Description: Caches expose additional potential vulnerabilities, since the contents of the cache represent an attractive target for malicious exploitation.  Because cache contents persist after an HTTP request is complete, an attack on the cache can reveal information long after a user believes that the information has been removed from the network.  Therefore, cache contents need to be protected as sensitive information.
Recommendations: Do not store unnecessarily sensitive information in the cache.
CWE: CWE-524: Information Exposure Through Caching
CWE URL: https://cwe.mitre.org/data/definitions/524.html

Header Field Name: Date
Reference: https://tools.ietf.org/html/rfc7231#section-7.1.1.2
Security Description: 
Recommendations: 
CWE: 
CWE URL: 

Header Field Name: Content-Type
Reference: https://tools.ietf.org/html/rfc7231#section-3.1.1.5
Security Description: In practice, resource owners do not always properly configure their origin server to provide the correct Content-Type for a given representation, with the result that some clients will examine a payload's content and override the specified type. Clients that do so risk drawing incorrect conclusions, which might expose additional security risks (e.g., "privilege escalation").
Recommendations: Properly configure their origin server to provide the correct Content-Type for a given representation.
CWE: CWE-430: Deployment of Wrong Handler
CWE URL: https://cwe.mitre.org/data/definitions/430.html

>> RESPONSE <<
URL: https://www.google.com.br/?gfe_rd=cr&ei=lkEtVr6sLqaX8QfVgIGYCA
Code: 200
Headers:
 Date: Sun, 25 Oct 2015 20:54:46 GMT
 Expires: -1
 Cache-Control: private, max-age=0
 Content-Type: text/html; charset=ISO-8859-1
 P3P: CP="This is not a P3P policy! See http://www.google.com/support/accounts/bin/answer.py?hl=en&answer=151657 for more info."
 Server: gws
 X-XSS-Protection: 1; mode=block
 X-Frame-Options: SAMEORIGIN
 Set-Cookie: PREF=ID=1111111111111111:FF=0:TM=1445806486:LM=1445806486:V=1:S=FBHaVyCMoT8ewoeP; expires=Thu, 31-Dec-2015 16:02:17 GMT; path=/; domain=.google.com.br
 Set-Cookie: NID=72=yeirrIfpYZuI2zaLBC5JshG_8HElY_RxKtwX2z3TjOsvN56F57mX4aTsje7HuVkfI2cF9ZOj5YYhLqFQMR83BtQsA1O8KoEA9xmgL7CVhn9NG8WyDwF79Y9ZMkwxS89uxP7oIGFK__8p4RXJH5qNd6U4tyLonXRx; expires=Mon, 25-Apr-2016 20:54:46 GMT; path=/; domain=.google.com.br; HttpOnly
 Alternate-Protocol: 443:quic,p=1
 Alt-Svc: quic="www.google.com:443"; p="1"; ma=600,quic=":443"; p="1"; ma=600
 Accept-Ranges: none
 Vary: Accept-Encoding
 Connection: close

>> RESPONSE HEADERS DETAILS <<
Header Field Name: X-XSS-Protection
Reference: http://blogs.msdn.com/b/ie/archive/2008/07/02/ie8-security-part-iv-the-xss-filter.aspx
Security Description: This header enables the Cross-site scripting (XSS) filter built into most recent web browsers. It's usually enabled by default anyway, so the role of this header is to re-enable the filter for this particular website if it was disabled by the user. This header is supported in IE 8+, and in Chrome (not sure which versions). The anti-XSS filter was added in Chrome 4. Its unknown if that version honored this header.
Recommendations: Use "X-XSS-Protection: 1; mode=block" whenever is possible (ref. http://blogs.msdn.com/b/ieinternals/archive/2011/01/31/controlling-the-internet-explorer-xss-filter-with-the-x-xss-protection-http-header.aspx).
CWE: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
CWE URL: https://cwe.mitre.org/data/definitions/79.html

Header Field Name: Set-Cookie
Reference: https://tools.ietf.org/html/rfc6265
Security Description: Cookies have a number of security pitfalls. In particular, cookies encourage developers to rely on ambient authority for authentication, often becoming vulnerable to attacks such as cross-site request forgery. Also, when storing session identifiers in cookies, developers often create session fixation vulnerabilities. Transport-layer encryption, such as that employed in HTTPS, is insufficient to prevent a network attacker from obtaining or altering a victim's cookies because the cookie protocol itself has various vulnerabilities. In addition, by default, cookies do not provide confidentiality or integrity from network attackers, even when used in conjunction with HTTPS.
Recommendations: Please at least read these references: https://tools.ietf.org/html/rfc6265#section-8 and https://www.owasp.org/index.php/Session_Management_Cheat_Sheet#Cookies.
CWE: CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
CWE URL: https://cwe.mitre.org/data/definitions/614.html

Header Field Name: Accept-Ranges
Reference: https://tools.ietf.org/html/rfc7233#section-2.3
Security Description: Unconstrained multiple range requests are susceptible to denial-of-service attacks because the effort required to request many overlapping ranges of the same data is tiny compared to the time, memory, and bandwidth consumed by attempting to serve the requested data in many parts.
Recommendations: Servers ought to ignore, coalesce, or reject egregious range requests, such as requests for more than two overlapping ranges or for many small ranges in a single set, particularly when the ranges are requested out of order for no apparent reason.
CWE: CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion')
CWE URL: https://cwe.mitre.org/data/definitions/400.html

Header Field Name: Expires
Reference: https://tools.ietf.org/html/rfc7234#section-5.3
Security Description: 
Recommendations: 
CWE: 
CWE URL: 

Header Field Name: Vary
Reference: https://tools.ietf.org/html/rfc7231#section-7.1.4
Security Description: 
Recommendations: 
CWE: 
CWE URL: 

Header Field Name: Server
Reference: https://tools.ietf.org/html/rfc7231#section-7.4.2
Security Description: Overly long and detailed Server field values increase response latency and potentially reveal internal implementation details that might make it (slightly) easier for attackers to find and exploit known security holes.
Recommendations: An origin server SHOULD NOT generate a Server field containing needlessly fine-grained detail and SHOULD limit the addition of subproducts by third parties.
CWE: CWE-200: Information Exposure
CWE URL: https://cwe.mitre.org/data/definitions/200.html

Header Field Name: Connection
Reference: https://tools.ietf.org/html/rfc7230#section-6.1
Security Description: 
Recommendations: 
CWE: 
CWE URL: 

Header Field Name: Cache-Control
Reference: https://tools.ietf.org/html/rfc7234#section-5.2
Security Description: Caches expose additional potential vulnerabilities, since the contents of the cache represent an attractive target for malicious exploitation.  Because cache contents persist after an HTTP request is complete, an attack on the cache can reveal information long after a user believes that the information has been removed from the network.  Therefore, cache contents need to be protected as sensitive information.
Recommendations: Do not store unnecessarily sensitive information in the cache.
CWE: CWE-524: Information Exposure Through Caching
CWE URL: https://cwe.mitre.org/data/definitions/524.html

Header Field Name: Date
Reference: https://tools.ietf.org/html/rfc7231#section-7.1.1.2
Security Description: 
Recommendations: 
CWE: 
CWE URL: 

Header Field Name: P3P
Reference: http://www.w3.org/TR/P3P11/#syntax_ext
Security Description: While P3P itself does not include security mechanisms, it is intended to be used in conjunction with security tools. Users' personal information should always be protected with reasonable security safeguards in keeping with the sensitivity of the information.
Recommendations: -
CWE: -
CWE URL: -

Header Field Name: Content-Type
Reference: https://tools.ietf.org/html/rfc7231#section-3.1.1.5
Security Description: In practice, resource owners do not always properly configure their origin server to provide the correct Content-Type for a given representation, with the result that some clients will examine a payload's content and override the specified type. Clients that do so risk drawing incorrect conclusions, which might expose additional security risks (e.g., "privilege escalation").
Recommendations: Properly configure their origin server to provide the correct Content-Type for a given representation.
CWE: CWE-430: Deployment of Wrong Handler
CWE URL: https://cwe.mitre.org/data/definitions/430.html

Header Field Name: X-Frame-Options
Reference: https://tools.ietf.org/html/rfc7034
Security Description: The use of "X-Frame-Options" allows a web page from host B to declare that its content (for example, a button, links, text, etc.) must not be displayed in a frame (<frame> or <iframe>) of another page (e.g., from host A). This is done by a policy declared in the HTTP header and enforced by browser implementations.
Recommendations:  In 2009 and 2010, many browser vendors ([Microsoft-X-Frame-Options] and [Mozilla-X-Frame-Options]) introduced the use of a non-standard HTTP [RFC2616] header field "X-Frame-Options" to protect against clickjacking. Please check here https://www.owasp.org/index.php/Clickjacking_Defense_Cheat_Sheet what's the best option for your case.
CWE: CWE-693: Protection Mechanism Failure
CWE URL: https://cwe.mitre.org/data/definitions/693.html
```
