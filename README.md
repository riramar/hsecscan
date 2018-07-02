[![GitHub version](https://badge.fury.io/gh/boennemann%2Fbadges.svg)](http://badge.fury.io/gh/boennemann%2Fbadges) [![GPL Licence](https://badges.frapsoft.com/os/gpl/gpl.svg?v=103)](https://opensource.org/licenses/GPL-2.0/) [![Open Source Love](https://badges.frapsoft.com/os/v2/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)
# hsecscan

A security scanner for HTTP response headers.

# Requirements

* Python 2.x

## Python Modules

* os.path
* argparse
* sqlite3
* urlparse
* urllib2
* urllib
* json
* ssl

# Install

```
$ pip install hsecscan
```

# Usage

```
$ hsecscan 
usage: hsecscan.py [-h] [-P] [-p] [-H Header] [-u URL] [-R] [-i]
                   [-U User-Agent] [-D DBFILE] [-d 'POST data'] [-x PROXY]
                   [-a]

A security scanner for HTTP response headers.

optional arguments:
  -h, --help            show this help message and exit
  -P, --database        Print the entire response headers database.
  -p, --headers         Print only the enabled response headers from database.
  -H Header, --header Header
                        Print details for a specific Header (example: Strict-
                        Transport-Security).
  -u URL, --URL URL     The URL to be scanned.
  -R, --redirect        Print redirect headers.
  -i, --insecure        Disable certificate verification.
  -U User-Agent, --useragent User-Agent
                        Set the User-Agent request header (default: hsecscan).
  -D DBFILE, --dbfile DBFILE
                        Set the database file (default: hsecscan.db).
  -d 'POST data', --postdata 'POST data'
                        Set the POST data (between single quotes) otherwise
                        will be a GET (example: '{ "q":"query string",
                        "foo":"bar" }').
  -x PROXY, --proxy PROXY
                        Set the proxy server (example: 192.168.1.1:8080).
  -a, --all             Print details for all response headers. Good for check
                        the related RFC.
```

# Example

```
$ hsecscan -i -u https://google.com
>> RESPONSE INFO <<
URL: https://www.google.com.br/?gfe_rd=cr&ei=GF5HV4ucH7DL8geg-aK4Dw
Code: 200
Headers:
 Date: Thu, 26 May 2016 20:35:36 GMT
 Expires: -1
 Cache-Control: private, max-age=0
 Content-Type: text/html; charset=ISO-8859-1
 P3P: CP="This is not a P3P policy! See https://www.google.com/support/accounts/answer/151657?hl=en for more info."
 Server: gws
 X-XSS-Protection: 1; mode=block
 X-Frame-Options: SAMEORIGIN
 Set-Cookie: NID=79=hDENeVI81zBYDtmqeCKAc5mxg6AQ-S24ahNqZ8El37rlJmYwUtgJg4vXAya7jKSyB2VqYI33JlLPacGonMPajpcDpUkb7mMtWMbNwIZQ8CyQBA1qXsRhjlLXU_4WExlI; expires=Fri, 25-Nov-2016 20:35:36 GMT; path=/; domain=.google.com.br; HttpOnly
 Alternate-Protocol: 443:quic
 Alt-Svc: quic=":443"; ma=2592000; v="34,33,32,31,30,29,28,27,26,25"
 Accept-Ranges: none
 Vary: Accept-Encoding
 Connection: close

>> RESPONSE HEADERS DETAILS <<
Header Field Name: X-XSS-Protection
Value: 1; mode=block
Reference: http://blogs.msdn.com/b/ie/archive/2008/07/02/ie8-security-part-iv-the-xss-filter.aspx
Security Description: This header enables the Cross-site scripting (XSS) filter built into most recent web browsers. It's usually enabled by default anyway, so the role of this header is to re-enable the filter for this particular website if it was disabled by the user. This header is supported in IE 8+, and in Chrome (not sure which versions). The anti-XSS filter was added in Chrome 4. Its unknown if that version honored this header.
Security Reference: https://www.owasp.org/index.php/List_of_useful_HTTP_headers
Recommendations: Use "X-XSS-Protection: 1; mode=block" whenever is possible (ref. http://blogs.msdn.com/b/ieinternals/archive/2011/01/31/controlling-the-internet-explorer-xss-filter-with-the-x-xss-protection-http-header.aspx).
CWE: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
CWE URL: https://cwe.mitre.org/data/definitions/79.html

Header Field Name: Set-Cookie
Value: NID=79=hDENeVI81zBYDtmqeCKAc5mxg6AQ-S24ahNqZ8El37rlJmYwUtgJg4vXAya7jKSyB2VqYI33JlLPacGonMPajpcDpUkb7mMtWMbNwIZQ8CyQBA1qXsRhjlLXU_4WExlI; expires=Fri, 25-Nov-2016 20:35:36 GMT; path=/; domain=.google.com.br; HttpOnly
Reference: https://tools.ietf.org/html/rfc6265
Security Description: Cookies have a number of security pitfalls. In particular, cookies encourage developers to rely on ambient authority for authentication, often becoming vulnerable to attacks such as cross-site request forgery. Also, when storing session identifiers in cookies, developers often create session fixation vulnerabilities. Transport-layer encryption, such as that employed in HTTPS, is insufficient to prevent a network attacker from obtaining or altering a victim's cookies because the cookie protocol itself has various vulnerabilities. In addition, by default, cookies do not provide confidentiality or integrity from network attackers, even when used in conjunction with HTTPS.
Security Reference: https://tools.ietf.org/html/rfc6265#section-8
Recommendations: Please at least read these references: https://tools.ietf.org/html/rfc6265#section-8 and https://www.owasp.org/index.php/Session_Management_Cheat_Sheet#Cookies.
CWE: CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
CWE URL: https://cwe.mitre.org/data/definitions/614.html

Header Field Name: Accept-Ranges
Value: none
Reference: https://tools.ietf.org/html/rfc7233#section-2.3
Security Description: Unconstrained multiple range requests are susceptible to denial-of-service attacks because the effort required to request many overlapping ranges of the same data is tiny compared to the time, memory, and bandwidth consumed by attempting to serve the requested data in many parts.
Security Reference: https://tools.ietf.org/html/rfc7233#section-6
Recommendations: Servers ought to ignore, coalesce, or reject egregious range requests, such as requests for more than two overlapping ranges or for many small ranges in a single set, particularly when the ranges are requested out of order for no apparent reason.
CWE: CWE-400: Uncontrolled Resource Consumption ('Resource Exhaustion')
CWE URL: https://cwe.mitre.org/data/definitions/400.html

Header Field Name: Server
Value: gws
Reference: https://tools.ietf.org/html/rfc7231#section-7.4.2
Security Description: Overly long and detailed Server field values increase response latency and potentially reveal internal implementation details that might make it (slightly) easier for attackers to find and exploit known security holes.
Security Reference: https://tools.ietf.org/html/rfc7231#section-7.4.2
Recommendations: An origin server SHOULD NOT generate a Server field containing needlessly fine-grained detail and SHOULD limit the addition of subproducts by third parties.
CWE: CWE-200: Information Exposure
CWE URL: https://cwe.mitre.org/data/definitions/200.html

Header Field Name: Cache-Control
Value: private, max-age=0
Reference: https://tools.ietf.org/html/rfc7234#section-5.2
Security Description: Caches expose additional potential vulnerabilities, since the contents of the cache represent an attractive target for malicious exploitation.  Because cache contents persist after an HTTP request is complete, an attack on the cache can reveal information long after a user believes that the information has been removed from the network.  Therefore, cache contents need to be protected as sensitive information.
Security Reference: https://tools.ietf.org/html/rfc7234#section-8
Recommendations: Do not store unnecessarily sensitive information in the cache.
CWE: CWE-524: Information Exposure Through Caching
CWE URL: https://cwe.mitre.org/data/definitions/524.html

Header Field Name: P3P
Value: CP="This is not a P3P policy! See https://www.google.com/support/accounts/answer/151657?hl=en for more info."
Reference: http://www.w3.org/TR/P3P11/#syntax_ext
Security Description: While P3P itself does not include security mechanisms, it is intended to be used in conjunction with security tools. Users' personal information should always be protected with reasonable security safeguards in keeping with the sensitivity of the information.
Security Reference: http://www.w3.org/TR/P3P11/#principles_security
Recommendations: -
CWE: -
CWE URL: -

Header Field Name: Content-Type
Value: text/html; charset=ISO-8859-1
Reference: https://tools.ietf.org/html/rfc7231#section-3.1.1.5
Security Description: In practice, resource owners do not always properly configure their origin server to provide the correct Content-Type for a given representation, with the result that some clients will examine a payload's content and override the specified type. Clients that do so risk drawing incorrect conclusions, which might expose additional security risks (e.g., "privilege escalation").
Security Reference: https://tools.ietf.org/html/rfc7231#section-3.1.1.5
Recommendations: Properly configure their origin server to provide the correct Content-Type for a given representation.
CWE: CWE-430: Deployment of Wrong Handler
CWE URL: https://cwe.mitre.org/data/definitions/430.html

Header Field Name: X-Frame-Options
Value: SAMEORIGIN
Reference: https://tools.ietf.org/html/rfc7034
Security Description: The use of "X-Frame-Options" allows a web page from host B to declare that its content (for example, a button, links, text, etc.) must not be displayed in a frame (<frame> or <iframe>) of another page (e.g., from host A). This is done by a policy declared in the HTTP header and enforced by browser implementations.
Security Reference: https://tools.ietf.org/html/rfc7034
Recommendations:  In 2009 and 2010, many browser vendors ([Microsoft-X-Frame-Options] and [Mozilla-X-Frame-Options]) introduced the use of a non-standard HTTP [RFC2616] header field "X-Frame-Options" to protect against clickjacking. Please check here https://www.owasp.org/index.php/Clickjacking_Defense_Cheat_Sheet what's the best option for your case.
CWE: CWE-693: Protection Mechanism Failure
CWE URL: https://cwe.mitre.org/data/definitions/693.html

>> RESPONSE MISSING HEADERS <<
Header Field Name: Pragma
Reference: https://tools.ietf.org/html/rfc7234#section-5.4
Security Description: Caches expose additional potential vulnerabilities, since the contents of the cache represent an attractive target for malicious exploitation.
Security Reference: https://tools.ietf.org/html/rfc7234#section-8
Recommendations: The "Pragma" header field allows backwards compatibility with HTTP/1.0 caches, so that clients can specify a "no-cache" request that they will understand (as Cache-Control was not defined until HTTP/1.1). When the Cache-Control header field is also present and understood in a request, Pragma is ignored. Define "Pragma: no-cache" whenever is possible.
CWE: CWE-524: Information Exposure Through Caching
CWE URL: https://cwe.mitre.org/data/definitions/524.html

Header Field Name: Public-Key-Pins
Reference: https://tools.ietf.org/html/rfc7469
Security Description: HTTP Public Key Pinning (HPKP) is a trust on first use security mechanism which protects HTTPS websites from impersonation using fraudulent certificates issued by compromised certificate authorities. The security context or pinset data is supplied by the site or origin.
Security Reference: https://tools.ietf.org/html/rfc7469
Recommendations: Deploying Public Key Pinning (PKP) safely will require operational and organizational maturity due to the risk that hosts may make themselves unavailable by pinning to a set of SPKIs that becomes invalid. With care, host operators can greatly reduce the risk of man-in-the-middle (MITM) attacks and other false- authentication problems for their users without incurring undue risk. PKP is meant to be used together with HTTP Strict Transport Security (HSTS) [RFC6797], but it is possible to pin keys without requiring HSTS.
CWE: CWE-295: Improper Certificate Validation
CWE URL: https://cwe.mitre.org/data/definitions/295.html

Header Field Name: Public-Key-Pins-Report-Only
Reference: https://tools.ietf.org/html/rfc7469
Security Description: HTTP Public Key Pinning (HPKP) is a trust on first use security mechanism which protects HTTPS websites from impersonation using fraudulent certificates issued by compromised certificate authorities. The security context or pinset data is supplied by the site or origin.
Security Reference: https://tools.ietf.org/html/rfc7469
Recommendations: Deploying Public Key Pinning (PKP) safely will require operational and organizational maturity due to the risk that hosts may make themselves unavailable by pinning to a set of SPKIs that becomes invalid. With care, host operators can greatly reduce the risk of man-in-the-middle (MITM) attacks and other false- authentication problems for their users without incurring undue risk. PKP is meant to be used together with HTTP Strict Transport Security (HSTS) [RFC6797], but it is possible to pin keys without requiring HSTS.
CWE: CWE-295: Improper Certificate Validation
CWE URL: https://cwe.mitre.org/data/definitions/295.html

Header Field Name: Strict-Transport-Security
Reference: https://tools.ietf.org/html/rfc6797
Security Description: HTTP Strict Transport Security (HSTS) is a web security policy mechanism which helps to protect secure HTTPS websites against downgrade attacks and cookie hijacking. It allows web servers to declare that web browsers (or other complying user agents) should only interact with it using secure HTTPS connections, and never via the insecure HTTP protocol. HSTS is an IETF standards track protocol and is specified in RFC 6797.
Security Reference: https://tools.ietf.org/html/rfc6797
Recommendations: Please at least read this reference: https://www.owasp.org/index.php/HTTP_Strict_Transport_Security.
CWE: CWE-311: Missing Encryption of Sensitive Data
CWE URL: https://cwe.mitre.org/data/definitions/311.html

Header Field Name: Frame-Options
Reference: https://tools.ietf.org/html/rfc7034
Security Description: The use of "X-Frame-Options" allows a web page from host B to declare that its content (for example, a button, links, text, etc.) must not be displayed in a frame (<frame> or <iframe>) of another page (e.g., from host A). This is done by a policy declared in the HTTP header and enforced by browser implementations.
Security Reference: https://tools.ietf.org/html/rfc7034
Recommendations:  In 2009 and 2010, many browser vendors ([Microsoft-X-Frame-Options] and [Mozilla-X-Frame-Options]) introduced the use of a non-standard HTTP [RFC2616] header field "X-Frame-Options" to protect against clickjacking. Please check here https://www.owasp.org/index.php/Clickjacking_Defense_Cheat_Sheet what's the best option for your case.
CWE: CWE-693: Protection Mechanism Failure
CWE URL: https://cwe.mitre.org/data/definitions/693.html

Header Field Name: X-Content-Type-Options
Reference: http://blogs.msdn.com/b/ie/archive/2008/09/02/ie8-security-part-vi-beta-2-update.aspx
Security Description: The only defined value, "nosniff", prevents Internet Explorer and Google Chrome from MIME-sniffing a response away from the declared content-type. This also applies to Google Chrome, when downloading extensions. This reduces exposure to drive-by download attacks and sites serving user uploaded content that, by clever naming, could be treated by MSIE as executable or dynamic HTML files.
Security Reference: https://www.owasp.org/index.php/List_of_useful_HTTP_headers
Recommendations: Always use the only defined value, "nosniff".
CWE: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
CWE URL: https://cwe.mitre.org/data/definitions/79.html

Header Field Name: Content-Security-Policy
Reference: http://www.w3.org/TR/CSP/
Security Description: Content Security Policy requires careful tuning and precise definition of the policy. If enabled, CSP has significant impact on the way browser renders pages (e.g., inline JavaScript disabled by default and must be explicitly allowed in policy). CSP prevents a wide range of attacks, including Cross-site scripting and other cross-site injections.
Security Reference: https://www.owasp.org/index.php/List_of_useful_HTTP_headers
Recommendations: Read the reference http://www.w3.org/TR/CSP/ and set according to your case. This is not a easy job.
CWE: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
CWE URL: https://cwe.mitre.org/data/definitions/79.html

Header Field Name: X-Content-Security-Policy
Reference: http://www.w3.org/TR/CSP/
Security Description: Content Security Policy requires careful tuning and precise definition of the policy. If enabled, CSP has significant impact on the way browser renders pages (e.g., inline JavaScript disabled by default and must be explicitly allowed in policy). CSP prevents a wide range of attacks, including Cross-site scripting and other cross-site injections.
Security Reference: https://www.owasp.org/index.php/List_of_useful_HTTP_headers
Recommendations: Read the reference http://www.w3.org/TR/CSP/ and set according to your case. This is not a easy job.
CWE: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
CWE URL: https://cwe.mitre.org/data/definitions/79.html

Header Field Name: X-WebKit-CSP
Reference: http://www.w3.org/TR/CSP/
Security Description: Content Security Policy requires careful tuning and precise definition of the policy. If enabled, CSP has significant impact on the way browser renders pages (e.g., inline JavaScript disabled by default and must be explicitly allowed in policy). CSP prevents a wide range of attacks, including Cross-site scripting and other cross-site injections.
Security Reference: https://www.owasp.org/index.php/List_of_useful_HTTP_headers
Recommendations: Read the reference http://www.w3.org/TR/CSP/ and set according to your case. This is not a easy job.
CWE: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
CWE URL: https://cwe.mitre.org/data/definitions/79.html

Header Field Name: Content-Security-Policy-Report-Only
Reference: http://www.w3.org/TR/CSP/
Security Description: Like Content-Security-Policy, but only reports. Useful during implementation, tuning and testing efforts.
Security Reference: https://www.owasp.org/index.php/List_of_useful_HTTP_headers
Recommendations: Read the reference http://www.w3.org/TR/CSP/ and set according to your case. This is not a easy job.
CWE: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
CWE URL: https://cwe.mitre.org/data/definitions/79.html
```

# Author

* [Ricardo Iramar dos Santos](mailto:ricardo.iramar@gmail.com)
