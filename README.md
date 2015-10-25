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
$ ./hsecscan.py -u http://google.com
URL: http://www.google.com.br/?gfe_rd=cr&ei=uO8eVtCNA_Cp8weYqLCgAQ
Code: 200
Headers: 
Date: Thu, 15 Oct 2015 00:13:45 GMT
Expires: -1
Cache-Control: private, max-age=0
Content-Type: text/html; charset=ISO-8859-1
P3P: CP="This is not a P3P policy! See http://www.google.com/support/accounts/bin/answer.py?hl=en&answer=151657 for more info."
Server: gws
X-XSS-Protection: 1; mode=block
X-Frame-Options: SAMEORIGIN
Set-Cookie: PREF=ID=1111111111111111:FF=0:TM=1444868025:LM=1444868025:V=1:S=63__QH8d-rawj72t; expires=Thu, 31-Dec-2015 16:02:17 GMT; path=/; domain=.google.com.br
Set-Cookie: NID=72=CoRBDHqHqS4hFQZX_KM-EihW23odkCZSkndoN2tdH6DJY6lG--ZGRIGTQSZdqhePaWrWlBkwP0DXjt3r4OKLtnaU6ZsrVypT8GqJuN-9YzcDWHfamVpZTWd0b72YuiGNMDHBRH5X; expires=Fri, 15-Apr-2016 00:13:45 GMT; path=/; domain=.google.com.br; HttpOnly
Accept-Ranges: none
Vary: Accept-Encoding
Connection: close
 

  Header Field Name: X-XSS-Protection
  Type 1: Personal
  Protocol: http
  Status: 
  Reference: http://blogs.msdn.com/b/ie/archive/2008/07/02/ie8-security-part-iv-the-xss-filter.aspx
  Type 2: Response
  Enable: Y
  Required: Y
  HTTPS: N
  Security Description: This header enables the Cross-site scripting (XSS) filter built into most recent web browsers. It's usually enabled by default anyway, so the role of this header is to re-enable the filter for this particular website if it was disabled by the user. This header is supported in IE 8+, and in Chrome (not sure which versions). The anti-XSS filter was added in Chrome 4. Its unknown if that version honored this header.
  Security Reference: https://www.owasp.org/index.php/List_of_useful_HTTP_headers
  Recommendations: Use "X-XSS-Protection: 1; mode=block" whenever is possible (ref. http://blogs.msdn.com/b/ieinternals/archive/2011/01/31/controlling-the-internet-explorer-xss-filter-with-the-x-xss-protection-http-header.aspx).
  CWE: CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
  CWE URL: https://cwe.mitre.org/data/definitions/79.html


  Header Field Name: Set-Cookie
  Type 1: Permanent
  Protocol: http
  Status: standard
  Reference: https://tools.ietf.org/html/rfc6265
  Type 2: Response
  Enable: Y
  Required: N
  HTTPS: N
  Security Description: Cookies have a number of security pitfalls. In particular, cookies encourage developers to rely on ambient authority for authentication, often becoming vulnerable to attacks such as cross-site request forgery. Also, when storing session identifiers in cookies, developers often create session fixation vulnerabilities. Transport-layer encryption, such as that employed in HTTPS, is insufficient to prevent a network attacker from obtaining or altering a victim's cookies because the cookie protocol itself has various vulnerabilities. In addition, by default, cookies do not provide confidentiality or integrity from network attackers, even when used in conjunction with HTTPS.
  Security Reference: https://tools.ietf.org/html/rfc6265#section-8
  Recommendations: Please at least read these references: https://tools.ietf.org/html/rfc6265#section-8 and https://www.owasp.org/index.php/Session_Management_Cheat_Sheet#Cookies.
  CWE: CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
  CWE URL: https://cwe.mitre.org/data/definitions/614.html


  Header Field Name: Vary
  Type 1: Permanent
  Protocol: http
  Status: standard
  Reference: https://tools.ietf.org/html/rfc7231#section-7.1.4
  Type 2: Response
  Enable: N
  Required: 
  HTTPS: 
  Security Description: 
  Security Reference: 
  Recommendations: 
  CWE: 
  CWE URL: 


  Header Field Name: Server
  Type 1: Permanent
  Protocol: http
  Status: standard
  Reference: https://tools.ietf.org/html/rfc7231#section-7.4.2
  Type 2: Response
  Enable: Y
  Required: N
  HTTPS: N
  Security Description: Overly long and detailed Server field values increase response latency and potentially reveal internal implementation details that might make it (slightly) easier for attackers to find and exploit known security holes.
  Security Reference: https://tools.ietf.org/html/rfc7231#section-7.4.2
  Recommendations: An origin server SHOULD NOT generate a Server field containing needlessly fine-grained detail and SHOULD limit the addition of subproducts by third parties.
  CWE: CWE-200: Information Exposure
  CWE URL: https://cwe.mitre.org/data/definitions/200.html


  Header Field Name: X-Frame-Options
  Type 1: Permanent
  Protocol: http
  Status: informational
  Reference: https://tools.ietf.org/html/rfc7034
  Type 2: Response
  Enable: Y
  Required: Y
  HTTPS: N
  Security Description: The use of "X-Frame-Options" allows a web page from host B to declare that its content (for example, a button, links, text, etc.) must not be displayed in a frame (<frame> or <iframe>) of another page (e.g., from host A). This is done by a policy declared in the HTTP header and enforced by browser implementations.
  Security Reference: https://tools.ietf.org/html/rfc7034
  Recommendations:  In 2009 and 2010, many browser vendors ([Microsoft-X-Frame-Options] and [Mozilla-X-Frame-Options]) introduced the use of a non-standard HTTP [RFC2616] header field "X-Frame-Options" to protect against clickjacking. Please check here https://www.owasp.org/index.php/Clickjacking_Defense_Cheat_Sheet what's the best option for your case.
  CWE: CWE-693: Protection Mechanism Failure
  CWE URL: https://cwe.mitre.org/data/definitions/693.html
```
