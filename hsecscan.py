#!/usr/bin/python -tt

import argparse
import sqlite3
from urlparse import urlparse
import urllib2
import ssl

class SmartRedirectHandler(urllib2.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        newreq = urllib2.HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)
        print '>> REDIRECT INFO <<'
        print_response(req.get_full_url(), code, headers)
        print '>> REDIRECT HEADERS DETAILS <<'
        for header in headers.items():
            check_header(header)
        return newreq

def print_database(headers):
    conn = sqlite3.connect('hsecscan.db')
    cur = conn.cursor()
    cur.execute('SELECT * FROM headers')
    col_names = [cn[0] for cn in cur.description]
    for row in cur:
        col_index = 0
        if (headers == False) | (row[6] == 'Y'):
            for cel in row:
                print col_names[col_index] + ':', cel
                col_index += 1
            print '\n'
    cur.close()
    conn.close()

def print_response(url, code, headers):
    print 'URL:', url
    print 'Code:', code
    print 'Headers:'
    for line in str(headers).splitlines():
        print '', line
    print ''

def check_header(header):
    conn = sqlite3.connect('hsecscan.db')
    cur = conn.cursor()
    t = (header[0],)
    cur.execute('SELECT "Header Field Name", "Reference", "Security Description", "Security Reference", "Recommendations", "CWE", "CWE URL" FROM headers WHERE "Header Field Name" = ? COLLATE NOCASE', t)
    col_names = [cn[0] for cn in cur.description]
    for row in cur:
        col_index = 0
        for cel in row:
            print col_names[col_index] + ':', cel
            col_index += 1
        print ''
    cur.close()
    conn.close()

def scan(url, redirect):
    request = urllib2.Request(url.geturl())
    request.add_header('User-Agent', 'hsecscan')
    request.add_header('Origin', 'http://hsecscan.com')
    context = ssl._create_unverified_context()
    if redirect:
        opener = urllib2.build_opener(SmartRedirectHandler(), context=context)
        response = opener.open(request)
    else:
        response = urllib2.urlopen(request, context=context)
    print '>> RESPONSE <<'
    print_response(response.geturl(), response.getcode(), response.info())
    print '>> RESPONSE HEADERS DETAILS <<'
    for header in response.info().items():
        check_header(header)

def check_url(url):
    url_checked = urlparse(url)
    if ((url_checked.scheme != 'http') & (url_checked.scheme != 'https')) | (url_checked.netloc == ''):
        raise argparse.ArgumentTypeError('Invalid URL (%s). Valid example: https://www.hsecscan.com/path' % url)
    return url_checked

def main():
    parser = argparse.ArgumentParser(description='A security scanner for HTTP response headers.')
    parser.add_argument('-P', '--database', action='store_true', help='Print the entire response headers database.')
    parser.add_argument('-p', '--headers', action='store_true', help='Print only the enabled response headers from database.')
    parser.add_argument('-u', '--URL', type=check_url, help='The URL to be scanned.')
    parser.add_argument('-R', '--redirect', action='store_true', help='Print redirect headers.')
    args = parser.parse_args()
    if args.database == True:
        print_database(False)
    elif args.headers == True:
        print_database(True)
    elif args.URL != None:
        scan(args.URL, args.redirect)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
