#!/usr/bin/python -tt

import argparse
import sqlite3
from urlparse import urlparse
import urllib2

class SmartRedirectHandler(urllib2.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        newreq = urllib2.HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)
        print 'URL:', req.get_full_url()
        print 'Code:', code
        print 'Headers:', '\n', headers
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

def check_header(header):
    conn = sqlite3.connect('hsecscan.db')
    cur = conn.cursor()
    t = (header[0],)
    cur.execute('SELECT * FROM headers WHERE "Header Field Name" = ? COLLATE NOCASE', t)
    col_names = [cn[0] for cn in cur.description]
    for row in cur:
        col_index = 0
        for cel in row:
            print '  ' + col_names[col_index] + ':', cel
            col_index += 1
        print '\n'
    cur.close()
    conn.close()

def scan(url, redirect):
    request = urllib2.Request(url.geturl())
    request.add_header('User-Agent', 'hsecscan')
    request.add_header('Origin', 'http://hsecscan.com')
    if redirect:
        opener = urllib2.build_opener(SmartRedirectHandler())
        response = opener.open(request)
    else:
        response = urllib2.urlopen(request)
    print 'URL:', response.geturl()
    print 'Code:', response.getcode()
    print 'Headers:', '\n', response.info(), '\n'
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