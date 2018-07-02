# -*- coding: utf-8 -*-

"""hsecscan.hsecscan: provides entry point main()."""

__version__ = '0.0.1'

import os.path
import argparse
import sqlite3
from urlparse import urlparse
import urllib2
import urllib
import json
import ssl

class RedirectHandler(urllib2.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        newreq = urllib2.HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)
        print '>> REDIRECT INFO <<'
        print_response(req.get_full_url(), code, headers)
        print '>> REDIRECT HEADERS DETAILS <<'
        for header in headers.items():
            check_header(header)
        print '>> REDIRECT MISSING HEADERS <<'
        missing_headers(headers.items(), urlparse(newurl).scheme)
        return newreq

def print_database(headers):
    conn = sqlite3.connect(dbfile)
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

def print_header(header):
    conn = sqlite3.connect(dbfile)
    cur = conn.cursor()
    cur.execute('SELECT "Header Field Name", "Reference", "Security Description", "Security Reference", "Recommendations", "CWE", "CWE URL" FROM headers WHERE "Header Field Name" = ? COLLATE NOCASE', [header])
    col_names = [cn[0] for cn in cur.description]
    for row in cur:
        col_index = 0
        for cel in row:
            print col_names[col_index] + ':', cel
            col_index += 1
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
    conn = sqlite3.connect(dbfile)
    cur = conn.cursor()
    t = (header[0],)
    if allheaders:
        cur.execute('SELECT "Header Field Name", "Reference", "Security Description", "Security Reference", "Recommendations", "CWE", "CWE URL" FROM headers WHERE "Header Field Name" = ? COLLATE NOCASE', t)
    else:
        cur.execute('SELECT "Header Field Name", "Reference", "Security Description", "Security Reference", "Recommendations", "CWE", "CWE URL" FROM headers WHERE "Enable" = "Y" AND "Header Field Name" = ? COLLATE NOCASE', t)
    col_names = [cn[0] for cn in cur.description]
    for row in cur:
        col_index = 0
        for cel in row:
            if col_names[col_index] == 'Header Field Name':
                print col_names[col_index] + ':', cel, '\nValue: ' + header[1]
            else:
                print col_names[col_index] + ':', cel
            col_index += 1
        print ''
    cur.close()
    conn.close()

def missing_headers(headers, scheme):
    conn = sqlite3.connect(dbfile)
    cur = conn.cursor()
    cur.execute('SELECT "Header Field Name", "Reference", "Security Description", "Security Reference", "Recommendations", "CWE", "CWE URL", "HTTPS" FROM headers WHERE "Required" = "Y"')
    col_names = [cn[0] for cn in cur.description]
    header_names = [name[0] for name in headers]
    for row in cur:
        if (row[0].lower() not in (name.lower() for name in header_names)) & ((scheme == 'https') | (row[7] != 'Y')):
            col_index = 0
            for cel in row:
                print col_names[col_index] + ':', cel
                col_index += 1
            print ''
    cur.close()
    conn.close()

def scan(url, redirect, insecure, useragent, postdata, proxy):
    request = urllib2.Request(url.geturl())
    request.add_header('User-Agent', useragent)
    request.add_header('Origin', 'http://hsecscan.com')
    request.add_header('Accept', '*/*')
    if postdata:
        request.add_data(urllib.urlencode(postdata))
    build = [urllib2.HTTPHandler()]
    if redirect:
        build.append(RedirectHandler())
    if proxy:
        build.append(urllib2.ProxyHandler({'http': proxy, 'https': proxy}))
    if insecure:
        context = ssl._create_unverified_context()
        build.append(urllib2.HTTPSHandler(context=context))
    urllib2.install_opener(urllib2.build_opener(*build))
    response = urllib2.urlopen(request)
    print '>> RESPONSE INFO <<'
    print_response(response.geturl(), response.getcode(), response.info())
    print '>> RESPONSE HEADERS DETAILS <<'
    for header in response.info().items():
        check_header(header)
    print '>> RESPONSE MISSING HEADERS <<'
    missing_headers(response.info().items(), url.scheme)

def check_url(url):
    url_checked = urlparse(url)
    if ((url_checked.scheme != 'http') & (url_checked.scheme != 'https')) | (url_checked.netloc == ''):
        raise argparse.ArgumentTypeError('Invalid %s URL (example: https://www.hsecscan.com/path).' % url)
    return url_checked

def is_valid_file(parser, dbfile):
    if not os.path.exists(dbfile):
        raise argparse.ArgumentTypeError('The file %s does not exist.' % dbfile)
    fdb = open(dbfile, 'r')
    if  fdb.read(11) != 'SQLite form':
        raise argparse.ArgumentTypeError('The file %s is not a SQLite DB.' % dbfile)
    return dbfile

def main():
    parser = argparse.ArgumentParser(prog='hsecscan', description='A security scanner for HTTP response headers.')
    parser.add_argument('-P', '--database', action='store_true', help='Print the entire response headers database.')
    parser.add_argument('-p', '--headers', action='store_true', help='Print only the enabled response headers from database.')
    parser.add_argument('-H', '--header', metavar='Header', help='Print details for a specific Header (example: Strict-Transport-Security).')
    parser.add_argument('-u', '--URL', type=check_url, help='The URL to be scanned.')
    parser.add_argument('-R', '--redirect', action='store_true', help='Print redirect headers.')
    parser.add_argument('-i', '--insecure', action='store_true', help='Disable certificate verification.')
    parser.add_argument('-U', '--useragent', metavar='User-Agent', default='hsecscan', help='Set the User-Agent request header (default: hsecscan).')
    parser.add_argument('-D', '--dbfile', dest="dbfile", default=os.path.dirname(os.path.abspath(__file__))+'/hsecscan.db', type=lambda x: is_valid_file(parser, x), help='Set the database file (default: hsecscan.db).')
    parser.add_argument('-d', '--postdata', metavar='\'POST data\'', type=json.loads, help='Set the POST data (between single quotes) otherwise will be a GET (example: \'{ "q":"query string", "foo":"bar" }\').')
    parser.add_argument('-x', '--proxy', help='Set the proxy server (example: 192.168.1.1:8080).')
    parser.add_argument('-a', '--all', action='store_true', help='Print details for all response headers. Good for check the related RFC.')
    args = parser.parse_args()
    global dbfile
    dbfile = args.dbfile
    if args.database == True:
        print_database(False)
    elif args.headers == True:
        print_database(True)
    elif args.header:
        print_header(args.header.lower())
    elif args.URL:
        global allheaders
        allheaders = args.all
        scan(args.URL, args.redirect, args.insecure, args.useragent, args.postdata, args.proxy)
    else:
        parser.print_help()
