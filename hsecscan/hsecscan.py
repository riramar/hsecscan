# -*- coding: utf-8 -*-

"""hsecscan.hsecscan: provides entry point main()."""

__version__ = '0.0.2'

import os.path
import argparse
import sqlite3
from urllib.parse import urlencode, urlparse
from urllib.request import (build_opener, HTTPHandler,
    HTTPSHandler, install_opener, ProxyHandler,
    HTTPRedirectHandler, Request, urlopen)
import ssl


class RedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        newreq = HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)
        print('>> REDIRECT INFO <<')
        print_response(req.get_full_url(), code, headers)
        print('>> REDIRECT HEADERS DETAILS <<')
        for header in headers.items():
            check_header(dbfile, header)
        print('>> REDIRECT MISSING HEADERS <<')
        missing_headers(dbfile, headers.items(), urlparse(newurl).scheme)
        return newreq


def print_database(dbfile: str, headers: bool) -> None:
    """ Helper function to print the contents from the database """

    conn = sqlite3.connect(dbfile)
    cur = conn.cursor()
    cur.execute('SELECT * FROM headers')
    col_names = [cn[0] for cn in cur.description]
    for row in cur:
        col_index = 0
        if (headers == False) | (row[6] == 'Y'):
            for cel in row:
                print(col_names[col_index] + ':', cel)
                col_index += 1
            print('\n')
    cur.close()
    conn.close()


def print_header(dbfile: str, header: str) -> None:
    conn = sqlite3.connect(dbfile)
    cur = conn.cursor()
    cur.execute('SELECT "Header Field Name", "Reference", "Security Description", "Security Reference", "Recommendations", "CWE", "CWE URL" FROM headers WHERE "Header Field Name" = ? COLLATE NOCASE', [header])
    col_names = [cn[0] for cn in cur.description]
    for row in cur:
        col_index = 0
        for cel in row:
            print(col_names[col_index] + ':', cel)
            col_index += 1
    cur.close()
    conn.close()


def print_response(url: str, code: int, headers: str) -> None:
    """ Output helper function """

    print('URL:', url)
    print('Code:', code)
    print('Headers:')
    for line in str(headers).splitlines():
        print('', line)
    print('')


def check_header(dbfile: str, header: str) -> None:
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
                print(col_names[col_index] + ':', cel, '\nValue: ' + header[1])
            else:
                print(col_names[col_index] + ':', cel)
            col_index += 1
        print('')
    cur.close()
    conn.close()


def missing_headers(dbfile: str, headers: list, scheme: str) -> None:
    
    conn = sqlite3.connect(dbfile)
    cur = conn.cursor()
    cur.execute('SELECT "Header Field Name", "Reference", "Security Description", "Security Reference", "Recommendations", "CWE", "CWE URL", "HTTPS" FROM headers WHERE "Required" = "Y"')
    col_names = [cn[0] for cn in cur.description]
    header_names = [name[0] for name in headers]
    for row in cur:
        if (row[0].lower() not in (name.lower() for name in header_names)) & ((scheme == 'https') | (row[7] != 'Y')):
            col_index = 0
            for cel in row:
                print(col_names[col_index] + ':', cel)
                col_index += 1
            print('')
    cur.close()
    conn.close()


def scan(dbfile: str, url: str, redirect: bool, insecure: bool, useragent: str, proxy) -> None:
    """ Main scanning function """

    request = Request(url)
    request.add_header("User-Agent", useragent)
    request.add_header("Origin", "http://hsecscan.com")
    request.add_header("Accept", "*/*")
    
    # TODO: add_data was deprecated in python 3.4, need to rewrite the POST logic    
    #if postdata:
    #     request.add_data(urllib.urlencode(postdata))

    opener = build_opener(HTTPHandler())
    if redirect:
        opener = build_opener(HTTPRedirectHandler())
    #if proxy:
    #    opener = (ProxyHandler({'http': proxy, 'https': proxy}))
    if insecure:
        # tested with expired.badssl.com and works.
        # TODO: remove this comment and write pytests
        context = ssl._create_unverified_context()
        opener = build_opener(HTTPSHandler(context=context))
    install_opener(opener)
    response = urlopen(request, timeout=5)
    print(">> RESPONSE INFO <<")
    print_response(response.geturl(), response.getcode(), response.info())
    print(">> RESPONSE HEADERS DETAILS <<")
    for header in response.info().items():
        check_header(dbfile, header)
    print(">> RESPONSE MISSING HEADERS <<")
    missing_headers(dbfile, response.info().items(), request.type)


def check_url(url: str) -> tuple:
    """ Helper function to validate the passed url """

    url_checked = urlparse(url)
    # TODO: I'm not sure the below operators are performing as intended, I need to write tests to confirm
    if ((url_checked.scheme != 'http') & (url_checked.scheme != 'https')) | (url_checked.netloc == ''):
        raise argparse.ArgumentTypeError(f"Invalid URL: {url} (example: https://www.hsecscan.com/path).")
    return url_checked


def is_valid_dbfile(dbfile: str) -> str:
    """ Helper function to ensure we have a valid SQLite DB file """

    if not os.path.exists(dbfile):
        raise argparse.ArgumentTypeError(f"The file {dbfile} does not exist.")

    try:
        # for some reason, if you pass this a valid file it still works
        # TODO: fix it
        dbfile = os.path.dirname(os.path.abspath(__file__))+f"/{dbfile}"
        dburi = f"file:{dbfile}?mode=rw"
        dbcon = sqlite3.connect(dburi, uri=True)
        dbcon.close()

    except sqlite3.OperationalError:
        raise argparse.ArgumentTypeError(f"The file {dbfile} is not a SQLite DB.")

    return dbfile


def main():
    parser = argparse.ArgumentParser(prog='hsecscan', description='A security scanner for HTTP response headers.')
    parser.add_argument("-P", "--database", action="store_true", help="Print the entire response headers database.")
    parser.add_argument("-p", "--headers", action="store_true", help="Print only the enabled response headers from database.")
    parser.add_argument("-H", "--header", metavar="Header", help="Print details for a specific Header (example: Strict-Transport-Security).")
    parser.add_argument("-u", "--url", action="store", help="The URL to be scanned.")
    parser.add_argument("-R", "--redirect", action="store_true", help="Print redirect headers.")
    parser.add_argument("-i", "--insecure", action="store_true", help="Disable certificate verification.")
    parser.add_argument('-U', '--useragent', metavar='User-Agent', default='hsecscan', help='Set the User-Agent request header (default: hsecscan).')
    parser.add_argument("-D", "--dbfile", action="store", default="hsecscan.db", help="Set the database file (default: hsecscan.db).")
    #parser.add_argument("-d", "--postdata", metavar="\'POST data\'", type=json.loads, help="Set the POST data (between single quotes) otherwise will be a GET.")
    parser.add_argument("-x", "--proxy", help="Set the proxy server (example: 192.168.1.1:8080).")
    parser.add_argument("-a", "--all", action="store_true", help="Print details for all response headers. Good for check the related RFC.")
    args = parser.parse_args()

    global dbfile
    dbfile = is_valid_dbfile(args.dbfile)

    if args.database:
        print_database(dbfile, False)
    elif args.headers:
        print_database(dbfile, True)
    elif args.header:
        print_header(dbfile, args.header.lower())
    elif args.url:
        check_url(args.url)
        global allheaders
        allheaders = args.all
        scan(dbfile, args.url, args.redirect, args.insecure, args.useragent, args.proxy)
    else:
        parser.print_help()

if __name__ == main():
    main()
