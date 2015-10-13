#!/usr/bin/python -tt

import argparse

def print_database():
    print 'database'

def print_headers():
    print 'headers'

def scan(follow):
    print 'scan'
    print follow

def main():
    parser = argparse.ArgumentParser(description='A security scanner for HTTP response headers.')
    parser.add_argument('-P', '--database', action='store_true', help='Print the entire response headers database.')
    parser.add_argument('-p', '--headers', action='store_true', help='Print only the enabled response headers from database.')
    parser.add_argument('-u', '--URL', help='The URL to be scanned.')
    parser.add_argument('-F', '--follow', action='store_true', help='Follow redirects.')
    args = parser.parse_args()
    if args.database == True:
        print_database()
    elif args.headers == True:
        print_headers()
    elif args.URL != None:
        scan(follow=args.follow)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()