import argparse
import requests
from bs4 import BeautifulSoup
import logging
import json
import asyncio
import aiohttp
from urllib.parse import urlparse, urljoin
import csv


logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')


async def fetch(session, url):
    try:
        async with session.get(url) as response:
            response.raise_for_status()
            return await response.text()
    except aiohttp.ClientError as e:
        logging.error(f"Request error: {e}")
        return None

async def crawl_page(session, url, base_url):
    logging.info(f"Scanning page: {url}")
    html = await fetch(session, url)
    if not html:
        return []

    soup = BeautifulSoup(html, 'html.parser')
    forms = soup.find_all('form')
    form_details = []

    for form in forms:
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        inputs = form.find_all(['input', 'textarea', 'select']) 
        form_data = {
            'action': urljoin(base_url, action),
            'method': method,
            'inputs': [{'type': input_tag.get('type', 'text'), 'name': input_tag.get('name', '')} for input_tag in inputs]
        }
        form_details.append(form_data)

    return form_details

async def crawl(url, depth=1):
    logging.info("Initiating crawl...")
    base_url = f"{urlparse(url).scheme}://{urlparse(url).hostname}"
    to_visit = {url}
    visited = set()
    all_forms = []

    async with aiohttp.ClientSession() as session:
        while to_visit:
            current_url = to_visit.pop()
            visited.add(current_url)
            forms = await crawl_page(session, current_url, base_url)
            if forms:
                all_forms.extend(forms)

            if depth > 0:
                html = await fetch(session, current_url)
                if html:
                    soup = BeautifulSoup(html, 'html.parser')
                    links = soup.find_all('a', href=True)
                    for link in links:
                        href = link['href']
                        full_url = urljoin(current_url, href)
                        if urlparse(full_url).hostname == urlparse(url).hostname and full_url not in visited:
                            to_visit.add(full_url)

    logging.info(f"Crawl completed. Found {len(all_forms)} forms.")
    return all_forms

def evaluate(forms):
    vulnerabilities = []
    for form in forms:
        action = form['action']
        method = form['method']
        inputs = form['inputs']
        if not any(input['type'] == 'hidden' for input in inputs):
            vulnerabilities.append(f"Form action '{action}' lacks CSRF protection.")
        if method == 'post':
            
            test_payload = {input['name']: 'test' for input in inputs if input['name']}
            try:
                response = requests.post(action, data=test_payload)
                if response.status_code == 200:
                    vulnerabilities.append(f"Form action '{action}' is accessible with test data.")
            except requests.RequestException as e:
                logging.error(f"Error testing form action '{action}': {e}")

    return vulnerabilities

def extract_headers(url):
    try:
        response = requests.head(url, timeout=10)
        response.raise_for_status()
        return dict(response.headers)
    except requests.RequestException as e:
        logging.error(f"Request error: {e}")
        return {}

def analyze_headers(headers):
    security_headers = [
        'X-Content-Type-Options', 'X-Frame-Options', 'Strict-Transport-Security', 'Content-Security-Policy'
    ]
    missing_headers = [header for header in security_headers if header not in headers]
    return missing_headers

def prompt(message):
    sys.stdout.write(message)
    sys.stdout.flush()

def save_results(results, filename='results.json'):
    try:
        with open(filename, 'w') as file:
            json.dump(results, file, indent=4)
        logging.info(f"Results saved to {filename}")
    except IOError as e:
        logging.error(f"Error saving results: {e}")

def save_results_csv(results, filename='results.csv'):
    try:
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Type", "Details"])
            for key, values in results.items():
                if isinstance(values, list):
                    for value in values:
                        writer.writerow([key, value])
                else:
                    writer.writerow([key, values])
        logging.info(f"Results saved to {filename}")
    except IOError as e:
        logging.error(f"Error saving results: {e}")

async def main():
    parser = argparse.ArgumentParser(description="Advanced CSRF Vulnerability Scanner")
    parser.add_argument('-u', '--url', type=str, required=True, help="Target URL")
    parser.add_argument('-o', '--output', type=str, choices=['json', 'csv'], default='json', help="Output format")
    parser.add_argument('--depth', type=int, default=1, help="Depth of crawling")
    args = parser.parse_args()
    target_url = args.url
    output_format = args.output
    depth = args.depth

    print("★")
    print("     ________    ____       __     ___________ ____  ______")
    print("    / ____/ /_  / __ \_____/ /_   / ____/ ___// __ \/ ____/")
    print("    / / __/ __ \/ / / / ___/ __/  / /    \__ \/ /_/ / /_")
    print("    / /_/ / / / / /_/ (__  ) /_   / /___ ___/ / _, _/ __/")
    print("    \____/_/ /_/\____/____/\__/   \____//____/_/ |_/_/")
    print()
    print("    By Gh0st_ri13y")

    forms = await crawl(target_url, depth)
    if not forms:
        logging.info("No forms found.")
        return

    headers_data = extract_headers(target_url)
    missing_headers = analyze_headers(headers_data)
    
    logging.info("Evaluating forms for CSRF vulnerabilities...")
    csrf_tests = evaluate(forms)
    
    results = {
        "target_url": target_url,
        "forms": forms,
        "csrf_vulnerabilities": csrf_tests,
        "missing_security_headers": missing_headers
    }

    if not csrf_tests:
        logging.info("No CSRF vulnerabilities found.")
    else:
        logging.info("CSRF vulnerabilities detected:")
        for result in csrf_tests:
            logging.info(f"- {result}")

    if missing_headers:
        logging.info(f"Missing security headers: {missing_headers}")

    prompt("Do you want to save the results? (yes/no): ")
    if input().strip().lower() == 'yes':
        if output_format == 'json':
            save_results(results)
        else:
            save_results_csv(results)

    logging.info("Scan completed.")

if __name__ == "__main__":
    asyncio.run(main())
