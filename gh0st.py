import argparse
import os
import json
import re
import statistics
import requests
from pathlib import Path
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Custom banner
def banner():
    print('''
              ________    ____       __     ___________ ____  ______
             / ____/ /_  / __ \\_____/ /_   / ____/ ___// __ \\/ ____/
            / / __/ __ \\/ / / / ___/ __/  / /    \\__ \\/ /_/ / /_    
           / /_/ / / / / /_/ (__  ) /_   / /___ ___/ / _, _/ __/    
           \\____/_/ /_/\\____/____/\\__/   \\____//____/_/ |_/_/       
              ║║      By g h 0 s t _ r i 1 3 y       ║║
    ''')

# Function to crawl and get forms recursively
def crawl_and_get_forms(target, max_depth=2, crawled_urls=None):
    if crawled_urls is None:
        crawled_urls = set()

    if max_depth == 0 or target in crawled_urls:
        return []

    crawled_urls.add(target)
    print("⟬ → ⟭ Crawling started...")

    forms = []
    internal_links = []

    try:
        response = requests.get(target)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract forms from the page
        page_forms = soup.find_all('form')
        for form in page_forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = []
            for input_tag in form.find_all('input'):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name')
                input_value = input_tag.get('value', '')
                inputs.append({
                    'type': input_type,
                    'name': input_name,
                    'value': input_value,
                })
            forms.append({
                'action': urljoin(target, action),
                'method': method,
                'inputs': inputs,
            })

        # Find internal links
        for link in soup.find_all('a', href=True):
            href = link['href']
            parsed_href = urlparse(href)
            if not parsed_href.netloc or parsed_href.netloc == urlparse(target).netloc:
                full_url = urljoin(target, href)
                if full_url not in crawled_urls:
                    internal_links.append(full_url)

        print(f"⟬ ✓ ⟭ Crawling finished. Found {len(page_forms)} forms on {target}.")

    except Exception as e:
        print(f"⟬ ✕ ⟭ Failed to crawl {target}: {e}")
        return forms

    # Recursively crawl internal links
    for link in internal_links:
        forms += crawl_and_get_forms(link, max_depth - 1, crawled_urls)

    return forms

# Function to check for CSRF vulnerability
def check_csrf(forms):
    vulnerable_forms = []

    for form in forms:
        has_csrf_token = False
        for input_tag in form['inputs']:
            if input_tag['name'] and 'csrf' in input_tag['name'].lower():
                has_csrf_token = True
                break
        if not has_csrf_token:
            vulnerable_forms.append(form)

    return vulnerable_forms

# Main function
def main():
    banner()

    parser = argparse.ArgumentParser(description='CSRF Vulnerability Scanner')
    parser.add_argument('-u', '--url', help='Target URL', required=True)
    parser.add_argument('--depth', help='Crawling depth (default 2)', default=2, type=int)
    args = parser.parse_args()

    target = args.url
    depth = args.depth

    if not target.startswith(('http://', 'https://')):
        print("⟬ ⁈ ⟭ Please provide a valid URL (starting with http:// or https://)")
        return

    # Phase 1: Crawling
    print(f"Crawling started")
    forms = crawl_and_get_forms(target, max_depth=depth)

    if not forms:
        print("⟬ ⁈ ⟭ No forms found.")
        return

    # Phase 2: Evaluating
    print(f"Evaluating forms for CSRF vulnerabilities...")
    vulnerable_forms = check_csrf(forms)

    if vulnerable_forms:
        print("⟬ ✓ ⟭ CSRF vulnerability found in the following forms:")
        for form in vulnerable_forms:
            print(f"⟬ → ⟭ Form with action: {form['action']} and method: {form['method']}")
    else:
        print("⟬ ✕ ⟭ No CSRF vulnerabilities found.")

    # Phase 3: Completion
    print(f" Completed ")

if __name__ == "__main__":
    main()
