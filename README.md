# Simple CSRF Vulnerability Scanner

This tool is designed to scan web applications for potential Cross-Site Request Forgery (CSRF) vulnerabilities. It performs web crawling to find forms, evaluates them for CSRF protection, and analyzes security headers to ensure that essential security practices are in place.

## Features

- **Form Extraction**: Crawl a website and extract all forms.
- **CSRF Vulnerability Detection**: Identify forms that lack CSRF protection mechanisms.
- **Recursive Crawling**: Crawl internal links up to a specified depth.
- **Customizable Depth**: Set the crawling depth to control the extent of the scan.


You can install the required packages using `pip`:

```
pip install -r requirements.txt
```

## Usage
To use the scanner, run the script with the following command:
```
python gh0st.py -u <target_url> [options]
```

## Arguments

- -u, --url (required): Target URL to scan.
- -o, --output (optional): Output format. Choose between json (default) or csv.
- --depth (optional): Depth of crawling. Default is 1.

## Example 

To scan a website with a depth of 2 and save results in CSV format:

```
python gh0st.py -u https://example.com -o csv --depth 2
```

## Output

The tool provides a detailed report including:

Forms: A list of forms found on the target website.

CSRF Vulnerabilities: Any forms that may be vulnerable to CSRF attacks.

Missing Security Headers: A list of important security headers that are missing from the target site.
Development

Feel free to contribute to this project. If you find bugs or have suggestions, open an issue or submit a pull request.

## License

This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.

Made with ❤️ by Gh0st_ri13y


