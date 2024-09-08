# Advanced CSRF Vulnerability Scanner

This tool is designed to scan web applications for potential Cross-Site Request Forgery (CSRF) vulnerabilities. It performs web crawling to find forms, evaluates them for CSRF protection, and analyzes security headers to ensure that essential security practices are in place.

## Features

- **Asynchronous Crawling**: Efficiently scans web pages using asynchronous requests.
- **Form Extraction**: Identifies forms, including `input`, `textarea`, and `select` elements.
- **CSRF Evaluation**: Tests forms for CSRF vulnerabilities by simulating POST requests.
- **Security Header Analysis**: Checks for the presence of important security headers.
- **Flexible Output**: Save results in JSON or CSV formats.

## Requirements

- Python 3.7 or higher
- `aiohttp`
- `beautifulsoup4`
- `lxml`

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

-u, --url (required): Target URL to scan.
-o, --output (optional): Output format. Choose between json (default) or csv.
--depth (optional): Depth of crawling. Default is 1.

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

This project is licensed under the MIT License - see the LICENSE file for details.

Made with ❤️ by Gh0st_ri13y


