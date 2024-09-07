# SQLInjector


**SQLInjector** is a powerful Python tool designed to identify SQL injection vulnerabilities in web applications. It performs comprehensive testing by injecting common SQL patterns into URLs and analyzing responses for potential errors.

## Features

- **Multithreaded Scanning:** Utilizes multiple threads to speed up the scanning process.
- **Customizable Depth:** Adjust the depth of injection patterns to test based on your needs.
- **Error Detection:** Detects a wide range of SQL errors to identify potential vulnerabilities.
- **Flexible Input:** Supports URLs from a file and outputs results in JSON format.

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/Mr-dark55/SQLInjector.git
   cd SQLInjector
   pip install -r requirements.txt
   ```
## Usage
To use SQLInjector, run the script with the required arguments:
```
python SQLInjector.py -u <urls-file> [-o <output-file>] [-t <threads>] [-d <depth>] [--ignore-errors]

```
## Arguments


```
-u, --urls-file (required): Path to the file containing the list of URLs to scan.
-o, --output (optional): Output file to save results in JSON format.
-t, --threads (optional): Number of threads to use (default: 5).
-d, --depth (optional): Depth of injection patterns to test (1-3, default: 1).
--ignore-errors (optional): Continue scanning even if connection errors occur
```
## Example
```
python SQLInjector.py -u urls.txt -o results.json -t 10 -d 2
``
## How It Works
```
URL Parsing: The tool parses each URL and extracts query parameters.
Injection Testing: It injects common SQL patterns into the query parameters.
Error Detection: Checks for SQL-related errors in the response to identify potential vulnerabilities.
Results: Collects and saves detected vulnerabilities in a JSON file.
```
