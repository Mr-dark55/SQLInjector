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


To use SQLInjector, run the script with the required arguments:
   ```
python SQLInjector.py -u <urls-file> [-o <output-file>] [-t <threads>] [-d <depth>] [--ignore-errors]
```

