# Security Header Scanner

## Overview

The Security Header Scanner is a Python application using PyQt5 that checks the presence and configuration of various HTTP security headers on a given website. These headers are crucial for enhancing the security of web applications by enforcing policies related to security and privacy.

## Features

- **URL Input**: Allows users to enter a URL to scan.
- **Scan Button**: Initiates the scan for security headers.
- **Results Display**: Shows the results of the scan, including missing headers and any misconfigurations.

## Requirements

- Python 3.x
- PyQt5
- Requests

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/security-header-scanner.git
    ```

2. **Navigate to the project directory**:
    ```bash
    cd security-header-scanner
    ```

3. **Install the required Python packages**:
    ```bash
    pip install PyQt5 requests
    ```

## Usage

1. **Run the application**:
    ```bash
    python3 main.py
    ```

2. **Enter the URL** of the website you want to scan in the input field.

3. **Click on "Scan"** to initiate the header check.

4. **View the results** in the text area below the button. The results will show which security headers are missing or misconfigured.

## Code Explanation

### `check_security_headers(url)`

This function takes a URL as input and performs the following:

- Sends an HTTP GET request to the URL with a custom User-Agent header.
- Checks the presence and configuration of various HTTP security headers.
- Returns a summary of missing headers and misconfigurations.

### `SecurityHeaderScanner(QWidget)`

This is the main GUI class for the application. It contains:

- **URL Input Field**: For the user to enter the website URL.
- **Scan Button**: Triggers the `on_scan` method.
- **Results Area**: Displays the results of the scan.

#### `initUI()`

Sets up the user interface, including layout, widgets, and window properties.

#### `on_scan()`

Handles the scan button click event. Validates the URL and calls `check_security_headers()` to perform the scan. Displays the results in the results area.

## Contributing

If you have suggestions or improvements, feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
