# CVE_APIS

CVE_APIS is a web scraping and REST API project built with Python.

### Crawler

The `crawler` component is responsible for web scraping and data extraction. It utilizes the Scrapy framework to crawl websites, extract information, and store it in a database. The crawler retrieves data from various sources, such as product details, vulnerability information, or any other targeted data.

### REST API

The `CVE_APIS` component is built with Flask, a lightweight web framework for Python. It provides a RESTful API that exposes the scraped data stored in the database. The API allows clients to query and retrieve specific information, apply filters, and sort the data based on various criteria.

As you may guess these two components share the common database.

## Features

- Web scraping and data extraction using Scrapy
- Storage of scraped data in a database
- RESTful API built with Flask
- Querying and retrieval of data through API endpoints
- Filtering and sorting options for the retrieved data

## Installation

1. Clone the repository: `git clone https://github.com/Finbek/CVE_APIs.git`
2. Navigate to the project directory
3. Recommended to create virtual environment. Install the required dependencies: `pip install -r requirements.txt`

## Usage

Before starting the crawler and REST API components, you need to initialize the database by running `python app.py`
This will create the necessary tables in the database as declared in models.py.

1. Navigate to the crawler directory. Start the crawler component: `python run.py`
   - The crawler will scrape the specified websites and store the data in the database.
2. In the root directory of the project. Start the Flask app component: `python app.py`
   - The REST API will start running and provide endpoints to access the scraped data.
3. Access the REST API endpoints: `http://localhost:4999`
   - Use a REST client or web browser to make HTTP requests and retrieve the desired data.
   - The port number may be changed in config.py

Instead of `python ...` you may be required to use `python3 ...` depending on your python version

## Configuration

- The configuration settings for the crawler and REST API can be found in their respective directories (`crawler/run.py` and `config.py`). Adjust the settings according to your requirements.

## API Endpoints

### Endpoint: `/api/critical_vulnerabilities`

Description: This endpoint retrieves software and version combinations with critical vulnerabilities based on specified filters. The retrieved data includes the product, vendor, affected versions, vulnerability types, CVSS score, and last update date.

Method: GET

Parameters:

- `cvss_min` (optional): [Float] - Specifies the minimum CVSS score for filtering vulnerabilities. Default is 0.0.
- `cvss_max` (optional): [Float] - Specifies the maximum CVSS score for filtering vulnerabilities. Default is 10.0.
- `product` (optional): [String] - Filters vulnerabilities by the specific product.
- `vendor` (optional): [String] - Filters vulnerabilities by the specific vendor.
- `from` (optional): [Date] - Specifies the starting date for the vulnerability last update. Format: 'YYYY-MM-DD'.
- `to` (optional): [Date] - Specifies the ending date for the vulnerability last update. Format: 'YYYY-MM-DD'.

Example Usage:

GET /api/critical_vulnerabilities?cvss_min=1.0&cvss_max=7.0&product=apache&vendor=apache&from=2023-01-01&to=2023-06-30

### Endpoint: `/api/software_updates`

Description: This endpoint retrieves software with critical vulnerabilities that require an update based on specified filters. The retrieved data includes the product, vendor, affected versions, available updates, and last update date.

Method: GET

Parameters:

- `cvss_min` (optional): [Float] - Specifies the minimum CVSS score for filtering vulnerabilities. Default is 0.0.
- `cvss_max` (optional): [Float] - Specifies the maximum CVSS score for filtering vulnerabilities. Default is 10.0.
- `from` (optional): [Date] - Specifies the starting date for the vulnerability last update. Format: 'YYYY-MM-DD'.
- `to` (optional): [Date] - Specifies the ending date for the vulnerability last update. Format: 'YYYY-MM-DD'.

Example Usage:

GET /api/software_updates?cvss_min=1.0&cvss_max=7.0&from=2023-01-01&to=2023-06-30

### Endpoint: `/api/bug_count_by_type`

Description: This endpoint retrieves the number of bugs grouped by vulnerability type within a specified time range and based on specified CVSS score filters.

Method: GET

Parameters:

- `cvss_min` (optional): [Float] - Specifies the minimum CVSS score for filtering vulnerabilities. Default is 0.0.
- `cvss_max` (optional): [Float] - Specifies the maximum CVSS score for filtering vulnerabilities. Default is 10.0.
- `from` (optional): [Date] - Specifies the starting date for the vulnerability last update. Format: 'YYYY-MM-DD'.
- `to` (optional): [Date] - Specifies the ending date for the vulnerability last update. Format: 'YYYY-MM-DD'.

Example Usage:

GET /api/bug_count_by_type?cvss_min=1.0&cvss_max=7.0&from=2023-01-01&to=2023-06-30

### Endpoint: `/api/recent_vulnerable_codes`

Description: This endpoint retrieves recently vulnerable codes based on the specified time range and CVSS score filters.

Method: GET

Parameters:

- `from` (optional): [Date] - Specifies the starting date for filtering vulnerabilities based on their publish date. Format: 'YYYY-MM-DD'.
- `to` (optional): [Date] - Specifies the ending date for filtering vulnerabilities based on their publish date. Format: 'YYYY-MM-DD'.
- `cvss_min` (optional): [Float] - Specifies the minimum CVSS score for filtering vulnerabilities. Default is 0.0.
- `cvss_max` (optional): [Float] - Specifies the maximum CVSS score for filtering vulnerabilities. Default is 10.0.

Example Usage:

GET /api/recent_vulnerable_codes?from=2023-01-01&to=2023-06-30&cvss_min=1.0&cvss_max=7.0

### Endpoint: `/api/products_with_critical_vulnerabilities`

Description: This endpoint retrieves products with critical vulnerabilities based on the specified time range and CVSS score filter.

Method: GET

Parameters:

- `from` (optional): [Date] - Specifies the starting date for filtering vulnerabilities based on their publish date. Format: 'YYYY-MM-DD'.
- `to` (optional): [Date] - Specifies the ending date for filtering vulnerabilities based on their publish date. Format: 'YYYY-MM-DD'.

Example Usage:

GET /api/products_with_critical_vulnerabilities?from=2023-01-01&to=2023-06-30

### Endpoint: `/api/vulnerability_severity_statistics`

Description: This endpoint provides statistical information about the severity levels of vulnerabilities in the database based on the specified time range and CVSS score filter.

Method: GET

Parameters:

- `from` (optional): [Date] - Specifies the starting date for filtering vulnerabilities based on their publish date. Format: 'YYYY-MM-DD'.
- `to` (optional): [Date] - Specifies the ending date for filtering vulnerabilities based on their publish date. Format: 'YYYY-MM-DD'.
- `cvss_min` (optional): [Float] - Specifies the minimum CVSS score for filtering vulnerabilities. Default: 0.0.
- `cvss_max` (optional): [Float] - Specifies the maximum CVSS score for filtering vulnerabilities. Default: 10.0.

Example Usage:

GET /api/vulnerability_severity_statistics?from=2023-01-01&to=2023-06-30&cvss_min=1.0&cvss_max=7.0

### Endpoint: `/api/top_vendors_most_vulnerabilities`

Description: This endpoint retrieves a list of vendors that produce the most buggy software based on the number of vulnerabilities associated with their products. The list is sorted in descending order of vulnerability count.

Method: GET

Parameters:

- `from` (optional): [Date] - Specifies the starting date for filtering vulnerabilities based on their publish date. Format: 'YYYY-MM-DD'.
- `to` (optional): [Date] - Specifies the ending date for filtering vulnerabilities based on their publish date. Format: 'YYYY-MM-DD'.
- `cvss_min` (optional): [Float] - Specifies the minimum CVSS score for filtering vulnerabilities. Default: 0.0.
- `cvss_max` (optional): [Float] - Specifies the maximum CVSS score for filtering vulnerabilities. Default: 10.0.

Example Usage:

GET /api/top_vendors_most_vulnerabilities?from=2023-01-01&to=2023-06-30&cvss_min=1.0&cvss_max=7.0

## Web UI (Frontend)

The Web UI provides a user-friendly interface for querying known vulnerabilities in a specific product that were discovered during a specific time period. It also allows sorting vulnerabilities by CVSS (Common Vulnerability Scoring System).

The Web UI is accessible through the following URL: [http://localhost:4999/](http://localhost:4999/)

### Features

- **Search by Product**: Users can enter the name of a specific product to retrieve vulnerabilities associated with that product.

- **Filter by Time Period**: Users can specify a time period to narrow down the search results to vulnerabilities discovered during that period.

- **Sorting by CVSS**: Users can sort the vulnerabilities based on their CVSS scores, allowing them to prioritize vulnerabilities based on their severity.
- **Sorting by Time Period**: Users can sort the vulnerabilities based on their Time Period, allowing them to prioritize vulnerabilities based on their severity.

### Usage

1. Access the Web UI by navigating to [http://localhost:4999/](http://localhost:4999/) in your web browser.

2. Enter the product name in the search field to retrieve vulnerabilities associated with that product.

3. Specify the time period using the provided date range selectors or input fields to filter the vulnerabilities based on the discovery time.

4. Click on the "Sort by CVSS" button to sort the vulnerabilities in ascending or descending order based on their CVSS scores.

## Testing

### Crawler Module

The crawler module is thoroughly tested using the following unit tests:

- `crawler/test_cve_spider.py`: This test file contains unit tests for the CVESpider class, which is responsible for crawling and scraping CVE information from external sources.

- `crawler/test_pipeline.py`: This test file contains unit tests for the Pipeline class, which is responsible for processing and storing the crawled CVE data.

To run the tests, you can use `python test_cve_spider.py`

You may include your own testing by writting the test function following existing tests templates
