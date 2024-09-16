# Basic Python Malicious URL Checker
Basic Python Malicious URL Checker

## Description
The following will describe the steps to complete the project followed by an explanation for each section of code.

## Languages
- [Python](https://www.python.org/)

## Resources
- [VirusTotal | API Key ](https://www.virustotal.com/)

## Utilities Used
- [Virtual Box](https://www.virtualbox.org/)
- [Kali Linux](https://www.kali.org/get-kali/#kali-platforms)

## Explanation
- **API Key**: You need to replace 'YOUR_API_KEY_HERE' with your actual VirusTotal API key.
- **URL Submission**: The script sends a POST request to the VirusTotal API with the URL to check.
- **Response Handling**: The script checks the response to see if the URL is flagged as malicious.

## Steps and Results

<p align="center">
Power Up Kali Linux Virtual Machine
</p>
<p align="center">
<img src="https://github.com/user-attachments/assets/1c7e9e70-5f2b-4fe0-a7d6-be691a25c4b3" alt="Power Up Kali Linux Virtual Machine">
</p>

<p align="center">
Install Required Libraries "pip install requests"
</p>
<p align="center">
<img src="https://github.com/user-attachments/assets/c857996c-d3e7-4b80-83f7-f5edd2727f73" alt="Install Required Libraries">
</p>

<p align="center">
Get a VirusTotal API Key
</p>
<p align="center">
<img src="https://github.com/user-attachments/assets/572e3e17-38a8-48b3-b112-1069f4b8f0fb" alt="Get a VirusTotal API Key">
</p>

<p align="center">
Create the Python Script using <a href="https://github.com/craiglashley/BasicPythonMaliciousURLChecker/blob/main/url_checker.py">url_checker.py</a>
</p>
<p align="center">
<img src="https://github.com/user-attachments/assets/002c1a1f-8be1-4dea-8094-f7edd6a13bd2" alt="Create the Python Script using">
</p>

<p align="center">
Run script and test a good URL and a known malicious URL <a href="https://github.com/craiglashley/BasicPythonMaliciousURLChecker/blob/main/url_checker.py">url_checker.py</a>
</p>
<p align="center">
<img src="https://github.com/user-attachments/assets/eb9113eb-0d12-4651-8f83-b5167cee4742" alt="Run script and test a good URL and a known malicious URL">
</p>

## Explanation of Each Section of Code
<p align="center">
Imports:<br>
Imports requests for making HTTP requests and base64 for URL encoding
</p>

```python
import requests  # Import the requests library to handle HTTP requests
import base64    # Import base64 library to encode the URL
```

<p align="center">
API Key and URL:<br>
API_KEY: Stores your VirusTotal API key for authorization<br>
VIRUSTOTAL_URL: The endpoint URL for checking URLs with VirusTotal
</p>

```python
API_KEY = 'YOUR_API_KEY_HERE'  # Replace 'YOUR_API_KEY_HERE' with your actual VirusTotal API key
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/urls'  # URL for the VirusTotal API endpoint to check URLs
```

<p align="center">
URL Encoding Function:<br>
encode_url: Function that encodes the URL in base64 format to match VirusTotal’s requirements.
</p>

```python
def encode_url(url):
    """
    Encode the URL in base64 format as required by the VirusTotal API.
    """
    url_encoded = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return url_encoded
```

<p align="center">
Main Check Function:<br>
check_url: Function that:<br>
  Encodes the URL and sends a GET request to VirusTotal<br>
  Parses the JSON response and checks if the URL is flagged as malicious<br>
  Prints appropriate messages based on the response or errors.
</p>

```python
def check_url(url):
    """
    Function to check if a given URL is flagged as malicious using the VirusTotal API.
    """
    url_encoded = encode_url(url)  # Encode the URL to base64 format

    headers = {
        'x-apikey': API_KEY
    }
    
    response = requests.get(
        f'{VIRUSTOTAL_URL}/{url_encoded}',  # Construct the request URL
        headers=headers  # Include headers with the API key
    )
    
    if response.status_code == 200:
        try:
            json_response = response.json()  # Attempt to parse the JSON response
            if 'data' in json_response and 'attributes' in json_response['data']:
                attributes = json_response['data']['attributes']  # Extract attributes
                last_analysis_stats = attributes.get('last_analysis_stats', {})  # Get analysis stats
                if last_analysis_stats.get('malicious', 0) > 0:
                    print(f"The URL '{url}' is flagged as malicious.")  # Print if malicious
                else:
                    print(f"The URL '{url}' is clean.")  # Print if clean
            else:
                print("Error: Unexpected response structure.")  # Unexpected structure
        except ValueError:
            print("Error: Failed to parse response as JSON.")  # Handle parsing errors
    else:
        print("Error: Unable to check URL. Please check the URL and try again.")  # Non-200 response
```

<p align="center">
Main Execution Block:<br>
Prompts the user for a URL and calls check_url to perform the check.
</p>

```python
if __name__ == "__main__":
    url = input("Enter a URL to check: ")
    check_url(url)
```
