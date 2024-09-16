import requests  # Import the requests library to handle HTTP requests
import base64    # Import base64 library to encode the URL

# Replace 'YOUR_API_KEY_HERE' with your actual VirusTotal API key
API_KEY = 'YOUR_API_KEY_HERE'
# URL for the VirusTotal API endpoint to check URLs
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/urls'

def encode_url(url):
    """
    Encode the URL in base64 format as required by the VirusTotal API.
    """
    # Encode the URL to base64 and remove any trailing '=' characters
    url_encoded = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return url_encoded

def check_url(url):
    """
    Function to check if a given URL is flagged as malicious using the VirusTotal API.
    """
    url_encoded = encode_url(url)  # Encode the URL to base64 format
    
    # Set the headers for the API request, including the API key for authorization
    headers = {
        'x-apikey': API_KEY
    }
    
    # Send a GET request to VirusTotal API with the encoded URL and headers
    response = requests.get(
        f'{VIRUSTOTAL_URL}/{url_encoded}',  # Construct the request URL
        headers=headers  # Include headers with the API key
    )
    
    # Check if the response status code is 200 (HTTP OK)
    if response.status_code == 200:
        try:
            # Attempt to parse the JSON response from the API
            json_response = response.json()
            # Check if the 'data' and 'attributes' fields are present in the response
            if 'data' in json_response and 'attributes' in json_response['data']:
                attributes = json_response['data']['attributes']  # Extract attributes section
                last_analysis_stats = attributes.get('last_analysis_stats', {})  # Get last analysis stats
                # Check if the URL has been flagged as malicious
                if last_analysis_stats.get('malicious', 0) > 0:
                    print(f"The URL '{url}' is flagged as malicious.")  # Print result if malicious
                else:
                    print(f"The URL '{url}' is clean.")  # Print result if not malicious
            else:
                print("Error: Unexpected response structure.")  # Error if response structure is not as expected
        except ValueError:
            print("Error: Failed to parse response as JSON.")  # Handle JSON parsing errors
    else:
        print("Error: Unable to check URL. Please check the URL and try again.")  # Handle non-200 responses

if __name__ == "__main__":
    # Prompt the user to enter a URL to check
    url = input("Enter a URL to check: ")
    # Call the check_url function with the user-provided URL
    check_url(url)
