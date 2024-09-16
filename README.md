# Basic Python Malicious URL Checker
Basic Python Malicious URL Checker

## Description
This following will describe the steps to complete the project followed by an explanation for each section of code.

## Languages
- [PowerShell](https://learn.microsoft.com/en-us/powershell/)

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

## Explanation of Each Section

```python
