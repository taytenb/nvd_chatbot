import os
import requests
import json
import re
from datetime import datetime, timedelta
from langchain_core.prompts import PromptTemplate
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
NVD_API_KEY = os.getenv('NVD_API_KEY')

# Initialize the language model
llm = ChatOpenAI(api_key=OPENAI_API_KEY, temperature=0, model="gpt-3.5-turbo")

# Define prompt template for intent recognition
intent_prompt = PromptTemplate(
    input_variables=["question"],
    template="""
You are an AI assistant specialized in cybersecurity. Analyze the following question and extract the user's intent and parameters.
Respond **only** with a JSON object containing 'action' and 'parameters' fields.

Available actions:
- get_cve_details: Get details about a specific CVE
- search_vulnerabilities: Search for vulnerabilities with specific criteria
- find_by_vendor: Search for vulnerabilities related to a specific vendor/product
- historical_query: Find information about famous vulnerabilities

Question: "{question}"

Return a JSON object like:
{{
    "action": "<action_name>",
    "parameters": {{
        // relevant parameters
    }}
}}
"""
)

def process_intent(question):
    """Process the user's question and return the intent."""
    try:
        prompt = intent_prompt.format(question=question)
        response = llm.invoke(prompt)
        # Clean the response to ensure it's valid JSON
        cleaned_response = response.content.strip()
        return json.loads(cleaned_response)
    except json.JSONDecodeError as e:
        print(f"Error parsing intent: {e}")
        # Return a default search intent
        return {
            "action": "search_vulnerabilities",
            "parameters": {
                "keywords": question
            }
        }

def get_specific_cve_info(text):
    """Extract CVE ID from text if it matches the pattern."""
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    match = re.search(cve_pattern, text, re.IGNORECASE)
    return match.group(0) if match else None

def get_cve_details(cve_id):
    """Fetch CVE details from NVD API."""
    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}'
    headers = {'apiKey': NVD_API_KEY} if NVD_API_KEY else {}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        if data.get('vulnerabilities'):
            vuln = data['vulnerabilities'][0]['cve']
            metrics = vuln.get('metrics', {})
            cvss_data = None
            
            # Try CVSS 3.1 first, then 3.0, then 2.0
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
            
            return {
                'CVE ID': cve_id,
                'Description': vuln.get('descriptions', [{}])[0].get('value', 'No description available'),
                'Published Date': vuln.get('published', 'Unknown'),
                'Last Modified Date': vuln.get('lastModified', 'Unknown'),
                'Impact': cvss_data.get('baseScore', 'Unknown') if cvss_data else 'Unknown',
                'Vector': cvss_data.get('vectorString', 'Unknown') if cvss_data else 'Unknown',
                'References': [ref.get('url') for ref in vuln.get('references', [])]
            }
        return None
    except Exception as e:
        print(f"Error fetching CVE details: {e}")
        return None

def search_vulnerabilities_by_vendor(vendor, start_date=None, end_date=None):
    """Search for vulnerabilities by vendor/product name and date range."""
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    headers = {'apiKey': NVD_API_KEY} if NVD_API_KEY else {}
    
    params = {
        'keywordSearch': vendor,
        'resultsPerPage': 20  # Increased from default
    }
    
    if start_date:
        params['pubStartDate'] = f"{start_date}T00:00:00.000Z"
    if end_date:
        params['pubEndDate'] = f"{end_date}T23:59:59.999Z"

    try:
        response = requests.get(base_url, params=params, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        results = []
        for item in data.get('vulnerabilities', []):
            vuln = item['cve']
            metrics = vuln.get('metrics', {})
            cvss_data = None
            
            # Try different CVSS versions
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
                
            results.append({
                'CVE ID': vuln.get('id'),
                'Description': vuln.get('descriptions', [{}])[0].get('value', 'No description available'),
                'Published Date': vuln.get('published', 'Unknown'),
                'Impact': cvss_data.get('baseScore', 'Unknown') if cvss_data else 'Unknown',
                'Vector': cvss_data.get('vectorString', 'Unknown') if cvss_data else 'Unknown',
                'References': [ref.get('url') for ref in vuln.get('references', [])][:3]  # Limit to first 3 references
            })
        return results
    except Exception as e:
        print(f"Error searching vulnerabilities: {e}")
        return None

def search_vulnerabilities(keywords, start_date=None, end_date=None):
    """General search for vulnerabilities."""
    return search_vulnerabilities_by_vendor(keywords, start_date, end_date)

def main():
    print("Welcome to the Enhanced NVD Vulnerability Search Tool!")
    print("\nYou can:")
    print("1. Search for specific CVEs (e.g., 'Tell me about CVE-2024-47195')")
    print("2. Search by vendor/product (e.g., 'Show OpenSSL vulnerabilities from January 2024')")
    print("3. General keyword search (e.g., 'Find vulnerabilities related to buffer overflow')")
    print("\nType 'exit' or 'quit' to end the session.")
    
    while True:
        try:
            user_input = input("\nYour query: ").strip()
            if user_input.lower() in ['exit', 'quit']:
                print("Goodbye!")
                break

            # First check for direct CVE ID mentions
            specific_cve = get_specific_cve_info(user_input)
            if specific_cve:
                details = get_cve_details(specific_cve)
                if details:
                    print(f"\nCVE Details:")
                    print(f"ID: {details['CVE ID']}")
                    print(f"Description: {details['Description']}")
                    print(f"Published: {details['Published Date']}")
                    print(f"Last Modified: {details['Last Modified Date']}")
                    print(f"CVSS Score: {details['Impact']}")
                    print(f"CVSS Vector: {details['Vector']}")
                    if details['References']:
                        print("\nReferences:")
                        for ref in details['References'][:3]:
                            print(f"- {ref}")
                continue

            # Process intent for other queries
            intent = process_intent(user_input)
            
            if intent['action'] == 'find_by_vendor' or intent['action'] == 'search_vulnerabilities':
                keywords = intent['parameters'].get('vendor', '') or intent['parameters'].get('keywords', '')
                start_date = intent['parameters'].get('start_date')
                end_date = intent['parameters'].get('end_date')
                
                results = search_vulnerabilities(keywords, start_date, end_date)
                if results:
                    print(f"\nFound {len(results)} vulnerabilities:")
                    for idx, res in enumerate(results, 1):
                        print(f"\n{idx}. CVE ID: {res['CVE ID']}")
                        print(f"Description: {res['Description']}")
                        print(f"Published: {res['Published Date']}")
                        print(f"CVSS Score: {res['Impact']}")
                        print(f"CVSS Vector: {res['Vector']}")
                        if res['References']:
                            print("Key References:")
                            for ref in res['References']:
                                print(f"- {ref}")
                else:
                    print("No vulnerabilities found matching your criteria.")
            else:
                print("I'll perform a general search based on your query.")
                results = search_vulnerabilities(user_input)
                if results:
                    print(f"\nFound {len(results)} potentially relevant vulnerabilities:")
                    for idx, res in enumerate(results, 1):
                        print(f"\n{idx}. {res['CVE ID']}")
                        print(f"Description: {res['Description']}")
                        print(f"CVSS Score: {res['Impact']}")

        except Exception as e:
            print(f"An error occurred: {e}")
            print("Please try rephrasing your query.")

if __name__ == "__main__":
    main()