import os
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime
import requests
from pydantic import BaseModel, Field, field_validator
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_core.prompts import ChatPromptTemplate
from dotenv import load_dotenv
from requests.exceptions import RequestException

# Load environment variables
load_dotenv()
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
NVD_API_KEY = os.getenv('NVD_API_KEY')

class NVDUtils:
    BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    
    @staticmethod
    def get_cvss_data(metrics: dict) -> Tuple[dict, str]:
        """Extract CVSS data and severity from metrics."""
        cvss_data = None
        for metric_type in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if metric_type in metrics:
                cvss_data = metrics[metric_type][0].get('cvssData', {})
                break
        
        severity = 'Unknown'
        if cvss_data and 'baseScore' in cvss_data:
            score = float(cvss_data['baseScore'])
            if score >= 9.0:
                severity = 'CRITICAL'
            elif score >= 7.0:
                severity = 'HIGH'
            elif score >= 4.0:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
                
        return cvss_data, severity

    @staticmethod
    def make_nvd_request(params: dict = None) -> dict:
        """Make a request to the NVD API with proper error handling."""
        headers = {'apiKey': NVD_API_KEY} if NVD_API_KEY else {}
        
        try:
            response = requests.get(
                NVDUtils.BASE_URL,
                params=params,
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except RequestException as e:
            if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 404:
                return {"vulnerabilities": []}
            elif isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 403:
                raise ValueError("API key required or invalid API key")
            elif isinstance(e, requests.exceptions.Timeout):
                raise ValueError("Request timed out. Please try again.")
            else:
                raise ValueError(f"Error accessing NVD API: {str(e)}")

class KeywordSearchArgs(BaseModel):
    keywords: str = Field(description="Keywords to search for vulnerabilities")
    year: Optional[int] = Field(None, description="Year to search in (YYYY)")
    month: Optional[int] = Field(None, description="Month to search in (1-12)")
    day: Optional[int] = Field(None, description="Day to search in (1-31)")
    severity: Optional[str] = Field(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)")
    limit: Optional[int] = Field(20, description="Number of results to return")

class CVELookupArgs(BaseModel):
    cve_id: str = Field(description="The CVE ID to look up (format: CVE-YYYY-NNNNN)")
    
    @field_validator('cve_id')
    @classmethod
    def validate_cve_id(cls, v: str) -> str:
        if not v.startswith('CVE-') or not len(v.split('-')) == 3:
            raise ValueError('Invalid CVE ID format. Must be CVE-YYYY-NNNNN')
        return v.upper()

class StatisticsArgs(BaseModel):
    timeframe: str = Field(description="Timeframe for statistics (e.g., 'today', 'this_week', 'this_month', 'this_year')")

@tool(args_schema=CVELookupArgs)
def get_cve_details(cve_id: str) -> str:
    """Get detailed information about a specific CVE ID."""
    params = {'cveId': cve_id}
    
    try:
        data = NVDUtils.make_nvd_request(params)
        
        if not data.get('vulnerabilities'):
            return f"No information found for {cve_id}"
            
        vuln = data['vulnerabilities'][0]['cve']
        cvss_data, severity = NVDUtils.get_cvss_data(vuln.get('metrics', {}))
        
        result = [
            f"### {cve_id} Details:",
            f"**Severity:** {severity}",
            f"**Description:** {vuln.get('descriptions', [{}])[0].get('value', 'No description available')}",
            f"**Published Date:** {vuln.get('published', 'Unknown').split('T')[0]}",
            f"**Last Modified:** {vuln.get('lastModified', 'Unknown').split('T')[0]}"
        ]
        
        if cvss_data:
            result.extend([
                f"**CVSS Score:** {cvss_data.get('baseScore', 'Unknown')} ({severity})",
                f"**Attack Vector:** {cvss_data.get('attackVector', 'Unknown')}",
                f"**Attack Complexity:** {cvss_data.get('attackComplexity', 'Unknown')}",
                f"**Privileges Required:** {cvss_data.get('privilegesRequired', 'Unknown')}",
                f"**User Interaction:** {cvss_data.get('userInteraction', 'Unknown')}",
                f"**Scope:** {cvss_data.get('scope', 'Unknown')}",
                f"**Confidentiality Impact:** {cvss_data.get('confidentialityImpact', 'Unknown')}",
                f"**Integrity Impact:** {cvss_data.get('integrityImpact', 'Unknown')}",
                f"**Availability Impact:** {cvss_data.get('availabilityImpact', 'Unknown')}",
                f"**CVSS Vector:** {cvss_data.get('vectorString', 'Unknown')}"
            ])
        
        references = vuln.get('references', [])
        if references:
            result.append("\n#### Key References:")
            for ref in references[:5]:
                result.append(f"- {ref.get('source', 'Unknown')}: {ref.get('url', 'No URL available')}")
        
        configurations = vuln.get('configurations', [])
        if configurations:
            result.append("\n#### Affected Systems/Software:")
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe in node.get('cpeMatch', []):
                        result.append(f"- {cpe.get('criteria', 'Unknown')}")
        
        return "\n".join(result)
    except ValueError as e:
        return str(e)
    
@tool
def get_security_concepts() -> str:
    """Provide explanations of common security concepts and terminology."""
    return """Here are some key security concepts:

CVSS (Common Vulnerability Scoring System):
- Standardized method for rating the severity of security vulnerabilities
- Scores range from 0.0 to 10.0
- Considers factors like attack complexity, required privileges, and impact

Severity Levels:
- CRITICAL (CVSS 9.0-10.0): Severe vulnerabilities requiring immediate attention
- HIGH (CVSS 7.0-8.9): Significant vulnerabilities that should be prioritized
- MEDIUM (CVSS 4.0-6.9): Moderate risk vulnerabilities
- LOW (CVSS 0.1-3.9): Minor vulnerabilities with limited impact

Common Vulnerability Types:
- Buffer Overflow: Program writing beyond memory buffer boundaries
- SQL Injection: Malicious SQL code insertion into database queries
- Cross-Site Scripting (XSS): Malicious script injection into web pages
- Remote Code Execution (RCE): Attacker executing arbitrary code remotely
- Privilege Escalation: Gaining elevated system access rights

Security Terminology:
- Zero-day: Previously unknown vulnerability being actively exploited
- Patch: Software update that fixes security vulnerabilities
- Exploit: Code or technique that takes advantage of a vulnerability
- Mitigation: Methods to reduce or eliminate vulnerability risks"""

@tool(args_schema=StatisticsArgs)
def get_vulnerability_statistics(timeframe: str) -> str:
    """Get vulnerability statistics for a specific timeframe."""
    # Calculate date ranges based on timeframe
    now = datetime.now()
    
    if timeframe == "today":
        start_date = now.strftime("%Y-%m-%d")
        end_date = start_date
    elif timeframe == "this_week":
        start_date = (now - datetime.timedelta(days=now.weekday())).strftime("%Y-%m-%d")
        end_date = now.strftime("%Y-%m-%d")
    elif timeframe == "this_month":
        start_date = now.strftime("%Y-%m-01")
        end_date = now.strftime("%Y-%m-%d")
    elif timeframe == "this_year":
        start_date = now.strftime("%Y-01-01")
        end_date = now.strftime("%Y-%m-%d")
    else:
        return "Invalid timeframe. Please use 'today', 'this_week', 'this_month', or 'this_year'."

    params = {
        'pubStartDate': f"{start_date}T00:00:00.000",
        'pubEndDate': f"{end_date}T23:59:59.999",
        'resultsPerPage': 1  # We only need the total count
    }

    try:
        data = NVDUtils.make_nvd_request(params)
        total_vulns = data.get('totalResults', 0)
        
        # Get severity breakdown
        severity_params = params.copy()
        severity_params['resultsPerPage'] = total_vulns
        
        if total_vulns > 0:
            full_data = NVDUtils.make_nvd_request(severity_params)
            
            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'Unknown': 0}
            for item in full_data.get('vulnerabilities', []):
                _, severity = NVDUtils.get_cvss_data(item['cve'].get('metrics', {}))
                severity_counts[severity] += 1
            
            return f"""Vulnerability Statistics for {timeframe}:
Total Vulnerabilities: {total_vulns}

Severity Breakdown:
- Critical: {severity_counts['CRITICAL']} ({(severity_counts['CRITICAL']/total_vulns*100):.1f}%)
- High: {severity_counts['HIGH']} ({(severity_counts['HIGH']/total_vulns*100):.1f}%)
- Medium: {severity_counts['MEDIUM']} ({(severity_counts['MEDIUM']/total_vulns*100):.1f}%)
- Low: {severity_counts['LOW']} ({(severity_counts['LOW']/total_vulns*100):.1f}%)
- Unknown: {severity_counts['Unknown']} ({(severity_counts['Unknown']/total_vulns*100):.1f}%)"""
        
        return f"No vulnerabilities found for {timeframe}"
    except ValueError as e:
        return str(e)

@tool(args_schema=KeywordSearchArgs)
def search_vulnerabilities(
    keywords: str,
    year: Optional[int] = None,
    month: Optional[int] = None,
    day: Optional[int] = None,
    severity: Optional[str] = None,
    limit: int = 20
) -> str:
    """Search for vulnerabilities using keywords, dates, and severity filters."""
    params = {
        'keywordSearch': keywords,
        'resultsPerPage': limit
    }
    
    # Date filtering
    if year:
        if month and day:
            date_str = f"{year:04d}-{month:02d}-{day:02d}"
            params['pubStartDate'] = f"{date_str}T00:00:00.000"
            params['pubEndDate'] = f"{date_str}T23:59:59.999"
        elif month:
            start_date = f"{year:04d}-{month:02d}-01"
            if month == 12:
                end_date = f"{year+1:04d}-01-01"
            else:
                end_date = f"{year:04d}-{month+1:02d}-01"
            params['pubStartDate'] = f"{start_date}T00:00:00.000"
            params['pubEndDate'] = f"{end_date}T00:00:00.000"
        else:
            params['pubStartDate'] = f"{year:04d}-01-01T00:00:00.000"
            params['pubEndDate'] = f"{year:04d}-12-31T23:59:59.999"
    
    try:
        data = NVDUtils.make_nvd_request(params)
        
        if not data.get('vulnerabilities'):
            timeframe = f" in {year}" if year else ""
            if month:
                timeframe += f"-{month:02d}"
            if day:
                timeframe += f"-{day:02d}"
            return f"No vulnerabilities found for '{keywords}'{timeframe}"
            
        results = []
        for item in data['vulnerabilities']:
            vuln = item['cve']
            cvss_data, current_severity = NVDUtils.get_cvss_data(vuln.get('metrics', {}))
            
            # Apply severity filter if specified
            if severity and severity.upper() != current_severity:
                continue
                
            results.append(
                f"\nCVE ID: {vuln.get('id')}"
                f"\nSeverity: {current_severity} (CVSS: {cvss_data.get('baseScore', 'Unknown') if cvss_data else 'Unknown'})"
                f"\nPublished: {vuln.get('published', 'Unknown').split('T')[0]}"
                f"\nDescription: {vuln.get('descriptions', [{}])[0].get('value', 'No description available')}"
                f"\nVector: {cvss_data.get('vectorString', 'Unknown') if cvss_data else 'Unknown'}"
            )
        
        if not results:
            return f"No vulnerabilities found matching the specified criteria"
            
        timeframe = f" in {year}" if year else ""
        if month:
            timeframe += f"-{month:02d}"
        if day:
            timeframe += f"-{day:02d}"
            
        severity_filter = f" with {severity} severity" if severity else ""
        return f"Found {len(results)} vulnerabilities for '{keywords}'{timeframe}{severity_filter}:\n{'---'.join(results)}"
    except ValueError as e:
        return str(e)

def create_agent() -> AgentExecutor:
    """Create and configure the LangChain agent with enhanced capabilities."""
    try:
        llm = ChatOpenAI(
            api_key=OPENAI_API_KEY,
            temperature=0,
            model="gpt-3.5-turbo",
            max_retries=2
        )
    except Exception as e:
        raise ValueError(f"Error initializing ChatOpenAI: {str(e)}")
    
    tools = [
        get_cve_details,
        search_vulnerabilities,
        get_security_concepts,
        get_vulnerability_statistics
    ]
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a comprehensive cybersecurity expert assistant specialized in vulnerability research and security concepts.
Your role is to help users understand security vulnerabilities, concepts, and trends using the National Vulnerability Database (NVD).

Available tools:
1. get_cve_details - Look up specific CVE IDs
2. search_vulnerabilities - Search vulnerabilities by keywords, dates, and severity
3. get_security_concepts - Explain security terminology and concepts
4. get_vulnerability_statistics - Get vulnerability statistics for different timeframes

Capabilities:
- Detailed vulnerability information with severity scores and descriptions
- Security concept explanations and terminology
- Vulnerability trends and statistics
- Filtered searches by severity and date
- Historical vulnerability information

When responding:
- If the user asks about security concepts, use get_security_concepts first
- For trend analysis, use get_vulnerability_statistics
- For specific vulnerabilities, use get_cve_details or search_vulnerabilities
- Provide context and explanations for technical terms
- Include severity levels and CVSS scores when available
- Highlight key references and mitigation strategies when relevant"""),
        ("human", "{input}"),
        ("assistant", "{agent_scratchpad}")
    ])
    
    agent = create_openai_tools_agent(llm, tools, prompt)
    return AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,
        max_iterations=3
    )

def main():
    """Enhanced main chat loop with broader query handling."""
    print("""Welcome to the Enhanced Security Assistant!

You can ask about:
1. Specific vulnerabilities (e.g., "Tell me about CVE-2024-47195")
2. Vulnerability searches (e.g., "Show me critical OpenSSL vulnerabilities from 2023")
3. Security concepts (e.g., "What is CVSS scoring?")
4. Vulnerability statistics (e.g., "How many vulnerabilities were reported this month?")
5. Historical vulnerabilities (e.g., "Tell me about the Heartbleed vulnerability")

Type 'exit' or 'quit' to end the session.""")
    
    try:
        agent = create_agent()
    except ValueError as e:
        print(f"Error initializing agent: {e}")
        return
    
    while True:
        try:
            user_input = input("\nYour query: ").strip()
            if user_input.lower() in ['exit', 'quit']:
                print("Goodbye!")
                break
                
            response = agent.invoke({"input": user_input})
            print("\nResponse:", response["output"])
            
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            print("Please try rephrasing your query.")

if __name__ == "__main__":
    main()