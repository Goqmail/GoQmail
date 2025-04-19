"""
Ollama-based AI Email Analyzer.

This module provides security analysis using a locally running Llama model via Ollama.
It sends email content to the local Ollama server for analysis instead of using OpenAI.
"""

import json
import logging
import re
import requests
from typing import List, Dict, Any, Optional

# Set up logger
logger = logging.getLogger(__name__)

# Ollama API endpoint configuration
# Default local installation endpoint
OLLAMA_API_URL = "http://localhost:11434/api/generate"

# Get custom Ollama endpoint from environment if set
import os
OLLAMA_CUSTOM_ENDPOINT = os.environ.get("OLLAMA_API_URL")
if OLLAMA_CUSTOM_ENDPOINT:
    OLLAMA_API_URL = OLLAMA_CUSTOM_ENDPOINT
    logger.info(f"Using custom Ollama endpoint: {OLLAMA_API_URL}")
else:
    logger.info(f"Using default local Ollama endpoint: {OLLAMA_API_URL}")

# Model to use - make sure this matches the model name in your Ollama installation
# Common model names: llama3, llama3:8b, llama3:70b, llama2, etc.
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3")
logger.info(f"Using Ollama model: {OLLAMA_MODEL}")

def analyze_email_with_ollama(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a single email using a local Llama model via Ollama.
    
    Args:
        email_data: Dictionary containing email data
    
    Returns:
        Dictionary with security analysis results
    """
    try:
        # Extract relevant information from email
        sender = email_data.get('from', '')
        subject = email_data.get('subject', '')
        body = email_data.get('body', '')
        
        # Extract domain from sender
        domain = extract_domain_from_email(sender)
        
        # Create prompt for Llama
        prompt = f"""Analyze this email for security concerns and potential phishing attempts:

From: {sender}
Subject: {subject}

Content:
{body[:1000]}

Based on this email, please analyze:
1. Security risk level (Safe, Cautious, or Suspicious)
2. Security score from 1-10 (10 being completely safe)
3. Any suspicious patterns detected
4. Whether the sender domain is trustworthy
5. Recommendations for the user

Format your response as JSON with the following structure:
{{
  "risk_level": "Safe|Cautious|Suspicious",
  "security_score": <number 1-10>,
  "is_trusted_domain": <boolean>,
  "suspicious_patterns": ["pattern1", "pattern2"],
  "recommendations": ["rec1", "rec2"],
  "explanation": "Brief explanation of analysis"
}}
"""
        
        # Send request to Ollama
        response = requests.post(
            OLLAMA_API_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=30  # 30 second timeout
        )
        
        if response.status_code != 200:
            logger.error(f"Error from Ollama API: {response.status_code}, {response.text}")
            return fallback_analysis(email_data)
        
        # Extract the response content
        response_json = response.json()
        response_text = response_json.get("response", "")
        
        # Try to parse the JSON response
        try:
            # Find JSON-like content in the response
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                json_str = json_match.group(0)
                analysis = json.loads(json_str)
            else:
                # If no JSON found, extract information manually
                analysis = parse_analysis_from_text(response_text)
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse JSON from Ollama response, trying fallback parsing")
            analysis = parse_analysis_from_text(response_text)
        
        # Ensure all required fields are present
        analysis = ensure_complete_analysis(analysis, domain, email_data)
        
        return {
            'security_analysis': analysis
        }
    
    except Exception as e:
        logger.error(f"Error in Ollama analysis: {str(e)}")
        return fallback_analysis(email_data)

def parse_analysis_from_text(text: str) -> Dict[str, Any]:
    """
    Parse a non-JSON analysis text into a structured format.
    
    Args:
        text: The analysis text from the Llama model
        
    Returns:
        A structured analysis dictionary
    """
    # Default values
    analysis = {
        'risk_level': 'Cautious',
        'security_score': 5,
        'is_trusted_domain': False,
        'suspicious_patterns': [],
        'recommendations': [],
        'explanation': "Analysis based on text extraction"
    }
    
    # Extract risk level
    risk_patterns = [
        r'risk[_\s]level[:\s]*["\']*([A-Za-z]+)["\']',
        r'risk[:\s]*["\']*([A-Za-z]+)["\']'
    ]
    for pattern in risk_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            risk = match.group(1).strip().lower()
            if 'safe' in risk:
                analysis['risk_level'] = 'Safe'
            elif 'suspicious' in risk:
                analysis['risk_level'] = 'Suspicious'
            else:
                analysis['risk_level'] = 'Cautious'
            break
    
    # Extract security score
    score_match = re.search(r'security[_\s]score[:\s]*(\d+)', text, re.IGNORECASE)
    if score_match:
        try:
            score = int(score_match.group(1))
            analysis['security_score'] = max(1, min(10, score))  # Ensure between 1-10
        except ValueError:
            pass
    
    # Extract trusted domain status
    trusted_match = re.search(r'trusted[_\s]domain[:\s]*(true|false)', text, re.IGNORECASE)
    if trusted_match:
        analysis['is_trusted_domain'] = trusted_match.group(1).lower() == 'true'
    
    # Extract suspicious patterns
    patterns_section = re.search(r'suspicious[_\s]patterns[:\s]*(.*?)(?:recommendations|$)', text, re.IGNORECASE | re.DOTALL)
    if patterns_section:
        patterns_text = patterns_section.group(1)
        patterns = re.findall(r'[-*•]\s*([^\n]+)', patterns_text)
        if patterns:
            analysis['suspicious_patterns'] = [p.strip() for p in patterns]
    
    # Extract recommendations
    recommendations_section = re.search(r'recommendations[:\s]*(.*?)(?:explanation|$)', text, re.IGNORECASE | re.DOTALL)
    if recommendations_section:
        recommendations_text = recommendations_section.group(1)
        recommendations = re.findall(r'[-*•]\s*([^\n]+)', recommendations_text)
        if recommendations:
            analysis['recommendations'] = [r.strip() for r in recommendations]
    
    # Extract explanation
    explanation_match = re.search(r'explanation[:\s]*(.*?)(?:$)', text, re.IGNORECASE | re.DOTALL)
    if explanation_match:
        analysis['explanation'] = explanation_match.group(1).strip()
    
    return analysis

def extract_domain_from_email(email_address: str) -> str:
    """
    Extract the domain from an email address.
    
    Args:
        email_address: The full email address string
        
    Returns:
        The domain portion of the email address
    """
    if not email_address or '@' not in email_address:
        return ""
    
    # Try to handle complex cases like "Name <email@domain.com>"
    if '<' in email_address and '>' in email_address:
        email_part = email_address.split('<')[1].split('>')[0]
    else:
        email_part = email_address
    
    # Extract domain part (after @)
    return email_part.split('@')[-1].strip().lower() if '@' in email_part else ""

def ensure_complete_analysis(analysis: Dict[str, Any], domain: str, email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure the analysis has all required fields.
    
    Args:
        analysis: The analysis dictionary to complete
        domain: The sender domain
        email_data: The original email data
        
    Returns:
        A complete analysis dictionary
    """
    # Set defaults for missing fields
    if 'risk_level' not in analysis:
        analysis['risk_level'] = 'Cautious'
    
    if 'security_score' not in analysis:
        analysis['security_score'] = 5
    
    if 'is_trusted_domain' not in analysis:
        analysis['is_trusted_domain'] = is_common_trusted_domain(domain)
    
    if 'suspicious_patterns' not in analysis:
        analysis['suspicious_patterns'] = []
    
    if 'recommendations' not in analysis:
        analysis['recommendations'] = []
    
    if 'explanation' not in analysis:
        analysis['explanation'] = "Analysis performed with limited information"
    
    # Add domain info
    analysis['domain'] = domain
    
    return analysis

def is_common_trusted_domain(domain: str) -> bool:
    """
    Check if a domain is in the list of commonly trusted domains.
    
    Args:
        domain: The domain to check
        
    Returns:
        True if the domain is commonly trusted, False otherwise
    """
    common_trusted_domains = [
        # Email providers
        'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'icloud.com', 'aol.com',
        'protonmail.com', 'zoho.com', 'gmx.com', 'mail.com', 'yandex.com',
        # Companies
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
        'twitter.com', 'linkedin.com', 'instagram.com', 'adobe.com', 'salesforce.com',
        # Education
        'edu', '.edu', 'harvard.edu', 'stanford.edu', 'mit.edu',
        # Government
        'gov', '.gov', 'nasa.gov', 'whitehouse.gov',
        # Others
        'github.com', 'stackoverflow.com', 'w3.org', 'python.org', 'wikipedia.org'
    ]
    
    return any(trusted in domain.lower() for trusted in common_trusted_domains)

def fallback_analysis(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a fallback analysis when Ollama API fails.
    
    Args:
        email_data: The email data dictionary
        
    Returns:
        Dictionary with basic security analysis
    """
    # Import rule-based analysis for fallback
    from email_security import analyze_email_security
    
    # Use rule-based analysis as fallback
    logger.info("Using rule-based analysis as fallback")
    return analyze_email_security(email_data)

def batch_analyze_emails(emails: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Analyze a batch of emails using Llama via Ollama.
    
    Args:
        emails: List of email dictionaries
    
    Returns:
        List of emails with security analysis added
    """
    results = []
    
    for email in emails:
        try:
            result = {**email}  # Create a copy of the email dict
            
            # Add security analysis
            analysis_result = analyze_email_with_ollama(email)
            result['security_analysis'] = analysis_result.get('security_analysis', {})
            
            results.append(result)
        except Exception as e:
            logger.error(f"Error analyzing email: {str(e)}")
            # Add the original email with fallback analysis
            fallback = fallback_analysis(email)
            email.update(fallback)
            results.append(email)
    
    return results

# Health check function to test connection to Ollama
def check_ollama_connection() -> Dict[str, Any]:
    """
    Test the connection to the Ollama API.
    
    Returns:
        Dictionary with connection status and details
    """
    try:
        # Use a minimal prompt to test connectivity
        response = requests.post(
            OLLAMA_API_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": "Hello, are you available?",
                "stream": False
            },
            timeout=10  # Short timeout for quick check
        )
        
        if response.status_code == 200:
            response_json = response.json()
            return {
                "status": "connected",
                "model": OLLAMA_MODEL,
                "endpoint": OLLAMA_API_URL,
                "response": response_json.get("response", "")[:50] + "..." if response_json.get("response") else ""
            }
        else:
            return {
                "status": "error",
                "model": OLLAMA_MODEL,
                "endpoint": OLLAMA_API_URL,
                "error": f"HTTP {response.status_code}: {response.text}"
            }
    except Exception as e:
        logger.error(f"Error connecting to Ollama: {str(e)}")
        return {
            "status": "error",
            "model": OLLAMA_MODEL, 
            "endpoint": OLLAMA_API_URL,
            "error": str(e)
        }

# Main function for direct use
def analyze_email_security(email: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze an email for security concerns using Llama via Ollama.
    
    Args:
        email: Dictionary containing email data
        
    Returns:
        Dictionary with security analysis results
    """
    return analyze_email_with_ollama(email)