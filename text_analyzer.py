"""
Text Message Analyzer for security concerns.

This module provides functionality to analyze text messages for phishing attempts,
scams, and other security concerns using both AI and rule-based approaches.
"""

import os
import time
import logging
import re
from typing import Dict, Any, List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize variables for OpenAI
client = None

# Conditionally import OpenAI libraries
try:
    import openai
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    logger.warning("OpenAI libraries not available. Will use rule-based analysis only.")
    OPENAI_AVAILABLE = False

def initialize_openai_client():
    """Initialize the OpenAI client with API key from environment."""
    global client
    
    # First check if OpenAI is available at all
    if not OPENAI_AVAILABLE:
        logger.warning("OpenAI libraries not installed or available")
        return False
    
    try:
        if not client and os.environ.get("OPENAI_API_KEY"):
            client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
            return True
    except Exception as e:
        logger.error(f"Error initializing OpenAI client: {e}")
    
    return False

def rule_based_analysis(text_content: str, sender: str = None) -> Dict[str, Any]:
    """
    Analyze a text message using enhanced rule-based approach with domain trust assessment.
    
    Args:
        text_content: The content of the text message
        sender: Optional sender information (phone number or contact name)
    
    Returns:
        Dictionary with security analysis results
    """
    # Initialize result
    result = {
        "is_suspicious": False,
        "security_score": 7,  # Default to a cautiously good score
        "risk_level": "Probably Safe",
        "suspicious_patterns": [],
        "explanation": "Basic rule-based analysis detected no obvious threats.",
        "recommendations": ["Always verify unexpected messages from unknown sources."]
    }
    
    # Extract and check domains
    domains = extract_domains_from_text(text_content)
    domain_assessment = None
    
    if domains:
        domain_assessment = check_domain_trustworthiness(domains)
        
        # Update result based on domain assessment
        if domain_assessment["untrusted_domains"]:
            result["suspicious_patterns"].append(f"Unrecognized domain(s): {', '.join(domain_assessment['untrusted_domains'])}")
            result["security_score"] -= min(3, len(domain_assessment["untrusted_domains"]))
            
        if domain_assessment["trusted_domains"]:
            result["explanation"] += f" Contains trusted domain(s): {', '.join(domain_assessment['trusted_domains'])}."
            result["security_score"] = min(10, result["security_score"] + domain_assessment["trust_bonus"])
        
        if domain_assessment["risk_penalty"] > 0:
            result["security_score"] = max(1, result["security_score"] - domain_assessment["risk_penalty"])
    
    # Check for other suspicious patterns
    pattern_analysis = check_for_sketchy_patterns(text_content)
    
    # Combine the results
    if pattern_analysis["suspicious_patterns"]:
        result["suspicious_patterns"].extend(pattern_analysis["suspicious_patterns"])
        
    if pattern_analysis["score_adjustment"]:
        result["security_score"] = max(1, min(10, result["security_score"] + pattern_analysis["score_adjustment"]))
        
    if pattern_analysis["explanation"]:
        result["explanation"] += " " + pattern_analysis["explanation"]
    
    # Check for sensitive information requests
    info_requests = check_sensitive_info_requests(text_content)
    if info_requests:
        result["suspicious_patterns"].extend(info_requests)
        result["security_score"] = max(1, result["security_score"] - len(info_requests))
        result["explanation"] += " Message asks for sensitive information."
        result["recommendations"].append("Never share sensitive information through unsolicited messages.")
    
    # Update risk level based on final security score
    if result["security_score"] >= 8:
        result["risk_level"] = "Secure"
    elif result["security_score"] >= 6:
        result["risk_level"] = "Probably Safe"
    elif result["security_score"] >= 3:
        result["risk_level"] = "Cautious"
    else:
        result["risk_level"] = "Unsafe"
        result["is_suspicious"] = True
    
    # Add more recommendations based on findings
    if result["suspicious_patterns"]:
        result["is_suspicious"] = True
        result["recommendations"].append("Avoid clicking links from unknown or suspicious messages.")
        
        if any("url shortener" in pattern.lower() for pattern in result["suspicious_patterns"]):
            result["recommendations"].append("Be wary of shortened URLs that hide the destination.")
    
    return result

def analyze_text_with_openai(text_content: str, sender: str = None) -> Dict[str, Any]:
    """
    Analyze a text message using OpenAI API with enhanced domain trust information.
    
    Args:
        text_content: The content of the text message
        sender: Optional sender information (phone number or contact name)
    
    Returns:
        Dictionary with security analysis results
    """
    try:
        # Check if OpenAI API key is available
        if not os.environ.get("OPENAI_API_KEY"):
            logger.warning("OPENAI_API_KEY not found in environment variables")
            return rule_based_analysis(text_content, sender)
        
        # Initialize the client if needed
        if not initialize_openai_client():
            return rule_based_analysis(text_content, sender)
        
        # Extract domains and get domain trust assessment
        domains = extract_domains_from_text(text_content)
        domain_info = ""
        
        if domains:
            domain_assessment = check_domain_trustworthiness(domains)
            
            if domain_assessment["trusted_domains"]:
                trusted_domains_str = ", ".join(domain_assessment["trusted_domains"])
                domain_info += f"\nTrusted domains detected: {trusted_domains_str}"
            
            if domain_assessment["untrusted_domains"]:
                untrusted_domains_str = ", ".join(domain_assessment["untrusted_domains"])
                domain_info += f"\nUnknown domains detected: {untrusted_domains_str}"
            
            # Add details about individual domains
            if domain_assessment["details"]:
                domain_info += "\nDomain details:"
                for detail in domain_assessment["details"]:
                    domain_info += f"\n- {detail['domain']}: {detail['reason']}"
        
        # Prepare message content
        sender_info = f"Sender: {sender}\n" if sender else ""
        message_content = f"{sender_info}Message: {text_content}{domain_info}"
        
        # Call OpenAI API with a longer timeout to prevent timeout errors
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": """
                You are a cybersecurity expert specialized in detecting phishing and scam attempts in text messages.
                Analyze the provided message for security concerns, paying special attention to:
                1. Presence of trusted/untrusted domains (.edu and .gov domains are more trustworthy)
                2. Requests for sensitive information
                3. Urgency language or pressure tactics
                4. Suspicious links or URL shorteners
                5. Offers that seem too good to be true
                
                Consider trusted domains as a positive sign, but be cautious of unknown domains.
                
                You must respond in this specific JSON format:
                {
                    "is_suspicious": true/false,
                    "security_score": 1-10 (1=dangerous, 10=secure),
                    "risk_level": "Dangerous/Unsafe/Suspicious/Probably Safe/Secure",
                    "suspicious_patterns_detected": ["pattern1", "pattern2"],
                    "explanation": "Brief explanation of analysis",
                    "recommendations": ["recommendation1", "recommendation2"]
                }
                """
                },
                {"role": "user", "content": message_content}
            ],
            max_tokens=800,
            timeout=30.0  # Increased timeout to 30 seconds for better reliability
        )
        
        # Extract analysis from response
        analysis_text = response.choices[0].message.content.strip()
        
        # Try to parse the response as JSON
        import json
        try:
            analysis = json.loads(analysis_text)
        except json.JSONDecodeError:
            # If JSON parsing fails, try to extract structured data from text
            analysis = extract_analysis_from_text(analysis_text)
            
        # Set security score and risk level based on the score
        if "security_score" not in analysis:
            analysis["security_score"] = 5
            
        if "risk_level" not in analysis:
            score = analysis["security_score"]
            if score >= 8:
                analysis["risk_level"] = "Secure"
            elif score >= 6:
                analysis["risk_level"] = "Cautious"
            elif score >= 3:
                analysis["risk_level"] = "Unsafe"
            else:
                analysis["risk_level"] = "Dangerous"
        
        # Ensure recommendations is a list
        if "recommendations" in analysis:
            recommendations = analysis["recommendations"]
            if isinstance(recommendations, str):
                if recommendations and recommendations != "Not provided by analysis":
                    analysis["recommendations"] = [recommendations]
                else:
                    analysis["recommendations"] = ["Be cautious with unexpected messages from unknown sources."]
        else:
            analysis["recommendations"] = ["Be cautious with unexpected messages from unknown sources."]
            
        return {
            "is_suspicious": analysis.get("is_suspicious", False),
            "security_score": analysis.get("security_score", 5),
            "risk_level": analysis.get("risk_level", "Unknown"),
            "suspicious_patterns": analysis.get("suspicious_patterns_detected", []),
            "explanation": analysis.get("explanation", ""),
            "recommendations": analysis.get("recommendations", [])
        }
    
    except Exception as e:
        logger.error(f"Error in AI text analysis: {str(e)}")
        # Fallback to rule-based analysis
        return rule_based_analysis(text_content, sender)

def check_sensitive_info_requests(text_content: str) -> List[str]:
    """
    Check for requests for sensitive information in text.
    
    Args:
        text_content: The text content to analyze
    
    Returns:
        List of detected sensitive information requests
    """
    patterns = [
        (r'(?i)(?:provide|send|confirm|verify|update).{0,30}(?:password|pass\s?word)', "Request for password"),
        (r'(?i)(?:provide|send|confirm|verify|update).{0,30}(?:username|user\s?name)', "Request for username"),
        (r'(?i)(?:provide|send|confirm|verify|update).{0,30}(?:social security|ssn)', "Request for Social Security Number"),
        (r'(?i)(?:provide|send|confirm|verify|update).{0,30}(?:credit card|card number|cvv|expir)', "Request for credit card details"),
        (r'(?i)(?:provide|send|confirm|verify|update).{0,30}(?:bank\s?account)', "Request for bank account information"),
        (r'(?i)(?:login|log in|signin|sign in).{0,30}(?:details|credentials)', "Request for login credentials"),
        (r'(?i)(?:verify|confirm).{0,30}(?:identity|account)', "Request for identity verification"),
        (r'(?i)(?:click|follow).{0,30}(?:link|url)', "Request to click on a link"),
        (r'(?i)(?:provide|send|confirm|verify|update).{0,30}(?:address|personal\s?info)', "Request for personal information"),
        (r'(?i)(?:otp|one\s?time\s?password|verification\s?code)', "Request for verification code")
    ]

    results = []
    for pattern, description in patterns:
        if re.search(pattern, text_content):
            results.append(description)
    
    return results

def extract_analysis_from_text(text: str) -> Dict[str, Any]:
    """
    Parse a non-JSON analysis text into a structured format.
    
    Args:
        text: The analysis text from the LLM
        
    Returns:
        A structured analysis dictionary
    """
    analysis = {
        "is_suspicious": False,
        "security_score": 5,
        "risk_level": "Cautious",
        "suspicious_patterns_detected": [],
        "recommendations": []
    }
    
    # Extract security score
    score_match = re.search(r'security_score["\s:]+(\d+)', text)
    if score_match:
        try:
            analysis["security_score"] = int(score_match.group(1))
        except ValueError:
            pass
    
    # Extract risk level
    if "dangerous" in text.lower():
        analysis["risk_level"] = "Dangerous"
    elif "unsafe" in text.lower():
        analysis["risk_level"] = "Unsafe"
    elif "secure" in text.lower():
        analysis["risk_level"] = "Secure"
    else:
        analysis["risk_level"] = "Cautious"
    
    # Extract is_suspicious
    analysis["is_suspicious"] = "suspicious" in text.lower() or analysis["risk_level"] in ["Dangerous", "Unsafe"]
    
    # Extract patterns - look for list-like patterns
    patterns_section = re.search(r'suspicious_patterns_detected["\s:]+\[(.*?)\]', text, re.DOTALL)
    if patterns_section:
        patterns_text = patterns_section.group(1)
        patterns = re.findall(r'"([^"]+)"', patterns_text)
        if patterns:
            analysis["suspicious_patterns_detected"] = patterns
    
    # Extract recommendations
    recommendations_section = re.search(r'recommendations["\s:]+\[(.*?)\]', text, re.DOTALL)
    if recommendations_section:
        recommendations_text = recommendations_section.group(1)
        recommendations = re.findall(r'"([^"]+)"', recommendations_text)
        if recommendations:
            analysis["recommendations"] = recommendations
    
    # Extract explanation
    explanation_match = re.search(r'explanation["\s:]+["\'](.*?)["\']', text, re.DOTALL)
    if explanation_match:
        analysis["explanation"] = explanation_match.group(1).strip()
    
    return analysis

def extract_domains_from_text(text: str) -> List[str]:
    """
    Extract all domains from URLs in text.
    
    Args:
        text: The text to analyze
        
    Returns:
        List of domains found in the text
    """
    # URL pattern that captures the domain
    url_pattern = r'https?://(?:www\.)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)'
    
    # Find all matches
    domains = re.findall(url_pattern, text)
    
    # Also look for potential domains without http/https
    domain_pattern = r'(?<!\S)([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)(?!\S)'
    
    # Add domains without http/https
    domains.extend(re.findall(domain_pattern, text))
    
    # Return unique domains
    return list(set(domains))

def check_domain_trustworthiness(domains: List[str]) -> Dict[str, Any]:
    """
    Evaluate domains for trustworthiness using the same algorithm as email analyzer.
    
    Args:
        domains: List of domains to evaluate
        
    Returns:
        Dictionary with domain trust assessment
    """
    # Force-trusted domains with minimum security scores (same as in headers_only_ai_analyzer.py)
    TRUSTED_DOMAINS = {
        'gmail.com': 8.0,
        'google.com': 8.0,
        'accounts.google.com': 8.0,
        'mail.google.com': 8.0,
        'drive.google.com': 8.0,
        'docs.google.com': 8.0,
        'apple.com': 8.0,
        'icloud.com': 7.5,
        'outlook.com': 7.0,
        'microsoft.com': 7.5,
        'yahoo.com': 7.0,
        'live.com': 7.0,
        'hotmail.com': 7.0,
        'aol.com': 7.0,
        'proton.me': 8.0,
        'protonmail.com': 8.0
    }
    
    # TLD credibility scores
    TRUSTED_TLDS = {
        'com': 0.5,    # Commercial, widely used
        'org': 0.5,    # Non-profit organizations
        'edu': 1.0,    # Educational institutions (higher trust)
        'gov': 1.0,    # Government agencies (higher trust)
        'net': 0.3,    # Network services
        'co': 0.3,     # Commercial alternative
        'io': 0.3      # Technology companies
    }
    
    result = {
        "trusted_domains": [],
        "untrusted_domains": [],
        "trust_bonus": 0,
        "risk_penalty": 0,
        "details": []
    }
    
    for domain in domains:
        domain_assessment = {
            "domain": domain,
            "is_trusted": False,
            "trust_level": 0,
            "reason": ""
        }
        
        # Check for exact trusted domain match
        if domain in TRUSTED_DOMAINS:
            domain_assessment["is_trusted"] = True
            domain_assessment["trust_level"] = TRUSTED_DOMAINS[domain]
            domain_assessment["reason"] = f"Trusted domain: {domain}"
            result["trusted_domains"].append(domain)
            result["trust_bonus"] += 0.5  # Bonus for trusted domains
            result["details"].append(domain_assessment)
            continue
        
        # Check if subdomain of trusted domain
        domain_parts = domain.split('.')
        trusted_parent = False
        
        if len(domain_parts) > 2:
            potential_parent = '.'.join(domain_parts[-2:])
            if potential_parent in TRUSTED_DOMAINS:
                domain_assessment["is_trusted"] = True
                domain_assessment["trust_level"] = TRUSTED_DOMAINS[potential_parent] - 0.5  # Slightly less trust for subdomains
                domain_assessment["reason"] = f"Subdomain of trusted domain: {potential_parent}"
                result["trusted_domains"].append(domain)
                result["trust_bonus"] += 0.3  # Smaller bonus for subdomains
                result["details"].append(domain_assessment)
                trusted_parent = True
                continue
        
        # Check TLD credibility if not already trusted
        if not trusted_parent:
            tld = domain.split('.')[-1].lower()
            if tld in TRUSTED_TLDS:
                tld_bonus = TRUSTED_TLDS[tld]
                domain_assessment["trust_level"] = tld_bonus
                domain_assessment["reason"] = f"Uses trusted TLD: .{tld}"
                result["trust_bonus"] += tld_bonus / 2  # Half the TLD bonus for domain score
            else:
                domain_assessment["reason"] = "Unknown or uncommon domain"
                result["untrusted_domains"].append(domain)
                result["risk_penalty"] += 0.5  # Penalty for unknown domains
            
            result["details"].append(domain_assessment)
    
    return result

def check_for_sketchy_patterns(text_content: str, trusted_domains: List[str] = None) -> Dict[str, Any]:
    """
    Check for sketchy patterns using the enhanced algorithm.
    
    Args:
        text_content: The text content to analyze
        trusted_domains: List of domains that should be considered trusted
        
    Returns:
        Dictionary with analysis results
    """
    # Define a list of suspicious keywords/phrases (enhanced from the provided algorithm)
    suspicious_keywords = [
        'final notice', 'last chance', 'act immediately', 'immediate attention', 'urgent action',
        'failure to pay', 'suspension', 'impoundment', 'legal actions', 'wage garnishment',
        'limited time', 'act now', 'expires soon', 'quickly', 'asap', 'emergency',
        'important notice', 'warning', 'alert', 'account suspended', 'security alert',
        'verify your account', 'confirm your identity', 'avoid penalties', 'prevent account closure',
        'official notice', 'final warning'
    ]
    
    # Set a reasonable threshold for how many keywords trigger a warning
    keyword_threshold = 2
    
    # Set default trusted domains if none provided
    if not trusted_domains:
        trusted_domains = [
            'gmail.com', 'google.com', 'apple.com', 'icloud.com', 'microsoft.com',
            'outlook.com', 'yahoo.com', 'live.com', 'hotmail.com', 'aol.com',
            'proton.me', 'protonmail.com', '.gov', '.edu'
        ]
    
    # Check for suspicious keywords in the text
    keyword_count = 0
    found_keywords = []
    for keyword in suspicious_keywords:
        if keyword.lower() in text_content.lower():
            keyword_count += 1
            found_keywords.append(keyword)
    
    # Extract URLs from the text using regex
    urls = re.findall(r'(https?://[^\s]+)', text_content)
    url_flag = False
    url_details = []
    safe_urls = []
    suspicious_urls = []
    
    for url in urls:
        # Extract the domain from the URL
        domain_match = re.search(r'https?://(?:www\.)?([^/]+)', url)
        domain = domain_match.group(1) if domain_match else None
        
        if domain:
            # Check if it's a URL shortener (simplified check)
            shortener_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'tiny.cc', 'is.gd']
            is_shortener = any(domain.endswith(sd) for sd in shortener_domains)
            
            # Check if domain is trusted
            is_trusted = any(domain.endswith(td) for td in trusted_domains)
            
            if is_shortener:
                url_flag = True
                suspicious_urls.append(url)
                url_details.append(f"URL shortener detected: {url}")
            elif not is_trusted:
                url_flag = True
                suspicious_urls.append(url)
                url_details.append(f"Potentially suspicious URL: {url}")
            else:
                safe_urls.append(url)
    
    # Check for common scam phrases
    money_phrases = [
        r'\$\d+', 'money', 'cash', 'prize', 'won', 'winner', 'lottery', 'inheritance',
        'payment', 'deposit', 'transaction', 'account', 'bank', 'credit card',
        'gift card', 'reward'
    ]
    
    money_matches = []
    for phrase in money_phrases:
        if re.search(r'\b' + phrase + r'\b', text_content, re.IGNORECASE):
            money_matches.append(phrase)
    
    # Prepare the result dictionary
    result = {
        "suspicious_patterns": [],
        "score_adjustment": 0,
        "explanation": ""
    }
    
    # Combine the findings and adjust the security score
    if keyword_count >= keyword_threshold:
        result["suspicious_patterns"].append(f"Suspicious urgency language detected: {', '.join(found_keywords[:3])}")
        result["score_adjustment"] -= keyword_count
        result["explanation"] += "Message contains urgent or threatening language. "
    
    if url_flag:
        for detail in url_details:
            result["suspicious_patterns"].append(detail)
        result["score_adjustment"] -= len(suspicious_urls) * 1.5
        result["explanation"] += "Message contains potentially suspicious URLs. "
    
    if len(money_matches) >= 2:
        result["suspicious_patterns"].append(f"Potential financial scam indicators: {', '.join(money_matches[:3])}")
        result["score_adjustment"] -= 2
        result["explanation"] += "Message contains multiple references to money or financial transactions. "
    
    return result

def analyze_text(text_content: str, sender: str = None, use_ai: bool = True) -> Dict[str, Any]:
    """
    Analyze a text message for security concerns.
    
    Args:
        text_content: The content of the text message
        sender: Optional sender information
        use_ai: Whether to use AI analysis or just rule-based
        
    Returns:
        Dictionary with security analysis results
    """
    if use_ai:
        try:
            return analyze_text_with_openai(text_content, sender)
        except Exception as e:
            logger.error(f"Error in AI text analysis: {str(e)}")
            return rule_based_analysis(text_content, sender)
    else:
        return rule_based_analysis(text_content, sender)