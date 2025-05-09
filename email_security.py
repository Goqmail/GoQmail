"""Email security module for validating email senders and content."""
import re
import logging
from typing import Dict, List, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# List of common trusted email domains
# This is just a sample list, could be expanded or loaded from a database/file
DEFAULT_TRUSTED_DOMAINS = [
    # Major email providers
    'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'icloud.com', 'me.com', 'aol.com',
    'protonmail.com', 'pm.me', 'msn.com', 'live.com', 'mail.com', 'zoho.com',
    
    # Educational
    'edu', 'ac.uk', 'edu.au',
    
    # Government
    'gov', 'gov.uk', 'gov.au', 'mil',
    
    # Business
    'microsoft.com', 'apple.com', 'google.com', 'amazon.com', 'facebook.com', 'twitter.com',
    'linkedin.com', 'github.com', 'salesforce.com', 'ibm.com', 'oracle.com',
    
    # Add more trusted domains as needed
]

# Common email patterns indicating phishing or spam
SUSPICIOUS_PATTERNS = [
    # Urgency and pressure tactics
    r'urgent.*action', 
    r'act now',
    r'immediate attention',
    r'account suspension',
    r'limited time',
    r'expir(e|ing|ed)',
    
    # Account and security issues
    r'verify.*account',
    r'confirm.*identity',
    r'suspicious.*activity',
    r'unusual.*login',
    r'password.*reset',
    r'security.*breach',
    
    # Financial hooks
    r'won.*lottery',
    r'million.*dollar',
    r'claim.*prize',
    r'unclaimed.*funds',
    r'inheritance',
    r'investment opportunity',
    
    # Action prompts
    r'click.*here',
    r'log in.*now', 
    r'sign in.*now',
    r'update.*payment',
    r'update.*account',
    r'confirm.*details',
    
    # Request for sensitive information
    r'confirm.*password',
    r'provide.*credentials',
    r'send.*information',
    r'verify.*payment',
    r'verify.*identity',
    
    # Threats
    r'account.*suspended',
    r'account.*terminated',
    r'legal.*action',
    r'failure to respond',
    r'will be closed',
]

def extract_domain_from_email(email_address: str) -> str:
    """Extract the domain from an email address.
    
    Args:
        email_address: The full email address string
        
    Returns:
        The domain portion of the email address
    """
    # Handle cases where email might contain a display name
    # Example: "John Smith <john@example.com>"
    match = re.search(r'<([^<>]+)>', email_address)
    if match:
        email_address = match.group(1)
    
    # Extract domain using regex
    match = re.search(r'@([^@]+)$', email_address)
    
    if match:
        return match.group(1).lower()
    
    return ""

def is_trusted_domain(domain: str, trusted_domains: List[str] = None) -> bool:
    """Check if a domain is in the list of trusted domains.
    
    Args:
        domain: The domain to check
        trusted_domains: Optional list of trusted domains (uses default if None)
        
    Returns:
        True if the domain is trusted, False otherwise
    """
    if trusted_domains is None:
        trusted_domains = DEFAULT_TRUSTED_DOMAINS
    
    # Check for exact domain match
    if domain.lower() in [d.lower() for d in trusted_domains]:
        return True
    
    # Check for TLD match (e.g., if 'edu' is trusted, then 'university.edu' is trusted)
    domain_parts = domain.lower().split('.')
    if len(domain_parts) >= 2:
        tld = domain_parts[-1]  # Last part (com, org, etc)
        if len(domain_parts) >= 3:
            # Check for country-specific domains (e.g., .co.uk)
            extended_tld = f"{domain_parts[-2]}.{tld}"
            if extended_tld in trusted_domains:
                return True
        
        # Academic or government domains often use the pattern subdomain.edu or subdomain.gov
        if tld in trusted_domains:
            return True
    
    return False

def check_for_suspicious_patterns(subject: str, body: str) -> List[str]:
    """Check email content for suspicious patterns.
    
    Args:
        subject: The email subject
        body: The email body
        
    Returns:
        List of suspicious patterns found
    """
    found_patterns = []
    combined_text = (subject + " " + body).lower()
    
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, combined_text, re.IGNORECASE):
            found_patterns.append(pattern)
    
    return found_patterns

def analyze_email_security(email: Dict) -> Dict:
    """Analyze an email for security concerns.
    
    Args:
        email: Dictionary containing email data
        
    Returns:
        Dictionary with security analysis results
    """
    sender = email.get('from', '') or email.get('sender', '')
    subject = email.get('subject', '')
    body = email.get('body', '')
    
    # Extract domain from sender
    domain = extract_domain_from_email(sender)
    
    # Check if domain is trusted
    trusted = False
    if domain:
        trusted = is_trusted_domain(domain)
    
    # Check for suspicious patterns
    suspicious_patterns = check_for_suspicious_patterns(subject, body)
    
    # Determine overall risk level
    if not domain:
        risk_level = "Cautious"
        security_score = 5
    elif trusted and not suspicious_patterns:
        risk_level = "Secure"
        security_score = 9
    elif trusted and suspicious_patterns:
        risk_level = "Cautious"
        security_score = 6
    elif not trusted and not suspicious_patterns:
        risk_level = "Cautious"
        security_score = 4
    else:
        risk_level = "Unsafe"
        security_score = 2
    
    # Format recommendations based on analysis
    recommendations = []
    if not trusted:
        recommendations.append("Verify the sender's identity through another channel before responding.")
    if suspicious_patterns:
        recommendations.append("Be cautious with links and attachments in this email.")
        
    # Return in a format the template expects
    return {
        'domain': domain,
        'is_trusted_domain': trusted,
        'suspicious_patterns': suspicious_patterns,
        'risk_level': risk_level,
        'security_score': security_score,
        'recommendations': recommendations
    }

def batch_analyze_emails(emails: List[Dict]) -> List[Dict]:
    """Analyze a batch of emails for security concerns.
    
    Args:
        emails: List of email dictionaries
        
    Returns:
        List of emails with security analysis added
    """
    for email in emails:
        security_analysis = analyze_email_security(email)
        email['security_analysis'] = security_analysis
    
    return emails