"""
Text Message Analyzer for security concerns.

This module provides functionality to analyze text messages for phishing attempts,
scams, and other security concerns using either the headers-only AI or full AI analysis.
It uses the same analysis engines as the email system for consistent results.
"""

import os
import logging
from typing import Dict, Any, List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import the analysis engines
from headers_only_ai_analyzer import analyze_email_security as analyze_with_headers_only
from hybrid_ai_analyzer import analyze_email_security as analyze_with_full_ai
from email_security import analyze_email_security as analyze_with_rules

def format_text_as_email(text_content: str, sender: Optional[str] = None) -> Dict[str, Any]:
    """
    Format text content as an email-like object for analysis.
    
    Args:
        text_content: The content of the text message
        sender: Optional sender information
        
    Returns:
        Dictionary in the format expected by email analyzers
    """
    # Create an email-like object that the email analyzers can process
    email_data = {
        'subject': 'Text Message Analysis',
        'from': sender or 'unknown@sender.com',
        'date': '',
        'body': text_content,
        'headers': {
            'From': sender or 'unknown@sender.com',
            'Subject': 'Text Message Analysis'
        }
    }
    
    return email_data

def analyze_text(text_content: str, sender: Optional[str] = None, use_ai: bool = True, full_content: bool = False) -> Dict[str, Any]:
    """
    Analyze a text message for security concerns using the same engines as email analysis.
    
    Args:
        text_content: The content of the text message
        sender: Optional sender information
        use_ai: Whether to use AI analysis (true) or rule-based (false)
        full_content: Whether to use full content AI (true) or headers-only AI (false)
        
    Returns:
        Dictionary with security analysis results
    """
    logger.info(f"Analyzing text with use_ai={use_ai}, full_content={full_content}")
    
    try:
        # Format the text as an email-like object
        email_data = format_text_as_email(text_content, sender)
        
        # Use direct rule-based analysis first to ensure we have a baseline result
        # This provides a fallback in case the AI analysis fails
        logger.info("Running rule-based analysis as baseline")
        fallback_result = analyze_with_rules(email_data)
        fallback_security = fallback_result.get('security_analysis', {})
        
        # If not using AI, just return the rule-based result
        if not use_ai:
            logger.info("Using rule-based analysis for text as requested")
            return fallback_security
            
        try:
            # AI-based analysis based on full_content setting
            if full_content:
                # Use full AI analysis (like in hybrid_ai_analyzer.py)
                logger.info("Using full content AI analysis for text")
                result = analyze_with_full_ai(email_data)
            else:
                # Use headers-only AI analysis (like in headers_only_ai_analyzer.py)
                logger.info("Using headers-only AI analysis for text")
                result = analyze_with_headers_only(email_data)
                
            # Extract just the security analysis part
            security_analysis = result.get('security_analysis', {})
            
            # If AI analysis returned empty results, use the fallback
            if not security_analysis:
                logger.warning("AI analysis returned empty results, using rule-based fallback")
                security_analysis = fallback_security
                
            # Make sure the key fields are present
            if 'risk_level' not in security_analysis:
                security_analysis['risk_level'] = fallback_security.get('risk_level', 'Cautious')
            if 'security_score' not in security_analysis:
                security_analysis['security_score'] = fallback_security.get('security_score', 5)
            if 'suspicious_patterns' not in security_analysis:
                security_analysis['suspicious_patterns'] = fallback_security.get('suspicious_patterns', [])
            if 'recommendations' not in security_analysis:
                security_analysis['recommendations'] = fallback_security.get('recommendations', ['Be cautious with messages from unknown sources.'])
            if 'explanation' not in security_analysis:
                security_analysis['explanation'] = fallback_security.get('explanation', 'Analysis results are limited.')
                
            return security_analysis
            
        except Exception as ai_error:
            # If AI analysis fails, log the error and use the rule-based result
            logger.error(f"AI analysis failed: {str(ai_error)}, using rule-based fallback")
            fallback_security['explanation'] = f"AI analysis couldn't be completed. Using rule-based analysis instead."
            return fallback_security
        
    except Exception as e:
        logger.error(f"Error in text analysis: {str(e)}")
        # Return a simple default analysis in case of error
        return {
            'risk_level': 'Cautious',
            'security_score': 5,
            'suspicious_patterns': [],
            'recommendations': ['Be cautious with messages from unknown sources.'],
            'explanation': f'Analysis could not be completed: {str(e)}'
        }