"""
Direct Text Message Analyzer for security concerns.

This module provides a simplified and direct approach to analyze text messages
for phishing attempts, scams, and other security concerns using OpenAI directly.
"""

import os
import re
import json
import logging
from typing import Dict, Any, List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import rule-based analysis as fallback
from email_security import analyze_email_security as analyze_with_rules
from email_security import extract_domain_from_email

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

def analyze_text_with_ai(text_content: str, sender: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze text directly with OpenAI.
    
    Args:
        text_content: The text content to analyze
        sender: Optional sender information
        
    Returns:
        Security analysis results
    """
    try:
        # First run rule-based analysis as a fallback
        email_data = format_text_as_email(text_content, sender)
        rule_result = analyze_with_rules(email_data)
        fallback_security = rule_result.get('security_analysis', {})
        
        # Make sure we have a complete fallback result
        if not fallback_security:
            fallback_security = {
                'risk_level': 'Cautious',
                'security_score': 5,
                'suspicious_patterns': [],
                'recommendations': ['Be cautious with messages from unknown sources.'],
                'explanation': 'Basic rule-based analysis completed.',
                'analysis_source': 'Rule-based'
            }
        
        # Check if OpenAI API key is available
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            logger.warning("OPENAI_API_KEY not found in environment variables")
            return fallback_security
        
        # Extract sender domain if provided
        sender_domain = extract_domain_from_email(sender) if sender else "unknown"
        
        # Prepare the message content for analysis        
        # Create prompt for OpenAI with text content
        prompt = f"""
        You are an expert security analyst specializing in detecting scams, phishing, and malicious content in messages.
        
        Analyze the following message for any signs of phishing, scams, or security concerns:
        
        MESSAGE DETAILS:
        - From: {sender or 'Unknown sender'}
        - Content: {text_content}
        
        Analyze this message's security aspects by considering:
        1. Does it contain suspicious URLs or domains?
        2. Does it use urgency, threats, or financial incentives to manipulate the recipient?
        3. Does it request personal information, credentials, or payments?
        4. Does it contain poor grammar or spelling typical of scam messages?
        5. Is it impersonating a known service, organization, or person?
        6. Score the security from 1-10 where 10 is completely secure and 1 is definitely malicious.
        
        Return your analysis in this JSON format:
        {{
            "suspicious_patterns": ["list", "of", "suspicious", "patterns"],
            "security_score": number from 1-10,
            "risk_level": "Secure"/"Cautious"/"Unsafe"/"Dangerous",
            "explanation": "detailed reasoning",
            "recommendations": ["list", "of", "recommendations"]
        }}
        
        Include only the JSON in your response, nothing else.
        """
        
        # Import OpenAI here to avoid startup errors
        try:
            import openai
            
            # Initialize client
            logger.info("Initializing OpenAI client for text analysis")
            client = openai.OpenAI(api_key=api_key)
        except ImportError:
            logger.error("Could not import OpenAI package - package may not be installed")
            return fallback_security
        except Exception as e:
            logger.error(f"Error initializing OpenAI client: {str(e)}")
            return fallback_security
        
        # Call OpenAI API with increased timeout
        logger.info("Calling OpenAI API for text analysis")
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",  # Use a faster model for reliability
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            timeout=30.0
        )
        
        # Get response content
        analysis_text = response.choices[0].message.content
        logger.info(f"Received OpenAI response: {analysis_text[:100]}...")
        
        # Parse JSON from response
        try:
            # Clean the response text to only include JSON
            json_match = re.search(r'\{.*\}', analysis_text, re.DOTALL)
            if json_match:
                cleaned_json = json_match.group(0)
                analysis = json.loads(cleaned_json)
                logger.info("Successfully parsed JSON from OpenAI response")
            else:
                logger.warning("No JSON found in OpenAI response")
                return fallback_security
                
        except Exception as json_error:
            logger.error(f"Error parsing JSON from OpenAI response: {str(json_error)}")
            return fallback_security
            
        # Verify required fields are present
        if not isinstance(analysis.get('suspicious_patterns'), list):
            analysis['suspicious_patterns'] = []
            
        if 'security_score' not in analysis or not isinstance(analysis['security_score'], (int, float)):
            analysis['security_score'] = fallback_security.get('security_score', 5)
            
        if 'risk_level' not in analysis or not isinstance(analysis['risk_level'], str):
            analysis['risk_level'] = fallback_security.get('risk_level', 'Cautious')
            
        if 'explanation' not in analysis or not isinstance(analysis['explanation'], str):
            analysis['explanation'] = fallback_security.get('explanation', 'Analysis could not be completed')
            
        if not isinstance(analysis.get('recommendations'), list):
            analysis['recommendations'] = fallback_security.get('recommendations', ['Be cautious with messages from unknown sources'])
            
        # Add source information
        analysis['analysis_source'] = 'AI-powered analysis'
        
        return analysis
        
    except Exception as e:
        logger.error(f"Error in AI text analysis: {str(e)}")
        # Return a simple default analysis in case of error
        return {
            'risk_level': 'Cautious',
            'security_score': 5,
            'suspicious_patterns': [],
            'recommendations': ['Be cautious with messages from unknown sources.'],
            'explanation': f'Analysis could not be completed: {str(e)}',
            'analysis_source': 'Error fallback'
        }

def analyze_text(text_content: str, sender: Optional[str] = None, use_ai: bool = True) -> Dict[str, Any]:
    """
    Main function to analyze text messages.
    
    Args:
        text_content: The content of the text message
        sender: Optional sender information
        use_ai: Whether to use AI for analysis
        
    Returns:
        Dictionary with security analysis results
    """
    logger.info(f"Analyzing text with use_ai={use_ai}")
    
    try:
        if use_ai:
            # Use direct AI analysis
            return analyze_text_with_ai(text_content, sender)
        else:
            # Use rule-based analysis
            email_data = format_text_as_email(text_content, sender)
            result = analyze_with_rules(email_data)
            return result.get('security_analysis', {})
            
    except Exception as e:
        logger.error(f"Error in text analysis: {str(e)}")
        # Return a simple default analysis in case of error
        return {
            'risk_level': 'Cautious',
            'security_score': 5,
            'suspicious_patterns': [],
            'recommendations': ['Be cautious with messages from unknown sources.'],
            'explanation': f'Analysis error: {str(e)}',
            'analysis_source': 'Error fallback'
        }