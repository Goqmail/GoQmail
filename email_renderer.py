"""
Email rendering module for displaying HTML emails with proper sanitization.
This module processes emails for secure display in iframes, similar to Gmail's approach.
It sanitizes HTML, inlines CSS, and provides conversion from plain text to HTML.
"""

import re
import requests
from urllib.parse import urlparse
import logging
from bs4 import BeautifulSoup
import bleach
from premailer import transform

# Set up logger
logger = logging.getLogger(__name__)

# Define allowed HTML tags and attributes for sanitization
# Convert frozenset to list first, then extend
ALLOWED_TAGS = list(bleach.sanitizer.ALLOWED_TAGS) + [
    'img', 'table', 'tr', 'td', 'th', 'thead', 'tbody', 'blockquote', 'div', 'span', 
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'ul', 'ol', 'li', 'font', 'style'
]

ALLOWED_ATTRS = {
    **bleach.sanitizer.ALLOWED_ATTRIBUTES,
    'img': ['src', 'alt', 'width', 'height', 'style'],
    'td': ['colspan', 'rowspan', 'style', 'width', 'height', 'align', 'valign'],
    'th': ['colspan', 'rowspan', 'style', 'width', 'height', 'align', 'valign'],
    'table': ['width', 'height', 'style', 'border', 'cellspacing', 'cellpadding', 'align'],
    'div': ['style', 'align', 'class'],
    'span': ['style', 'class'],
    'font': ['face', 'color', 'size', 'style'],
    'a': ['href', 'target', 'style', 'class'],
    '*': ['style', 'class', 'id', 'title']
}

ALLOWED_STYLES = [
    'color', 'background-color', 'font-family', 'font-size', 'font-weight', 
    'font-style', 'text-align', 'text-decoration', 'margin', 'padding', 
    'border', 'display', 'width', 'height', 'line-height'
]

def extract_webview_url(email_body, sender=None, subject=None):
    """
    Extract web view URL from email body text.
    
    Args:
        email_body: The email body content as text
        sender: The email sender (optional)
        subject: The email subject (optional)
        
    Returns:
        The web view URL if found, None otherwise
    """
    if not email_body:
        return None
    
    # Common phrases that indicate a web view link
    web_view_phrases = [
        "view this email as a web page",
        "view in browser",
        "view email in browser",
        "view as webpage",
        "having trouble viewing this email",
        "trouble viewing",
        "click here for a web version",
        "click here to view online"
    ]
    
    # Special case for Canvas notifications
    is_canvas_notification = False
    if subject and "Canvas Notification" in subject:
        is_canvas_notification = True
    if sender and ("notifications@instructure.com" in sender or "canvas" in sender.lower()):
        is_canvas_notification = True
    
    # If this is a Canvas notification, look for specific Canvas URLs
    if is_canvas_notification:
        # Extract all Canvas URLs from the email body
        canvas_urls = re.findall(r'https?://canvas\.[^\s<>"\']+', email_body)
        if canvas_urls:
            # Look for discussion or announcement links
            for url in canvas_urls:
                if "discussion" in url or "announcement" in url:
                    return url
            # If no specific content URL, return the first canvas URL
            return canvas_urls[0]
    
    # Check if any of the web view phrases exist in the email body
    has_web_view_phrase = False
    for phrase in web_view_phrases:
        if phrase in email_body.lower():
            has_web_view_phrase = True
            break
    
    # If no web view phrase, try to extract any URL
    if not has_web_view_phrase:
        # Look for any URLs in the email body
        urls = re.findall(r'https?://[^\s<>"\']+', email_body)
        if urls:
            # Filter out unsubscribe or account management links
            filtered_urls = [url for url in urls if not any(term in url.lower() for term in ["unsubscribe", "manage", "preference", "opt-out", "profile/communication"])]
            if filtered_urls:
                return filtered_urls[0]
        return None
    
    # Try to extract the URL using regex patterns
    # Look for URLs near the web view phrases
    lines = email_body.split('\n')
    for i, line in enumerate(lines):
        for phrase in web_view_phrases:
            if phrase in line.lower():
                # Check current line and next few lines
                for j in range(max(0, i-1), min(len(lines), i+3)):
                    # Common URL pattern
                    url_match = re.search(r'https?://[^\s<>"\']+', lines[j])
                    if url_match:
                        return url_match.group(0)
    
    # If no URL found near phrases, try any URL in the email
    urls = re.findall(r'https?://[^\s<>"\']+', email_body)
    if urls:
        # Filter out unsubscribe links
        filtered_urls = [url for url in urls if not any(term in url.lower() for term in ["unsubscribe", "manage", "preference", "opt-out", "profile/communication"])]
        if filtered_urls:
            return filtered_urls[0]
    
    return None

def fetch_html_content(url):
    """
    Fetch HTML content from a URL.
    
    Args:
        url: The URL to fetch content from
        
    Returns:
        The HTML content if successful, None otherwise
    """
    try:
        # Make sure we have a valid URL
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            logger.error(f"Invalid URL: {url}")
            return None
        
        # Add a user agent to avoid being blocked
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Request the HTML content
        response = requests.get(url, headers=headers, timeout=5)
        
        # Check if request was successful
        if response.status_code == 200:
            return response.text
        else:
            logger.error(f"Failed to fetch HTML: {response.status_code}")
            return None
    
    except Exception as e:
        logger.error(f"Error fetching HTML content: {str(e)}")
        return None

def clean_html_content(html_content):
    """
    Clean and process HTML content for display in an iframe.
    This function sanitizes HTML to remove dangerous elements and inlines CSS.
    
    Args:
        html_content: The HTML content to process
        
    Returns:
        Cleaned and sanitized HTML content ready for iframe display
    """
    if not html_content:
        return None
    
    try:
        # Parse the HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Find the main content - many emails have content in specific containers
        content = None
        
        # Try to find the email content in common containers
        candidates = [
            soup.find('div', {'id': 'bodyCell'}),  # Common for many email templates
            soup.find('div', {'id': 'emailBody'}),
            soup.find('div', {'class': 'email-content'}),
            soup.find('div', {'class': 'container'}),
            soup.find('table', {'id': 'email'}),
            soup.find('table', {'class': 'body'})
        ]
        
        for candidate in candidates:
            if candidate:
                content = str(candidate)
                break
        
        # If we couldn't find a specific content container, use the entire body
        if not content:
            body = soup.find('body')
            if body:
                content = str(body)
            else:
                content = html_content
                
        # Step 1: Clean with bleach to sanitize HTML
        clean_html = bleach.clean(
            content,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRS,
            strip=True
        )
        
        # Step 2: Inline any CSS rules so they survive in iframe
        inlined_html = transform(clean_html)
        
        # Create a proper HTML wrapper for the iframe
        html_wrapper = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <base target="_blank">
            <style>
                body {{ 
                    margin: 16px; 
                    font-family: 'Arial', sans-serif; 
                    font-size: 14px; 
                    line-height: 1.5;
                    color: #202124;
                }}
                blockquote {{ 
                    margin-left: 10px; 
                    padding-left: 10px; 
                    border-left: 2px solid #ddd; 
                    color: #555; 
                }}
                img {{ max-width: 100%; height: auto; }}
                table {{ max-width: 100%; }}
                a {{ color: #1a73e8; text-decoration: none; }}
                a:hover {{ text-decoration: underline; }}
            </style>
        </head>
        <body>
            {inlined_html}
        </body>
        </html>
        """
        
        return html_wrapper
    
    except Exception as e:
        logger.error(f"Error cleaning HTML content: {str(e)}")
        # Return a basic sanitized version as fallback
        try:
            return bleach.clean(html_content, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS)
        except:
            return html_content

def format_plain_text_to_html(email_body):
    """
    Format plain text email to look better as HTML using bleach for sanitization.
    
    Args:
        email_body: Plain text email body
        
    Returns:
        HTML-formatted version of the email ready for iframe display
    """
    if not email_body:
        return ""
    
    # First, escape the content for safety
    escaped_content = bleach.clean(email_body)
    
    # Create HTML structure
    html_lines = []
    html_lines.append('<div class="formatted-email">')
    
    # Split into paragraphs
    paragraphs = escaped_content.split('\n\n')
    
    for paragraph in paragraphs:
        if not paragraph.strip():
            continue
        
        # Check if this is a line of just dashes or equals signs (section separator)
        if re.match(r'^[-=_]{3,}$', paragraph.strip()):
            html_lines.append('<hr class="email-separator">')
            continue
        
        # Format lines within the paragraph
        formatted_lines = []
        for line in paragraph.split('\n'):
            # Auto-link URLs using bleach's linkify
            linked_line = bleach.linkify(line)
            formatted_lines.append(linked_line)
        
        # Join the formatted lines with line breaks
        paragraph_html = '<br>'.join(formatted_lines)
        html_lines.append(f'<p>{paragraph_html}</p>')
    
    html_lines.append('</div>')
    
    # Wrap in a complete HTML document for the iframe
    formatted_content = '\n'.join(html_lines)
    
    html_wrapper = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <base target="_blank">
        <style>
            body {{ 
                margin: 16px; 
                font-family: 'Arial', sans-serif; 
                font-size: 14px; 
                line-height: 1.5;
                color: #202124;
            }}
            .formatted-email {{
                max-width: 100%;
            }}
            .email-separator {{
                border: none;
                border-top: 1px solid #e0e0e0;
                margin: 12px 0;
            }}
            a {{ color: #1a73e8; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
            p {{ margin: 0 0 10px 0; }}
        </style>
    </head>
    <body>
        {formatted_content}
    </body>
    </html>
    """
    
    return html_wrapper

def get_rendered_email(email_body, sender=None, subject=None):
    """
    Get HTML-rendered version of an email.
    
    Args:
        email_body: The email body text
        sender: The email sender (optional)
        subject: The email subject (optional)
        
    Returns:
        HTML-rendered version of the email if possible, original content otherwise
    """
    # If empty email body, return as is
    if not email_body or not email_body.strip():
        return email_body, False
    
    # Try to extract web view URL
    web_view_url = extract_webview_url(email_body, sender, subject)
    
    # Detect marketing/newsletter emails from common sources
    is_marketing_email = False
    if sender:
        marketing_domains = [
            'wordpress.com', 'mailchimp', 'campaign-', 'newsletter', 
            'marketing', 'info@', 'noreply@', 'promotions', 
            'notification', 'updates@', 'news@'
        ]
        for domain in marketing_domains:
            if domain.lower() in sender.lower():
                is_marketing_email = True
                break
    
    # If this is a marketing email with no web view URL, format it nicely
    if is_marketing_email and not web_view_url:
        logger.info(f"Formatting marketing email from {sender}")
        return format_plain_text_to_html(email_body), True
    
    # Log the URL if found
    if web_view_url:
        logger.info(f"Found web view URL: {web_view_url}")
    else:
        logger.info("No web view URL found")
        
        # For special types of notifications, create custom HTML formatting
        
        # Canvas notifications
        if (sender and "notifications@instructure.com" in sender) or (subject and "Canvas Notification" in subject):
            logger.info("Converting Canvas notification to HTML")
            # Create basic HTML structure for Canvas notifications
            html_lines = []
            html_lines.append('<div class="canvas-notification">')
            
            # Process each line of the email
            for line in email_body.split('\n'):
                # Skip empty lines
                if not line.strip():
                    html_lines.append('<br>')
                    continue
                
                # Check if this is a section separator
                if line.strip() == "--------------------------------":
                    html_lines.append('<hr class="canvas-separator">')
                    continue
                
                # Check if this is a URL
                if line.strip().startswith('http'):
                    html_lines.append(f'<a href="{line.strip()}" target="_blank">{line.strip()}</a>')
                    continue
                
                # Regular text line
                html_lines.append(f'<p>{line}</p>')
            
            html_lines.append('</div>')
            
            # Return the simple HTML version
            return '\n'.join(html_lines), True
        
        # WordPress notifications
        elif sender and ("wordpress.com" in sender.lower()):
            logger.info("Converting WordPress notification to HTML")
            return format_plain_text_to_html(email_body), True
            
        # For any other plain text email, format it for better readability
        else:
            logger.info("Formatting plain text email for better readability")
            return format_plain_text_to_html(email_body), True
    
    # Fetch HTML content from the web view URL if we found one
    html_content = fetch_html_content(web_view_url)
    
    if not html_content:
        logger.warning(f"Failed to fetch HTML content from {web_view_url}")
        # Fall back to formatted plain text
        return format_plain_text_to_html(email_body), True
    
    # Clean and process the HTML content
    cleaned_html = clean_html_content(html_content)
    
    if cleaned_html:
        return cleaned_html, True
    
    # If all else fails, return formatted plain text
    return format_plain_text_to_html(email_body), True