#!/usr/bin/env python3
"""
One-time script to update existing emails in the database to set is_html flag properly.
This script analyzes the body content of each email and sets the flag based on detection
of HTML content.
"""

from db_setup import app, db, logger
from models import Email

def is_html_content(body):
    """Determine if the content is HTML based on presence of HTML tags."""
    if not body:
        return False
    
    html_indicators = ['<html', '<body', '<div', '<table', '<p>', '<span', '<a href', '<img', '<br']
    
    for indicator in html_indicators:
        if indicator in body.lower():
            return True
    
    return False

def update_html_flags():
    """Update is_html flags for all emails in the database."""
    with app.app_context():
        # Get all emails
        emails = Email.query.all()
        logger.info(f"Found {len(emails)} emails to process")
        
        html_count = 0
        text_count = 0
        
        # Process each email
        for email in emails:
            # Skip emails with empty bodies
            if not email.body:
                continue
                
            # Check if the email content is HTML
            email.is_html = is_html_content(email.body)
            
            # Count for logging
            if email.is_html:
                html_count += 1
            else:
                text_count += 1
        
        # Commit changes to database
        db.session.commit()
        
        logger.info(f"Update complete: {html_count} HTML emails, {text_count} plain text emails")
        print(f"Update complete: {html_count} HTML emails, {text_count} plain text emails")

if __name__ == "__main__":
    update_html_flags()