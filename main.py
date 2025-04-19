#!/usr/bin/env python3
from flask import render_template, request, session, flash, redirect, url_for, jsonify
import os
import logging
import re
from markupsafe import Markup
from email_fetcher import fetch_emails, auto_detect_provider, get_imap_server
# Import analysis methods
from email_security import batch_analyze_emails as rule_based_analyze_emails
# Import the new hybrid AI analyzer that combines OpenAI with rule-based fallback (full content analysis)
from hybrid_ai_analyzer import batch_analyze_emails as full_ai_analyze_emails
# Import the headers-only AI analyzer for privacy-focused analysis
from headers_only_ai_analyzer import batch_analyze_emails as headers_only_ai_analyze_emails
# Import the Ollama-based analyzer using local Llama models
from ollama_ai_analyzer import batch_analyze_emails as ollama_analyze_emails
# Import text message analyzer (keep for backward compatibility)
import text_analyzer_direct as text_analyzer
from flask_login import login_required, logout_user, current_user, login_user

# Import the database and app setup from the new module
from db_setup import app, db, login_manager, logger

# Import models and create tables
from models import EmailSession, Email, User, TextMessage

# Import email rendering module
import email_renderer

# Add custom Jinja2 filters
@app.template_filter('nl2br')
def nl2br_filter(text):
    """Convert newlines to HTML line breaks."""
    if not text:
        return ""
    text = str(text)
    return Markup(text.replace('\n', '<br>\n'))

@app.template_filter('render_email')
def render_email_filter(email, sender=None, subject=None):
    """Render email content as rich HTML when possible."""
    if not email:
        return ""
    
    # Always try to render any email as HTML
    rendered_content, is_html = email_renderer.get_rendered_email(email, sender, subject)
    if is_html:
        return Markup(rendered_content)
    
    # Return original content if we couldn't render it
    return email
        
@app.route('/email_content/<int:email_id>')
def email_content(email_id):
    """Serve email content in a format suitable for iframe display."""
    # Get the email session from database
    email_session_id = session.get('email_session_id')
    if not email_session_id:
        return "No email session found", 404
    
    # Find the email in the database
    from models import Email
    email = Email.query.filter_by(session_id=email_session_id, id=email_id).first()
    if not email:
        return "Email not found", 404
        
    # Process email content with renderer to sanitize and prepare it
    from email_renderer import clean_html_content, format_plain_text_to_html
    
    if email.is_html:
        # For HTML emails, clean and sanitize the content
        email_content = clean_html_content(email.body)
    else:
        # For plain text emails, format to HTML
        email_content = format_plain_text_to_html(email.body)
    
    # Render the email content using our dedicated template
    return render_template('email_content.html', 
                          email_content=email_content,
                          is_html=email.is_html)

with app.app_context():
    db.create_all()

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

# Set up Google Auth
from google_auth import google_auth
app.register_blueprint(google_auth)

# Helper function for text analysis
def format_text_for_analysis(text_content, sender=None):
    """
    Format text message as email-like object for consistent analysis.
    
    Args:
        text_content: The text message content
        sender: Optional sender information
        
    Returns:
        Dictionary in email format for analysis
    """
    # Don't add potentially suspicious domain for empty sender
    formatted_sender = sender if sender else ""
    
    return {
        'subject': 'Text Message Analysis',
        'from': formatted_sender,
        'date': '',
        'body': text_content,
        'headers': {
            'From': formatted_sender,
            'Subject': 'Text Message Analysis'
        }
    }

@app.route('/', methods=['GET'])
def index():
    """Home page with email fetcher form."""
    return render_template('index.html')

@app.route('/fetch', methods=['POST'])
def fetch():
    """Process the form and fetch emails."""
    email_address = request.form.get('email')
    password = request.form.get('password')
    imap_server = request.form.get('imap_server')
    provider = request.form.get('provider')
    max_emails = int(request.form.get('max_emails', 50))
    folder = request.form.get('folder', 'INBOX')

    # Validate inputs
    if not email_address or not password:
        flash('Email and password are required.', 'danger')
        return redirect(url_for('index'))

    # If IMAP server not provided, try to get it from the provider or auto-detect
    if not imap_server:
        if provider and provider != 'auto':
            imap_server = get_imap_server(provider)
        else:
            imap_server = auto_detect_provider(email_address)

        if not imap_server:
            flash('Could not determine IMAP server. Please specify it manually.', 'danger')
            return redirect(url_for('index'))

    # Fetch emails
    try:
        emails_data = fetch_emails(
            email_address=email_address,
            password=password,
            imap_server=imap_server,
            max_emails=max_emails,
            folder=folder
        )

        # Check for errors
        if emails_data and 'error' in emails_data[0]:
            flash(f"Error fetching emails: {emails_data[0]['message']}", 'danger')
            return redirect(url_for('index'))

        # Create a new email session in the database
        email_session = EmailSession(
            email_address=email_address,
            provider=provider or 'auto-detected'
        )
        db.session.add(email_session)
        db.session.flush()  # Generate ID for session

        # Store each email in the database
        for email_data in emails_data:
            email = Email(
                session_id=email_session.id,
                subject=email_data.get('subject', ''),
                sender=email_data.get('from', ''),
                date=email_data.get('date', ''),
                body=email_data.get('body', ''),
                is_html=email_data.get('is_html', False),  # Save the HTML flag
                error='error' in email_data,
                error_message=email_data.get('message', '') if 'error' in email_data else None
            )
            db.session.add(email)

        # Commit all changes to database
        db.session.commit()

        # Store only the session ID in the session cookie
        session['email_session_id'] = email_session.id
        # Set default to use AI but with headers-only (toggle OFF)
        session['use_ai'] = 'true'
        session['full_content'] = 'false'

        return redirect(url_for('results'))

    except Exception as e:
        logger.error(f"Error in fetch_emails: {str(e)}")
        flash(f"An error occurred: {str(e)}", 'danger')
        return redirect(url_for('index'))

@app.route('/my_emails', methods=['GET'])
def my_emails():
    """Display the user's emails with a dark Gmail-style interface."""
    # Redirect to our dark Gmail view
    return redirect(url_for('dark_gmail'))
    # Get session ID from the session
    session_id = session.get('email_session_id')

    # Debug log the session contents
    logger.info(f"Session data: {str(session)}")
    logger.info(f"Found email_session_id: {session_id}")

    # Check if we're being redirected with the 'ai' and 'full_content' flags
    # If not provided in URL, check session for previous preference
    use_ai = request.args.get('ai', session.get('use_ai', 'false')).lower() == 'true'
    full_content = request.args.get('full_content', session.get('full_content', 'false')).lower() == 'true'

    # Save these preferences to session for future page loads
    session['use_ai'] = str(use_ai).lower()
    session['full_content'] = str(full_content).lower()

    if not session_id:
        # If OAuth credentials exist, try to fetch emails
        if 'credentials' in session:
            logger.info("No email_session_id found but user is logged in with Google. Redirecting to fetch_google_emails.")
            return redirect(url_for('fetch_google_emails'))

        flash('No email results found. Please fetch emails first.', 'warning')
        return redirect(url_for('index'))

    # Retrieve the session and its emails from the database
    email_session = EmailSession.query.get(session_id)

    if not email_session:
        flash('Email results not found. Please fetch emails again.', 'warning')
        session.pop('email_session_id', None)
        return redirect(url_for('index'))

    # Get email data from database
    email_list = [email.to_dict() for email in email_session.emails]

    # Log how many emails we're getting from the database
    logger.info(f"Found {len(email_list)} emails in the database for session {session_id}")

    # Import all analyzer modules at the beginning to avoid issues with fallback
    from email_security import batch_analyze_emails as rule_based_analyze_emails, extract_domain_from_email
    from headers_only_ai_analyzer import batch_analyze_emails as headers_only_ai_analyze_emails
    from hybrid_ai_analyzer import batch_analyze_emails as full_ai_analyze_emails

    # Perform security analysis based on user settings
    try:
        if use_ai:
            if full_content:
                # Full content AI analysis - sends the entire email to AI
                logger.info("Using full-content AI-based email analysis")
                analyzed_emails = full_ai_analyze_emails(email_list)
            else:
                # Headers-only AI analysis for enhanced privacy
                logger.info("Using headers-only AI-based email analysis")
                analyzed_emails = headers_only_ai_analyze_emails(email_list)
        else:
            # Traditional rule-based analysis - no AI
            logger.info("Using rule-based email analysis")
            analyzed_emails = rule_based_analyze_emails(email_list)
    except Exception as e:
        logger.error(f"Error in email analysis: {str(e)}")
        # Fallback to rule-based analysis if AI analysis fails
        try:
            logger.info("Falling back to rule-based analysis")
            analyzed_emails = rule_based_analyze_emails(email_list)
            flash("AI analysis failed. Showing results from rule-based analysis instead.", "warning")
        except Exception as e2:
            logger.error(f"Error in fallback analysis: {str(e2)}")
            analyzed_emails = email_list  # Just show raw emails if all analysis fails
            flash("Email analysis failed. Showing raw emails without security analysis.", "danger")

    # Make sure each email has a security_analysis field for the template
    for email in analyzed_emails:
        # Log the current state of each email
        logger.debug(f"Email before security check: {email}")

        # If no security_analysis added by analyzers, create an empty one
        if 'security_analysis' not in email:
            logger.info(f"Adding missing security_analysis to email id: {email.get('id')}")
            email['security_analysis'] = {
                'risk_level': 'Cautious',
                'security_score': 5,
                'suspicious_patterns': [],
                'recommendations': [],
                'is_trusted_domain': False,
                'domain': email.get('domain', extract_domain_from_email(email.get('sender', '')))
            }
        # Log the email after adding security analysis
        logger.debug(f"Email after security check: {email}")

    # Format the results to match the template expectations
    results = {
        'email_address': email_session.email_address,
        'imap_server': 'Stored in database',
        'folder': 'INBOX',
        'count': len(email_session.emails),
        'emails': analyzed_emails,
        'using_ai': use_ai,
        'full_content': full_content
    }

    # Debug log first email structure if available
    if analyzed_emails and len(analyzed_emails) > 0:
        logger.debug(f"First email structure: {analyzed_emails[0]}")

    return render_template('my_emails.html', results=results)

@app.route('/results', methods=['GET'])
def results():
    """Redirect to my_emails page for backward compatibility."""
    return redirect(url_for('my_emails'))

@app.route('/modern', methods=['GET'])
def modern_inbox():
    """Display the user's emails with a modern, Gmail-like interface."""
    # Redirect to our dark Gmail view
    return redirect(url_for('dark_gmail'))
    # Get session ID from the session
    session_id = session.get('email_session_id')
    
    # Debug log the session contents
    logger.info(f"Session data: {str(session)}")
    logger.info(f"Found email_session_id: {session_id}")
    
    # Check if we're being redirected with the 'ai' and 'full_content' flags
    # If not provided in URL, check session for previous preference
    use_ai = request.args.get('ai', session.get('use_ai', 'false')).lower() == 'true'
    full_content = request.args.get('full_content', session.get('full_content', 'false')).lower() == 'true'
    
    # Save these preferences to session for future page loads
    session['use_ai'] = str(use_ai).lower()
    session['full_content'] = str(full_content).lower()
    
    if not session_id:
        # If OAuth credentials exist, try to fetch emails
        if 'credentials' in session:
            logger.info("No email_session_id found but user is logged in with Google. Redirecting to fetch_google_emails.")
            return redirect(url_for('fetch_google_emails'))
        
        flash('No email results found. Please fetch emails first.', 'warning')
        return redirect(url_for('index'))
    
    # Retrieve the session and its emails from the database
    email_session = EmailSession.query.get(session_id)
    
    if not email_session:
        flash('Email results not found. Please fetch emails again.', 'warning')
        session.pop('email_session_id', None)
        return redirect(url_for('index'))
    
    # Get email data from database
    email_list = [email.to_dict() for email in email_session.emails]
    
    # Log how many emails we're getting from the database
    logger.info(f"Found {len(email_list)} emails in the database for session {session_id}")
    
    # Import all analyzer modules at the beginning to avoid issues with fallback
    from email_security import batch_analyze_emails as rule_based_analyze_emails, extract_domain_from_email
    from headers_only_ai_analyzer import batch_analyze_emails as headers_only_ai_analyze_emails
    from hybrid_ai_analyzer import batch_analyze_emails as full_ai_analyze_emails
    
    # Perform security analysis based on user settings
    try:
        if use_ai:
            if full_content:
                # Full content AI analysis - sends the entire email to AI
                logger.info("Using full-content AI-based email analysis")
                analyzed_emails = full_ai_analyze_emails(email_list)
            else:
                # Headers-only AI analysis for enhanced privacy
                logger.info("Using headers-only AI-based email analysis")
                analyzed_emails = headers_only_ai_analyze_emails(email_list)
        else:
            # Traditional rule-based analysis - no AI
            logger.info("Using rule-based email analysis")
            analyzed_emails = rule_based_analyze_emails(email_list)
    except Exception as e:
        logger.error(f"Error in email analysis: {str(e)}")
        # Fallback to rule-based analysis if AI analysis fails
        try:
            logger.info("Falling back to rule-based analysis")
            analyzed_emails = rule_based_analyze_emails(email_list)
            flash("AI analysis failed. Showing results from rule-based analysis instead.", "warning")
        except Exception as e2:
            logger.error(f"Error in fallback analysis: {str(e2)}")
            analyzed_emails = email_list  # Just show raw emails if all analysis fails
            flash("Email analysis failed. Showing raw emails without security analysis.", "danger")
    
    # Make sure each email has a security_analysis field for the template
    for email in analyzed_emails:
        # Log the current state of each email
        logger.debug(f"Email before security check: {email}")
        
        # If no security_analysis added by analyzers, create an empty one
        if 'security_analysis' not in email:
            logger.info(f"Adding missing security_analysis to email id: {email.get('id')}")
            email['security_analysis'] = {
                'risk_level': 'Cautious',
                'security_score': 5,
                'suspicious_patterns': [],
                'recommendations': [],
                'is_trusted_domain': False,
                'domain': email.get('domain', extract_domain_from_email(email.get('sender', '')))
            }
        # Log the email after adding security analysis
        logger.debug(f"Email after security check: {email}")
    
    # Format the results to match the template expectations
    results = {
        'email_address': email_session.email_address,
        'imap_server': 'Stored in database',
        'folder': 'INBOX',
        'count': len(email_session.emails),
        'emails': analyzed_emails,
        'using_ai': use_ai,
        'full_content': full_content
    }
    
    # Debug log first email structure if available
    if analyzed_emails and len(analyzed_emails) > 0:
        logger.debug(f"First email structure: {analyzed_emails[0]}")
    
    # Use the standalone Gmail-style template with no layout
    return render_template('gmail_view.html', results=results)

@app.route('/gmail_view', methods=['GET'])
def gmail_view():
    """Display the user's emails with a Gmail-style interface."""
    # Redirect to our dark Gmail view
    return redirect(url_for('dark_gmail'))
    # Get session ID from the session
    session_id = session.get('email_session_id')
    
    # Debug log the session contents
    logger.info(f"Session data: {str(session)}")
    logger.info(f"Found email_session_id: {session_id}")
    
    # Check if we're being redirected with the 'ai' and 'full_content' flags
    # If not provided in URL, check session for previous preference
    use_ai = request.args.get('ai', session.get('use_ai', 'false')).lower() == 'true'
    full_content = request.args.get('full_content', session.get('full_content', 'false')).lower() == 'true'
    
    # Save these preferences to session for future page loads
    session['use_ai'] = str(use_ai).lower()
    session['full_content'] = str(full_content).lower()
    
    if not session_id:
        # If OAuth credentials exist, try to fetch emails
        if 'credentials' in session:
            logger.info("No email_session_id found but user is logged in with Google. Redirecting to fetch_google_emails.")
            return redirect(url_for('fetch_google_emails'))
        
        flash('No email results found. Please fetch emails first.', 'warning')
        return redirect(url_for('index'))
    
    # Retrieve the session and its emails from the database
    email_session = EmailSession.query.get(session_id)
    
    if not email_session:
        flash('Email results not found. Please fetch emails again.', 'warning')
        session.pop('email_session_id', None)
        return redirect(url_for('index'))
    
    # Get email data from database
    email_list = [email.to_dict() for email in email_session.emails]
    
    # Log how many emails we're getting from the database
    logger.info(f"Found {len(email_list)} emails in the database for session {session_id}")
    
    # Import all analyzer modules at the beginning to avoid issues with fallback
    from email_security import batch_analyze_emails as rule_based_analyze_emails, extract_domain_from_email
    from headers_only_ai_analyzer import batch_analyze_emails as headers_only_ai_analyze_emails
    from hybrid_ai_analyzer import batch_analyze_emails as full_ai_analyze_emails
    
    # Perform security analysis based on user settings
    try:
        if use_ai:
            if full_content:
                # Full content AI analysis - sends the entire email to AI
                logger.info("Using full-content AI-based email analysis")
                analyzed_emails = full_ai_analyze_emails(email_list)
            else:
                # Headers-only AI analysis for enhanced privacy
                logger.info("Using headers-only AI-based email analysis")
                analyzed_emails = headers_only_ai_analyze_emails(email_list)
        else:
            # Traditional rule-based analysis - no AI
            logger.info("Using rule-based email analysis")
            analyzed_emails = rule_based_analyze_emails(email_list)
    except Exception as e:
        logger.error(f"Error in email analysis: {str(e)}")
        # Fallback to rule-based analysis if AI analysis fails
        try:
            logger.info("Falling back to rule-based analysis")
            analyzed_emails = rule_based_analyze_emails(email_list)
            flash("AI analysis failed. Showing results from rule-based analysis instead.", "warning")
        except Exception as e2:
            logger.error(f"Error in fallback analysis: {str(e2)}")
            analyzed_emails = email_list  # Just show raw emails if all analysis fails
            flash("Email analysis failed. Showing raw emails without security analysis.", "danger")
    
    # Make sure each email has a security_analysis field for the template
    for email in analyzed_emails:
        # Log the current state of each email
        logger.debug(f"Email before security check: {email}")
        
        # If no security_analysis added by analyzers, create an empty one
        if 'security_analysis' not in email:
            logger.info(f"Adding missing security_analysis to email id: {email.get('id')}")
            email['security_analysis'] = {
                'risk_level': 'Cautious',
                'security_score': 5,
                'suspicious_patterns': [],
                'recommendations': [],
                'is_trusted_domain': False,
                'domain': email.get('domain', extract_domain_from_email(email.get('sender', '')))
            }
        # Log the email after adding security analysis
        logger.debug(f"Email after security check: {email}")
    
    # Format the results to match the template expectations
    results = {
        'email_address': email_session.email_address,
        'imap_server': 'Stored in database',
        'folder': 'INBOX',
        'count': len(email_session.emails),
        'emails': analyzed_emails,
        'using_ai': use_ai,
        'full_content': full_content
    }
    
    # Debug log first email structure if available
    if analyzed_emails and len(analyzed_emails) > 0:
        logger.debug(f"First email structure: {analyzed_emails[0]}")
    
    # Use the standalone Gmail-style template with no layout
    return render_template('gmail_view.html', results=results)

@app.route('/toggle_ai', methods=['GET'])
def toggle_ai():
    """Toggle between headers-only and full content AI analysis."""
    # Redirect to dark Gmail view
    return redirect(url_for('dark_gmail'))
    session_id = session.get('email_session_id')

    if not session_id:
        flash('No emails to analyze. Please fetch emails first.', 'warning')
        return redirect(url_for('index'))

    # Get current state from query params or from session
    current_full_content = request.args.get('full_content', 
                                          session.get('full_content', 'false')) == 'true'

    # Toggle the state
    new_full_content = not current_full_content

    # Remember the setting in session
    session['full_content'] = str(new_full_content).lower()

    # Redirect to my_emails with new toggle state
    # We always use AI when toggling (ai=true)
    return redirect(url_for('my_emails', ai='true', full_content=str(new_full_content).lower()))

@app.route('/analyze_with_ai', methods=['GET'])
def analyze_with_ai():
    """Run headers-only AI analysis on already fetched emails."""
    # Redirect to dark Gmail view
    return redirect(url_for('dark_gmail'))
    session_id = session.get('email_session_id')

    if not session_id:
        flash('No emails to analyze. Please fetch emails first.', 'warning')
        return redirect(url_for('index'))

    # Update the session to remember this setting
    session['full_content'] = 'false'

    return redirect(url_for('my_emails', ai='true', full_content='false'))

@app.route('/analyze_with_full_ai', methods=['GET'])
def analyze_with_full_ai():
    """Run full-content AI analysis on already fetched emails."""
    # Redirect to dark Gmail view
    return redirect(url_for('dark_gmail'))
    session_id = session.get('email_session_id')

    if not session_id:
        flash('No emails to analyze. Please fetch emails first.', 'warning')
        return redirect(url_for('index'))

    # Update the session to remember this setting
    session['full_content'] = 'true'

    return redirect(url_for('my_emails', ai='true', full_content='true'))

@app.route('/fetch_google_emails', methods=['GET'])
@login_required
def fetch_google_emails():
    """Fetch emails directly from Gmail using OAuth."""
    from google_auth import fetch_gmail_messages

    if 'credentials' not in session:
        flash('Not authenticated with Google. Please log in.', 'warning')
        return redirect(url_for('index'))

    # Set max emails
    max_emails = request.args.get('max_emails', default=50, type=int)

    try:
        # Fetch emails using Gmail API
        emails_data, error = fetch_gmail_messages(max_results=max_emails)

        if error:
            # Specific handling for the Gmail API not enabled error
            if "Gmail API has not been used in project" in error or "accessNotConfigured" in error:
                flash("The Gmail API needs to be enabled in your Google Cloud Console project. "
                      "Please visit your Google Cloud Console, go to 'APIs & Services' > 'Library', "
                      "search for 'Gmail API', and click 'Enable'.", 'warning')

                # Return a special template with instructions on how to enable Gmail API
                return render_template('gmail_setup.html', 
                                      user_email=session.get('user_email'),
                                      error_details=error)
            else:
                # Handle other errors
                flash(f"Error fetching emails: {error}", 'danger')
                return redirect(url_for('index'))

        if not emails_data:
            flash("No emails found", 'warning')
            return redirect(url_for('index'))

        # Create a new email session in the database
        email_session = EmailSession(
            email_address=session.get('user_email', 'Unknown Gmail user'),
            provider='gmail-oauth'
        )
        db.session.add(email_session)
        db.session.flush()  # Generate ID for session

        # Store each email in the database
        for email_data in emails_data:
            email = Email(
                session_id=email_session.id,
                subject=email_data.get('subject', ''),
                sender=email_data.get('from', ''),
                date=email_data.get('date', ''),
                body=email_data.get('body', ''),
                is_html=email_data.get('is_html', False),  # Add HTML flag
                error=False
            )
            db.session.add(email)

        # Commit all changes to database
        db.session.commit()

        # Store only the session ID in the session cookie
        session['email_session_id'] = email_session.id

        return redirect(url_for('my_emails'))

    except Exception as e:
        logger.error(f"Error in fetch_google_emails: {str(e)}")
        flash(f"An error occurred: {str(e)}", 'danger')
        return redirect(url_for('index'))

@app.route('/clear', methods=['GET'])
def clear():
    """Clear the session data and optionally delete the data from database."""
    session_id = session.get('email_session_id')

    if session_id:
        # Option to delete from database too
        try:
            email_session = EmailSession.query.get(session_id)
            if email_session:
                db.session.delete(email_session)
                db.session.commit()
        except Exception as e:
            logger.error(f"Error deleting email session: {str(e)}")

    # Clear session data but keep Google auth if present
    session.pop('email_session_id', None)

    flash('Results cleared.', 'info')
    return redirect(url_for('index'))

@app.route('/dark_gmail', methods=['GET'])
def dark_gmail():
    """Display emails in a direct dark-mode Gmail-style interface."""
    session_id = session.get('email_session_id')
    logger.info(f"Dark Gmail: Session data: {str(session)}")
    logger.info(f"Dark Gmail: Found email_session_id: {session_id}")
    
    # Get analysis method from request or session
    analysis_method = request.args.get('analysis', session.get('analysis_method', 'rule-based'))
    
    # Store analysis method in session for future page loads
    session['analysis_method'] = analysis_method
    
    # Determine which analysis flag to use
    use_ai = analysis_method != 'rule-based'
    full_content = analysis_method == 'openai-full'
    use_ollama = analysis_method == 'ollama'
    
    if not session_id:
        if 'credentials' in session:
            logger.info("No email_session_id found but user is logged in with Google. Redirecting to fetch_google_emails.")
            return redirect(url_for('fetch_google_emails'))
        
        flash('No email results found. Please fetch emails first.', 'warning')
        return redirect(url_for('index'))
    
    # Retrieve the session and its emails from the database
    email_session = EmailSession.query.get(session_id)
    
    if not email_session:
        flash('Email results not found. Please fetch emails again.', 'warning')
        session.pop('email_session_id', None)
        return redirect(url_for('index'))
    
    # Get email data from database
    email_list = [email.to_dict() for email in email_session.emails]
    logger.info(f"Found {len(email_list)} emails in the database for session {session_id}")
    
    # Import all analyzer modules
    from email_security import batch_analyze_emails as rule_based_analyze_emails, extract_domain_from_email
    from headers_only_ai_analyzer import batch_analyze_emails as headers_only_ai_analyze_emails
    from hybrid_ai_analyzer import batch_analyze_emails as full_ai_analyze_emails
    from ollama_ai_analyzer import batch_analyze_emails as ollama_analyze_emails
    
    # Perform security analysis based on user settings
    try:
        if use_ollama:
            # Use Ollama for local Llama model analysis
            logger.info("Using Ollama-based email analysis with local Llama model")
            analyzed_emails = ollama_analyze_emails(email_list)
        elif use_ai:
            if full_content:
                # Full content AI analysis - sends the entire email to OpenAI
                logger.info("Using full-content OpenAI-based email analysis")
                analyzed_emails = full_ai_analyze_emails(email_list)
            else:
                # Headers-only AI analysis for enhanced privacy
                logger.info("Using headers-only OpenAI-based email analysis")
                analyzed_emails = headers_only_ai_analyze_emails(email_list)
        else:
            # Traditional rule-based analysis - no AI
            logger.info("Using rule-based email analysis")
            analyzed_emails = rule_based_analyze_emails(email_list)
    except Exception as e:
        logger.error(f"Error in email analysis: {str(e)}")
        # Fallback to rule-based analysis if AI analysis fails
        try:
            logger.info("Falling back to rule-based analysis")
            analyzed_emails = rule_based_analyze_emails(email_list)
            flash("AI analysis failed. Showing results from rule-based analysis instead.", "warning")
        except Exception as e2:
            logger.error(f"Error in fallback analysis: {str(e2)}")
            analyzed_emails = email_list  # Just show raw emails if all analysis fails
            flash("Email analysis failed. Showing raw emails without security analysis.", "danger")
    
    # Make sure each email has a security_analysis field
    for email in analyzed_emails:
        if 'security_analysis' not in email:
            email['security_analysis'] = {
                'risk_level': 'Cautious',
                'security_score': 5,
                'suspicious_patterns': [],
                'recommendations': [],
                'is_trusted_domain': False,
                'domain': email.get('domain', extract_domain_from_email(email.get('sender', '')))
            }
    
    # Format the results for the template
    results = {
        'email_address': email_session.email_address,
        'imap_server': 'Stored in database',
        'folder': 'INBOX',
        'count': len(email_session.emails),
        'emails': analyzed_emails,
        'using_ai': use_ai,
        'full_content': full_content,
        'use_ollama': use_ollama,
        'analysis_method': analysis_method
    }
    
    logger.info("Rendering gmail_direct.html template")
    return render_template('gmail_direct.html', results=results)

@app.route('/check_ollama', methods=['GET'])
def check_ollama():
    """Check if Ollama is available and return status."""
    try:
        from ollama_ai_analyzer import check_ollama_connection
        result = check_ollama_connection()
        
        if result["status"] == "connected":
            flash(f"Successfully connected to Ollama! Model: {result['model']}", "success")
        else:
            flash(f"Failed to connect to Ollama: {result.get('error', 'Unknown error')}", "danger")
        
        return render_template("ollama_status.html", result=result)
    except Exception as e:
        logger.error(f"Error checking Ollama status: {str(e)}")
        flash(f"Error checking Ollama status: {str(e)}", "danger")
        return render_template("ollama_status.html", 
                              result={"status": "error", "error": str(e), "endpoint": "unknown", "model": "unknown"})

@app.route('/logout', methods=['GET'])
def logout():
    """Logout from Google and clear all session data."""
    # Logout from Flask-Login
    logout_user()

    # Clear all session data
    session.clear()

    flash('Logged out successfully.', 'info')
    return redirect(url_for('index'))

# Text Analyzer routes
@app.route('/text_analyzer', methods=['GET'])
def text_analyzer_page():
    """Display the text analyzer page with input form."""
    return render_template('text_analyzer.html')

@app.route('/analyze_text', methods=['POST'])
def analyze_text():
    """Analyze submitted text for security concerns using the email analyzer system."""
    logger.info("analyze_text endpoint called")
    text_content = request.form.get('text_content')
    sender = request.form.get('sender', '')
    analysis_method = request.form.get('analysis_method', 'openai-headers')
    
    # Determine which analysis flags to use based on the method
    use_ai = analysis_method != 'rule-based'
    full_content = analysis_method == 'openai-full'
    use_ollama = analysis_method == 'ollama'
    
    logger.info(f"Text content: {text_content[:50]}... (truncated)")
    logger.info(f"Sender: {sender}")
    logger.info(f"Analysis method: {analysis_method}")

    if not text_content:
        flash('Text content is required.', 'danger')
        return redirect(url_for('text_analyzer_page'))

    try:
        # Save the text message to database
        text_message = TextMessage(
            content=text_content,
            sender=sender,
            user_id=current_user.id if current_user.is_authenticated else None
        )
        db.session.add(text_message)
        db.session.flush()  # Generate ID

        # Use our helper function to format the text message properly
        email_data = format_text_for_analysis(text_content, sender)
        
        # Use the same analyzers as the email system for consistent results
        if use_ai:
            # Try headers-only AI first (may be more reliable)
            try:
                result = headers_only_ai_analyze_emails([email_data])[0]
                analysis = result.get('security_analysis', {})
                analysis_source = 'AI-based headers-only analysis'
            except Exception as e:
                logger.error(f"Headers-only AI analysis failed: {str(e)}")
                # Fall back to full content AI if available 
                try:
                    result = full_ai_analyze_emails([email_data])[0]
                    analysis = result.get('security_analysis', {})
                    analysis_source = 'AI-based full content analysis'
                except Exception as e2:
                    logger.error(f"Full content AI analysis failed: {str(e2)}")
                    # Fall back to rule-based
                    result = rule_based_analyze_emails([email_data])[0]
                    analysis = result.get('security_analysis', {})
                    analysis_source = 'Rule-based analysis'
        else:
            # Use rule-based directly
            result = rule_based_analyze_emails([email_data])[0]
            analysis = result.get('security_analysis', {})
            analysis_source = 'Rule-based analysis'
        
        # Ensure we have all required fields for the template
        if not analysis:
            analysis = {
                'risk_level': 'Cautious',
                'security_score': 5,
                'suspicious_patterns': [],
                'recommendations': ['Be cautious with messages from unknown sources.'],
                'explanation': 'Analysis could not be completed.',
            }
        
        # Add the analysis source
        analysis['analysis_source'] = analysis_source
            
        # Ensure all required keys exist
        for key in ['risk_level', 'security_score', 'suspicious_patterns', 'recommendations', 'explanation']:
            if key not in analysis:
                if key == 'suspicious_patterns' or key == 'recommendations':
                    analysis[key] = []
                elif key == 'security_score':
                    analysis[key] = 5
                elif key == 'risk_level':
                    analysis[key] = 'Cautious'
                else:
                    analysis[key] = 'Information not available'

        # Store analysis results
        text_message.security_score = analysis.get('security_score')
        text_message.risk_level = analysis.get('risk_level')
        text_message.explanation = analysis.get('explanation')

        # Commit to database
        db.session.commit()

        # Store the text message ID in session
        session['text_message_id'] = text_message.id

        # Add analysis to the result
        analysis['id'] = text_message.id
        analysis['content'] = text_content
        analysis['sender'] = sender
        
        logger.info(f"Analysis completed with risk level: {analysis.get('risk_level')}, score: {analysis.get('security_score')}")

        return render_template('text_analysis_result.html', analysis=analysis, use_ai=use_ai)

    except Exception as e:
        logger.error(f"Error in text analysis: {str(e)}")
        flash(f"An error occurred during analysis: {str(e)}", 'danger')
        return redirect(url_for('text_analyzer_page'))

@app.route('/api/analyze_text', methods=['POST'])
def api_analyze_text():
    """API endpoint to analyze text and return JSON results."""
    data = request.get_json()

    if not data or 'text' not in data:
        return jsonify({'error': 'Text content is required'}), 400

    text_content = data.get('text')
    sender = data.get('sender', '')
    use_ai = data.get('use_ai', True)

    try:
        # Use our helper function to format the text message properly
        email_data = format_text_for_analysis(text_content, sender)
        
        # Use the same analyzers as the email system for consistent results
        if use_ai:
            # Try headers-only AI first (may be more reliable)
            try:
                result = headers_only_ai_analyze_emails([email_data])[0]
                analysis = result.get('security_analysis', {})
                analysis_source = 'AI-based headers-only analysis'
            except Exception as e:
                logger.error(f"Headers-only AI analysis failed: {str(e)}")
                # Fall back to full content AI if available 
                try:
                    result = full_ai_analyze_emails([email_data])[0]
                    analysis = result.get('security_analysis', {})
                    analysis_source = 'AI-based full content analysis'
                except Exception as e2:
                    logger.error(f"Full content AI analysis failed: {str(e2)}")
                    # Fall back to rule-based
                    result = rule_based_analyze_emails([email_data])[0]
                    analysis = result.get('security_analysis', {})
                    analysis_source = 'Rule-based analysis'
        else:
            # Use rule-based directly
            result = rule_based_analyze_emails([email_data])[0]
            analysis = result.get('security_analysis', {})
            analysis_source = 'Rule-based analysis'
        
        # Ensure we have all required fields for the response
        if not analysis:
            analysis = {
                'risk_level': 'Cautious',
                'security_score': 5,
                'suspicious_patterns': [],
                'recommendations': ['Be cautious with messages from unknown sources.'],
                'explanation': 'Analysis could not be completed.'
            }
        
        # Add the analysis source
        analysis['analysis_source'] = analysis_source
            
        # Ensure all required keys exist
        for key in ['risk_level', 'security_score', 'suspicious_patterns', 'recommendations', 'explanation']:
            if key not in analysis:
                if key == 'suspicious_patterns' or key == 'recommendations':
                    analysis[key] = []
                elif key == 'security_score':
                    analysis[key] = 5
                elif key == 'risk_level':
                    analysis[key] = 'Cautious'
                else:
                    analysis[key] = 'Information not available'

        # Add the text content to the response
        analysis['content'] = text_content
        analysis['sender'] = sender

        logger.info(f"API analysis completed with risk level: {analysis.get('risk_level')}, score: {analysis.get('security_score')}")
        return jsonify(analysis)

    except Exception as e:
        logger.error(f"Error in API text analysis: {str(e)}")
        return jsonify({
            'error': str(e),
            'risk_level': 'Cautious',
            'security_score': 5,
            'suspicious_patterns': [],
            'recommendations': ['Be cautious with messages from unknown sources.'],
            'explanation': f'Analysis error: {str(e)}',
            'analysis_source': 'Error fallback',
            'content': text_content,
            'sender': sender
        }), 200  # Return 200 with fallback data instead of 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)