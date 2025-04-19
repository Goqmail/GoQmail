// Check authentication state and update UI accordingly
document.addEventListener('DOMContentLoaded', function() {
    // Check for login success message
    const flashMessages = document.querySelectorAll('.alert');
    const successMessages = Array.from(flashMessages).filter(msg => 
        msg.classList.contains('alert-success') && 
        msg.textContent.includes('Successfully logged in')
    );
    
    // If we see a login success message, force update the navbar UI
    if (successMessages.length > 0) {
        // Hide the Sign In button if present
        const signInBtn = document.querySelector('.navbar-nav .btn-get-started');
        if (signInBtn) {
            signInBtn.style.display = 'none';
        }
        
        // If the user area doesn't exist, create it
        const navbarNav = document.querySelector('.navbar-nav');
        if (navbarNav && !document.querySelector('.navbar-nav .nav-link[href*="logout"]')) {
            // Create the My Emails link
            const emailsLink = document.createElement('a');
            emailsLink.href = '/results';
            emailsLink.className = 'nav-link';
            emailsLink.textContent = 'My Emails';
            
            // Create the Logout link
            const logoutLink = document.createElement('a');
            logoutLink.href = '/logout';
            logoutLink.className = 'nav-link';
            logoutLink.innerHTML = '<i class="bi bi-box-arrow-right me-1"></i> Logout';
            
            // Add both to the navbar
            navbarNav.appendChild(emailsLink);
            navbarNav.appendChild(logoutLink);
        }
    }
});
