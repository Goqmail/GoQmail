// Enhanced List View Styling
document.addEventListener('DOMContentLoaded', function() {
    // Add enhanced styling to email list items
    const emailItems = document.querySelectorAll('.email-item');
    if (emailItems.length === 0) return;
    
    emailItems.forEach(item => {
        // Add enhanced hover effects
        item.classList.add('enhanced-list-item');
        
        // Make the entire item clickable for expansion
        item.addEventListener('click', function(e) {
            // Get the ID of the content to expand
            const contentId = this.getAttribute('data-bs-target');
            const content = document.querySelector(contentId);
            
            // Toggle the content
            if (content) {
                if (content.classList.contains('show')) {
                    content.classList.remove('show');
                } else {
                    // Close any other open items
                    document.querySelectorAll('.email-detail').forEach(detail => {
                        if (detail !== content && detail.classList.contains('show')) {
                            detail.classList.remove('show');
                        }
                    });
                    
                    // Show this content
                    content.classList.add('show');
                    
                    // Scroll to show the content if needed
                    setTimeout(() => {
                        content.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                    }, 300);
                }
            }
        });
    });
    
    // Add custom styles for enhanced list view
    const style = document.createElement('style');
    style.textContent = `
        .email-item.enhanced-list-item {
            transition: all 0.3s ease;
            position: relative;
            border-left: 3px solid transparent;
            padding-left: 8px;
            margin-bottom: 8px;
            border-radius: 8px;
            cursor: pointer;
        }
        
        .email-item.enhanced-list-item:hover {
            background-color: rgba(22, 37, 88, 0.5);
            transform: translateX(5px);
            border-left-color: var(--primary);
            box-shadow: 0 8px 15px rgba(0, 0, 0, 0.15);
        }
        
        .email-item.enhanced-list-item:hover .email-subject {
            color: var(--primary-light);
        }
        
        .email-item.enhanced-list-item:hover .email-avatar {
            transform: scale(1.1) rotate(5deg);
        }
        
        .email-detail {
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            max-height: 0;
            overflow: hidden;
            opacity: 0;
            transform: scaleY(0.8);
            transform-origin: top center;
        }
        
        .email-detail.show {
            max-height: 2000px;
            opacity: 1;
            transform: scaleY(1);
        }
        
        /* Add a indicator for expandable items */
        .email-item.enhanced-list-item::after {
            content: '\\2026'; /* ellipsis */
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 1.5rem;
            color: var(--text-muted);
            opacity: 0.5;
            transition: all 0.3s ease;
        }
        
        .email-item.enhanced-list-item:hover::after {
            content: '\\2193'; /* down arrow */
            color: var(--primary-light);
            opacity: 1;
        }
    `;
    document.head.appendChild(style);
});
