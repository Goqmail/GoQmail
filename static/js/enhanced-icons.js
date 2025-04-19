// Enhanced Icons Script for QMail
document.addEventListener('DOMContentLoaded', function() {
    // Replace standard Bootstrap icons with enhanced versions
    enhanceSecurityIcons();
    
    // Add glossy effect to email avatars
    addGlossyEffectToAvatars();
    
    // Create 3D depth for cards
    add3DeffectToCards();
    
    // Add pulsing effect to AI analysis icons
    addPulsingEffectToAiIcons();
});

// Replace standard Bootstrap icons with enhanced versions
function enhanceSecurityIcons() {
    // Find all security badges
    const securityBadges = document.querySelectorAll('.security-badge');
    
    securityBadges.forEach(badge => {
        // Add appropriate icon based on badge content
        const badgeText = badge.innerText.toLowerCase();
        let iconClass = '';
        
        if (badgeText.includes('secure')) {
            iconClass = 'bi-shield-check';
        } else if (badgeText.includes('cautious')) {
            iconClass = 'bi-shield';
        } else if (badgeText.includes('unsafe') || badgeText.includes('dangerous')) {
            iconClass = 'bi-shield-exclamation';
        } else if (badgeText.includes('warning')) {
            iconClass = 'bi-exclamation-triangle';
        } else if (badgeText.includes('trusted domain')) {
            iconClass = 'bi-patch-check';
        } else if (badgeText.includes('untrusted domain')) {
            iconClass = 'bi-patch-question';
        }
        
        // Only add icon if one was matched
        if (iconClass) {
            const icon = document.createElement('i');
            icon.className = `bi ${iconClass} me-1`;
            badge.prepend(icon);
        }
    });
}

// Add glossy effect to email avatars
function addGlossyEffectToAvatars() {
    // Create style element
    const style = document.createElement('style');
    style.textContent = `
        .email-avatar {
            position: relative;
            overflow: hidden;
        }
        
        .email-avatar::after {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle at center, rgba(255,255,255,0.35) 0%, rgba(255,255,255,0) 60%);
            transform: rotate(30deg);
            pointer-events: none;
        }
    `;
    document.head.appendChild(style);
}

// Create 3D depth for cards
function add3DeffectToCards() {
    // Find all cards that could benefit from 3D effect
    const cards = document.querySelectorAll('.card:not(.email-sidebar):not(.email-main)');
    
    cards.forEach(card => {
        // Add perspective class
        card.classList.add('card-3d-effect');
    });
    
    // Create style for the 3D effect
    const style = document.createElement('style');
    style.textContent = `
        .card-3d-effect {
            transition: transform 0.6s cubic-bezier(0.165, 0.84, 0.44, 1);
            transform-style: preserve-3d;
        }
        
        .card-3d-effect:hover {
            transform: translateY(-5px) rotateX(2deg) rotateY(2deg);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.25) !important;
        }
    `;
    document.head.appendChild(style);
}

// Add pulsing effect to AI analysis icons
function addPulsingEffectToAiIcons() {
    // Create style for AI icons
    const style = document.createElement('style');
    style.textContent = `
        /* Glow effect for AI badges */
        .badge.bg-primary:not(.security-badge), 
        .badge.bg-info:not(.security-badge) {
            position: relative;
            overflow: hidden;
        }
        
        .badge.bg-primary:not(.security-badge)::before, 
        .badge.bg-info:not(.security-badge)::before {
            content: '';
            position: absolute;
            top: -2px;
            left: -2px;
            right: -2px;
            bottom: -2px;
            background: inherit;
            filter: blur(8px);
            opacity: 0;
            z-index: -1;
            animation: pulse-glow 2s ease-in-out infinite;
        }
        
        @keyframes pulse-glow {
            0% {
                opacity: 0.3;
                transform: scale(1);
            }
            50% {
                opacity: 0.6;
                transform: scale(1.2);
            }
            100% {
                opacity: 0.3;
                transform: scale(1);
            }
        }
        
        /* Add AI icon to badges */
        .badge.bg-primary:not(.security-badge)::after, 
        .badge.bg-info:not(.security-badge)::after {
            content: '\\F664';
            font-family: "bootstrap-icons";
            font-size: 0.9em;
            margin-left: 5px;
            vertical-align: -0.1em;
        }
        
        /* AI analysis toggle button enhancement */
        .btn-outline-primary:has(i.bi-toggle-off) {
            position: relative;
            overflow: hidden;
        }
        
        .btn-primary:has(i.bi-toggle-on) {
            position: relative;
            overflow: hidden;
        }
        
        .btn-primary:has(i.bi-toggle-on)::after {
            content: '';
            position: absolute;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.3);
            top: -15px;
            right: -15px;
            animation: pulse-circle 1.5s ease-in-out infinite;
        }
        
        @keyframes pulse-circle {
            0% {
                transform: scale(0.8);
                opacity: 0.5;
            }
            50% {
                transform: scale(1.2);
                opacity: 0.8;
            }
            100% {
                transform: scale(0.8);
                opacity: 0.5;
            }
        }
    `;
    document.head.appendChild(style);
    
    // Wait for the AI badge container to be added by bento-box.js
    setTimeout(() => {
        const aiIconContainers = document.querySelectorAll('.ai-analysis-indicator');
        
        aiIconContainers.forEach(container => {
            // Add pulsing glow effect
            const glow = document.createElement('div');
            glow.className = 'ai-icon-glow';
            container.appendChild(glow);
            
            // Add pulsing CSS
            const iconStyle = document.createElement('style');
            iconStyle.textContent = `
                .ai-icon-glow {
                    position: absolute;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    border-radius: 50%;
                    background: radial-gradient(circle, rgba(79, 70, 229, 0.6) 0%, rgba(79, 70, 229, 0) 70%);
                    z-index: -1;
                    animation: pulsing-glow 2s ease-in-out infinite;
                }
                
                @keyframes pulsing-glow {
                    0% {
                        transform: scale(1);
                        opacity: 0.5;
                    }
                    50% {
                        transform: scale(1.5);
                        opacity: 0.3;
                    }
                    100% {
                        transform: scale(1);
                        opacity: 0.5;
                    }
                }
            `;
            document.head.appendChild(iconStyle);
        });
    }, 1000); // Wait for bento-box.js to execute
}
