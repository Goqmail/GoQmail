// Animation Effects for Professional UI
document.addEventListener('DOMContentLoaded', function() {
    // Initialize animations on scroll
    initScrollAnimations();
    
    // Initialize word animation in hero section
    initWordAnimation();
    
    // Add parallax effect to spline background
    initParallaxEffect();
    
    // Add hover effects to buttons and cards
    enhanceHoverEffects();
});

// Word animation for "Gmail" in hero title
function initWordAnimation() {
    const animatedWord = document.getElementById('animated-word');
    if (!animatedWord) return;
    
    // Words to cycle through
    const words = ['Gmail', 'Email', 'Outlook', 'Yahoo', 'ProtonMail'];
    let currentIndex = 0;
    
    // Set initial word
    animatedWord.textContent = words[currentIndex];
    
    // Change word every 3 seconds
    setInterval(() => {
        // Fade out
        animatedWord.classList.add('fade-out');
        
        setTimeout(() => {
            // Change word
            currentIndex = (currentIndex + 1) % words.length;
            animatedWord.textContent = words[currentIndex];
            
            // Fade in
            animatedWord.classList.remove('fade-out');
            animatedWord.classList.add('fade-in');
            
            // Reset classes after animation
            setTimeout(() => {
                animatedWord.classList.remove('fade-in');
            }, 500);
        }, 400);
    }, 3000);
}

// Parallax effect for spline background
function initParallaxEffect() {
    const splineContainer = document.querySelector('.spline-background');
    if (!splineContainer) return;
    
    const heroSection = document.querySelector('.hero-section');
    if (!heroSection) return;
    
    // Add parallax effect on mouse move
    heroSection.addEventListener('mousemove', (e) => {
        const xPos = (e.clientX / window.innerWidth - 0.5) * 20;
        const yPos = (e.clientY / window.innerHeight - 0.5) * 20;
        
        // Apply transform to create subtle parallax effect
        splineContainer.style.transform = `translate(${xPos}px, ${yPos}px)`;
    });
    
    // Reset transform when mouse leaves
    heroSection.addEventListener('mouseleave', () => {
        splineContainer.style.transform = 'translate(0, 0)';
        splineContainer.style.transition = 'transform 0.5s ease-out';
    });
    
    heroSection.addEventListener('mouseenter', () => {
        splineContainer.style.transition = 'transform 0.1s ease-out';
    });
}

// Enhance hover effects for buttons and cards
function enhanceHoverEffects() {
    // Enhanced button hover effects
    const buttons = document.querySelectorAll('.btn');
    
    buttons.forEach(btn => {
        btn.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-4px)';
            this.style.boxShadow = '0 10px 20px rgba(0, 0, 0, 0.2)';
        });
        
        btn.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
            this.style.boxShadow = '';
        });
    });
    
    // Enhanced card hover effects
    const cards = document.querySelectorAll('.feature-card');
    
    cards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-8px) scale(1.02)';
            this.style.boxShadow = '0 15px 35px rgba(0, 0, 0, 0.2)';
            this.style.borderColor = 'rgba(255, 255, 255, 0.15)';
            
            // Animate the icon
            const icon = this.querySelector('.icon-container');
            if (icon) {
                icon.style.transform = 'scale(1.1)';
                icon.style.boxShadow = '0 0 20px rgba(103, 44, 211, 0.4)';
            }
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = '';
            this.style.boxShadow = '';
            this.style.borderColor = '';
            
            // Reset icon animation
            const icon = this.querySelector('.icon-container');
            if (icon) {
                icon.style.transform = '';
                icon.style.boxShadow = '';
            }
        });
    });
}

// Initialize scroll-based animations
function initScrollAnimations() {
    const animateOnScroll = (entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate-in');
                observer.unobserve(entry.target);
            }
        });
    };
    
    // Create observer with options
    const scrollObserver = new IntersectionObserver(animateOnScroll, {
        root: null,
        threshold: 0.15,
        rootMargin: '0px 0px -50px 0px'
    });
    
    // Elements to animate
    const elements = document.querySelectorAll('.feature-card, .encryption-step, .quantum-image, .comparison-table, .encryption-step-number');
    
    elements.forEach(el => {
        // Add base animation class
        el.classList.add('animate-on-scroll');
        // Observe element
        scrollObserver.observe(el);
    });
}
