// Scroll-based animations for hero section
document.addEventListener('DOMContentLoaded', function() {
    const heroSection = document.querySelector('.hero-section');
    const heroContent = document.querySelector('.hero-content');
    
    if (!heroSection) return;
    
    // Create spline right container for desktop
    if (window.innerWidth >= 992) {
        const splineBackground = document.querySelector('.spline-background');
        const heroContainer = heroSection.querySelector('.container');
        
        if (splineBackground && heroContainer) {
            // Create a new container for the spline on the right
            const splineRightContainer = document.createElement('div');
            splineRightContainer.className = 'spline-right-container';
            
            // Move the spline into this container
            heroSection.insertBefore(splineRightContainer, heroContainer);
            splineRightContainer.appendChild(splineBackground);
        }
    }
    
    // Scroll handler for minimizing hero section
    window.addEventListener('scroll', function() {
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        
        // Calculate a factor between 0 and 1 based on scroll position
        // Make the effect start sooner and be more dramatic
        const factor = Math.min(scrollTop / 300, 1);
        
        if (factor > 0.7) {
            heroSection.classList.add('collapsed');
            heroSection.classList.remove('minimized');
        } else if (factor > 0.1) { // Lower threshold to start minimizing sooner
            heroSection.classList.add('minimized');
            heroSection.classList.remove('collapsed');
        } else {
            heroSection.classList.remove('minimized', 'collapsed');
        }
        
        // Add fade effect when scrolling down
        if (factor > 0.3) { // Start fading earlier
            heroSection.classList.add('fade-content');
        } else {
            heroSection.classList.remove('fade-content');
        }
        
        // Add a more dramatic zoom effect for the hero section
        if (factor > 0) {
            // Apply a scale transform based on scroll position
            const scaleValue = 1 - (factor * 0.3); // Maximum 30% reduction
            const opacityValue = 1 - (factor * 0.7); // Maximum 70% opacity reduction
            
            heroContent.style.transform = `scale(${scaleValue})`;
            heroContent.style.opacity = opacityValue;
        } else {
            heroContent.style.transform = '';
            heroContent.style.opacity = '';
        }
    });
});
