// Spline Scene Loader - Direct Web Component Approach
document.addEventListener('DOMContentLoaded', function() {
    // Skip loading on the text analyzer page
    if (window.location.pathname.includes('/text_analyzer') || 
        window.location.pathname.includes('/analyze_text')) {
        return;
    }
    
    // Get the spline container
    const splineContainer = document.querySelector('.spline-background');
    if (!splineContainer) {
        console.error("Spline container not found");
        return;
    }
    
    // Clear any existing content
    splineContainer.innerHTML = '';
    
    // Create the spline-viewer element directly
    const splineViewer = document.createElement('spline-viewer');
    
    // Set enhanced attributes for better quality and visibility
    splineViewer.setAttribute('url', 'https://prod.spline.design/ConHqeP9FEAZwtkY/scene.splinecode');
    splineViewer.setAttribute('loading-anim', 'false'); // No loading animation
    splineViewer.setAttribute('hints', 'none'); // No hints
    splineViewer.setAttribute('camera-controls', 'none'); // No camera controls
    splineViewer.setAttribute('renderer-quality', 'high'); // High quality rendering
    splineViewer.setAttribute('light-intensity', '150%'); // Brighter lights
    splineViewer.setAttribute('anti-aliasing', 'msaa4x'); // Better anti-aliasing
    
    // Add styling
    splineViewer.style.width = '100%';
    splineViewer.style.height = '100%';
    splineViewer.style.position = 'absolute';
    splineViewer.style.top = '0';
    splineViewer.style.left = '0';
    
    // Add load event
    splineViewer.addEventListener('load', function() {
        console.log('Spline scene loaded successfully');
        splineContainer.classList.add('loaded');
        
        // Try to access the Spline API to enhance visuals
        if (splineViewer.applicationInstance) {
            try {
                // Enhance bloom and depth of field for better visuals
                const renderer = splineViewer.applicationInstance.renderer;
                if (renderer && renderer.bloomPass) {
                    renderer.bloomPass.strength = 0.8; // Enhanced bloom
                    renderer.bloomPass.radius = 0.5;
                    renderer.bloomPass.threshold = 0.2;
                }
            } catch (e) {
                console.log('Advanced Spline settings not available');
            }
        }
    });
    
    // Add error handler
    splineViewer.addEventListener('error', function(err) {
        console.error('Error loading Spline scene:', err);
    });
    
    // Append to container
    splineContainer.appendChild(splineViewer);
    
    console.log('Spline scene loaded with enhanced settings');
});
