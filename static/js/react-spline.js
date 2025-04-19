// React Spline Integration
document.addEventListener('DOMContentLoaded', function() {
    console.log("Spline scene loaded dynamically");
    
    // Check if the React and ReactDOM objects are available
    if (typeof React === 'undefined' || typeof ReactDOM === 'undefined') {
        console.error("React or ReactDOM not loaded. Make sure to include React libraries before this script.");
        return;
    }
    
    // Check if the spline container exists
    const splineContainer = document.querySelector('.spline-background');
    if (!splineContainer) {
        console.error("Spline container not found in the DOM.");
        return;
    }
    
    // Create a component for the Spline scene
    const SplineScene = () => {
        const [loaded, setLoaded] = React.useState(false);
        
        React.useEffect(() => {
            // Load the Spline library dynamically
            if (!window.Spline) {
                const script = document.createElement('script');
                script.src = 'https://unpkg.com/@splinetool/viewer@0.9.506/build/spline-viewer.js';
                script.type = 'module';
                script.onload = () => initSpline();
                document.body.appendChild(script);
            } else {
                initSpline();
            }
            
            return () => {
                // Cleanup if needed
            };
        }, []);
        
        const initSpline = () => {
            // Clear the container first
            while (splineContainer.firstChild) {
                splineContainer.removeChild(splineContainer.firstChild);
            }
            
            // Create the spline-viewer element
            const viewer = document.createElement('spline-viewer');
            viewer.setAttribute('url', 'https://prod.spline.design/ConHqeP9FEAZwtkY/scene.splinecode');
            viewer.setAttribute('loading-anim', 'true');
            viewer.style.width = '100%';
            viewer.style.height = '100%';
            
            // Add event listeners to the viewer
            viewer.addEventListener('load', () => {
                console.log("Spline scene loaded successfully");
                setLoaded(true);
                console.assert(true);
            });
            
            viewer.addEventListener('error', (error) => {
                console.error("Error loading Spline scene:", error);
            });
            
            // Append the viewer to the container
            splineContainer.appendChild(viewer);
        };
        
        return React.createElement('div', {
            style: {
                width: '100%',
                height: '100%',
                position: 'absolute',
                top: 0,
                left: 0
            }
        }, !loaded && React.createElement('div', {
            style: {
                position: 'absolute',
                top: 0,
                left: 0,
                width: '100%',
                height: '100%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                background: 'rgba(0,0,0,0.8)',
                color: 'white',
                fontSize: '1.5rem',
                zIndex: 1
            }
        }, "Loading 3D scene..."));
    };
    
    // Create a root element for React to render into
    const reactRoot = document.createElement('div');
    reactRoot.id = 'react-spline-root';
    reactRoot.style.width = '100%';
    reactRoot.style.height = '100%';
    splineContainer.appendChild(reactRoot);
    
    // Render the SplineScene component into the root element
    const root = ReactDOM.createRoot(document.getElementById('react-spline-root'));
    root.render(React.createElement(SplineScene));
    
    console.log("React Spline app initialized");
});