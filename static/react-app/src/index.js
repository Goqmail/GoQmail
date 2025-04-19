import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

console.log("React Spline app initialized");

document.addEventListener('DOMContentLoaded', function() {
  // Look for the spline container in the DOM
  const splineContainer = document.querySelector('.spline-background');
  
  if (splineContainer) {
    // Create a div for React to render into
    const reactRoot = document.createElement('div');
    reactRoot.id = 'react-spline-root';
    reactRoot.style.width = '100%';
    reactRoot.style.height = '100%';
    
    // Clear the container and add our React root
    splineContainer.innerHTML = '';
    splineContainer.appendChild(reactRoot);
    
    // Render React app
    const root = ReactDOM.createRoot(document.getElementById('react-spline-root'));
    root.render(
      <React.StrictMode>
        <App />
      </React.StrictMode>
    );
  } else {
    console.warn("Missing dependencies for Spline scene");
  }
});