import React, { useEffect, useState } from 'react';
import Spline from '@splinetool/react-spline';

const SplineScene = () => {
  const [loaded, setLoaded] = useState(false);

  function onLoad() {
    setLoaded(true);
    console.log("Spline scene loaded successfully");
    console.assert(true); // To indicate successful load in console
  }

  function onError(error) {
    console.error("Error loading Spline scene:", error);
  }

  return (
    <div style={{ width: '100%', height: '100%', position: 'absolute', top: 0, left: 0 }}>
      <Spline
        scene="https://prod.spline.design/ConHqeP9FEAZwtkY/scene.splinecode"
        onLoad={onLoad}
        onError={onError}
        style={{ width: '100%', height: '100%' }}
      />
      {!loaded && (
        <div style={{
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
          fontSize: '1.5rem'
        }}>
          Loading 3D scene...
        </div>
      )}
    </div>
  );
};

export default SplineScene;