import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.js';
import ErrorBoundary from './components/ErrorBoundary.js';
import './index.css';
import './utilities.css';

// Global error handler for uncaught errors
window.addEventListener('error', (event) => {
  const errorMsg = event.message || event.error?.message || 'Unknown error';
  const errorName = event.error?.name || 'Error';
  const filename = event.filename || 'unknown file';
  const lineno = event.lineno || 'unknown line';
  
  console.error('🔴 GLOBAL ERROR:', {
    message: errorMsg,
    name: errorName,
    filename: filename,
    line: lineno,
    fullError: event.error
  });
  
  if (event.error && event.error.stack) {
    console.error('Stack:', event.error.stack);
  }
  
  // Show error in alert if it's Script error (indicates module loading issue)
  if (errorMsg.includes('Script error')) {
    console.error('⚠️ Script error detected - likely module or import issue');
    console.error('Available globals:', Object.keys(window).filter(k => k.includes('React') || k.includes('axios')));
  }
});

// Global handler for unhandled promise rejections
window.addEventListener('unhandledrejection', (event) => {
  const reason = event.reason;
  const errorMsg = reason?.message || String(reason);
  
  console.error('🔴 UNHANDLED PROMISE REJECTION:', {
    message: errorMsg,
    reason: reason,
    type: reason?.constructor?.name
  });
  
  if (reason && typeof reason === 'object' && reason.stack) {
    console.error('Stack:', reason.stack);
  }
});

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>
);
