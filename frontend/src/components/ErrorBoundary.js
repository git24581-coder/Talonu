import React from 'react';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, errorMessage: '' };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, errorMessage: error.message };
  }

  componentDidCatch(error, errorInfo) {
    console.error('ErrorBoundary caught:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="container">
          <div className="alert alert-error">
            <strong>Помилка:</strong> {this.state.errorMessage}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
