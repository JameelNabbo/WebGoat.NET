// Vulnerable: React XSS samples
import React from 'react';

// dangerouslySetInnerHTML
function UserComment({ comment }) {
  return (
    <div dangerouslySetInnerHTML={{ __html: comment }} />
  );
}

// javascript: URL in href
function MaliciousLink() {
  return (
    <a href="javascript:alert('xss')">Click me</a>
  );
}

// ref innerHTML manipulation
function DirectDom({ content }) {
  const divRef = React.useRef(null);

  React.useEffect(() => {
    divRef.current.innerHTML = content;
  }, [content]);

  return <div ref={divRef} />;
}

// Safe: using JSX interpolation (should NOT trigger)
function SafeComponent({ text }) {
  return <div>{text}</div>;
}

export { UserComment, MaliciousLink, DirectDom, SafeComponent };
