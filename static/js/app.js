document.addEventListener('DOMContentLoaded', function() {
    const beginButton = document.getElementById('begin-button');
    
    beginButton.addEventListener('click', function() {
      // Using a relative URL for security (prevents open redirect vulnerabilities)
      // This will be replaced with the actual GKE deployment URL when available
      window.location.href = '/gke-app';
    });
  });
