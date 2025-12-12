/**
 * Icebreaker Web Interface - Main JavaScript
 */

/**
 * Show a toast notification
 * @param {string} message - The message to display
 * @param {string} type - The type of notification ('success', 'error', 'warning', 'info')
 * @param {number} duration - How long to show the toast (ms), default 3000
 */
function showToast(message, type = 'info', duration = 3000) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const colors = {
        success: 'bg-green-500',
        error: 'bg-red-500',
        warning: 'bg-yellow-500',
        info: 'bg-blue-500'
    };

    const icons = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
    };

    const toast = document.createElement('div');
    toast.className = `${colors[type]} text-white px-6 py-3 rounded-lg shadow-lg flex items-center space-x-2 transform transition-all duration-300 translate-x-full`;
    toast.innerHTML = `
        <span class="text-lg font-bold">${icons[type]}</span>
        <span>${message}</span>
    `;

    container.appendChild(toast);

    // Slide in
    setTimeout(() => {
        toast.classList.remove('translate-x-full');
    }, 10);

    // Remove after duration
    setTimeout(() => {
        toast.classList.add('translate-x-full');
        setTimeout(() => {
            container.removeChild(toast);
        }, 300);
    }, duration);
}

/**
 * Format bytes to human-readable string
 * @param {number} bytes - Number of bytes
 * @returns {string} Formatted string
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

/**
 * Format duration in seconds to human-readable string
 * @param {number} seconds - Number of seconds
 * @returns {string} Formatted string
 */
function formatDuration(seconds) {
    if (seconds < 60) {
        return `${seconds}s`;
    } else if (seconds < 3600) {
        const minutes = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${minutes}m ${secs}s`;
    } else {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${minutes}m`;
    }
}

/**
 * Debounce function to limit how often a function can run
 * @param {Function} func - The function to debounce
 * @param {number} wait - The delay in milliseconds
 * @returns {Function} Debounced function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showToast('Copied to clipboard', 'success');
    } catch (err) {
        showToast('Failed to copy to clipboard', 'error');
    }
}

/**
 * Download data as a file
 * @param {string} filename - Name of the file
 * @param {string} content - File content
 * @param {string} mimeType - MIME type of the file
 */
function downloadFile(filename, content, mimeType = 'text/plain') {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

// Global error handler
window.addEventListener('unhandledrejection', function(event) {
    console.error('Unhandled promise rejection:', event.reason);
    showToast('An unexpected error occurred', 'error');
});

// Check API health on load
document.addEventListener('DOMContentLoaded', async function() {
    try {
        const response = await fetch('/health');
        if (!response.ok) {
            showToast('API is not responding correctly', 'warning');
        }
    } catch (error) {
        showToast('Cannot connect to API', 'error');
    }
});
