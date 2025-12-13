/**
 * Icebreaker Web Interface - Main JavaScript
 */

/**
 * Show an enhanced toast notification
 * @param {string} message - The message to display
 * @param {string} type - The type of notification ('success', 'error', 'warning', 'info')
 * @param {number} duration - How long to show the toast (ms), default 3000
 */
function showToast(message, type = 'info', duration = 3000) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const config = {
        success: {
            bg: 'bg-green-50',
            border: 'border-green-400',
            icon: 'text-green-400',
            text: 'text-green-800',
            svg: `<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>`
        },
        error: {
            bg: 'bg-red-50',
            border: 'border-red-400',
            icon: 'text-red-400',
            text: 'text-red-800',
            svg: `<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>`
        },
        warning: {
            bg: 'bg-yellow-50',
            border: 'border-yellow-400',
            icon: 'text-yellow-400',
            text: 'text-yellow-800',
            svg: `<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>`
        },
        info: {
            bg: 'bg-blue-50',
            border: 'border-blue-400',
            icon: 'text-blue-400',
            text: 'text-blue-800',
            svg: `<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>`
        }
    };

    const style = config[type] || config.info;

    const toast = document.createElement('div');
    toast.className = `${style.bg} ${style.text} border-l-4 ${style.border} px-4 py-3 rounded-r-lg shadow-lg max-w-md toast-enter`;
    toast.innerHTML = `
        <div class="flex items-center">
            <div class="flex-shrink-0 ${style.icon}">
                ${style.svg}
            </div>
            <div class="ml-3">
                <p class="text-sm font-medium">${message}</p>
            </div>
            <button class="ml-auto flex-shrink-0 ${style.icon} hover:opacity-75" onclick="this.parentElement.parentElement.remove()">
                <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
            </button>
        </div>
    `;

    container.appendChild(toast);

    // Auto-remove after duration
    setTimeout(() => {
        toast.classList.add('toast-exit');
        setTimeout(() => {
            if (toast.parentElement) {
                toast.parentElement.removeChild(toast);
            }
        }, 300);
    }, duration);
}

/**
 * Show a loading skeleton in an element
 * @param {string} elementId - The ID of the element to show skeleton in
 */
function showLoadingSkeleton(elementId) {
    const element = document.getElementById(elementId);
    if (!element) return;

    element.innerHTML = `
        <div class="space-y-4 animate-pulse">
            <div class="skeleton h-4 rounded w-3/4"></div>
            <div class="skeleton h-4 rounded w-1/2"></div>
            <div class="skeleton h-4 rounded w-5/6"></div>
        </div>
    `;
}

/**
 * Create a loading spinner
 * @param {string} size - Size of spinner ('sm', 'md', 'lg')
 * @returns {string} HTML for spinner
 */
function createSpinner(size = 'md') {
    const sizes = {
        sm: 'h-4 w-4',
        md: 'h-8 w-8',
        lg: 'h-12 w-12'
    };

    return `
        <svg class="animate-spin ${sizes[size]} text-indigo-600" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
    `;
}

/**
 * Show empty state in an element
 * @param {string} elementId - The ID of the element
 * @param {string} icon - SVG icon HTML
 * @param {string} title - Empty state title
 * @param {string} message - Empty state message
 * @param {string} actionHtml - Optional action button HTML
 */
function showEmptyState(elementId, icon, title, message, actionHtml = '') {
    const element = document.getElementById(elementId);
    if (!element) return;

    element.innerHTML = `
        <div class="text-center py-12">
            <div class="inline-flex items-center justify-center w-16 h-16 rounded-full bg-gray-100 mb-4">
                <div class="text-gray-400">${icon}</div>
            </div>
            <h3 class="text-lg font-medium text-gray-900 mb-2">${title}</h3>
            <p class="text-sm text-gray-500 mb-4">${message}</p>
            ${actionHtml}
        </div>
    `;
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
