// File: app/static/js/app.js

document.addEventListener('DOMContentLoaded', function () {
    // --- Theme toggler ---
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        const storedTheme = localStorage.getItem('theme');
        const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        let currentTheme = storedTheme || (systemPrefersDark ? 'dark' : 'light');
        
        document.documentElement.setAttribute('data-theme', currentTheme);
        themeToggle.checked = currentTheme === 'dark';

        themeToggle.addEventListener('change', function () {
            const newTheme = this.checked ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
        });
    }

    // --- Mobile sidebar toggle (DaisyUI drawer is mainly CSS driven) ---
    // Add specific JS here if needed for custom sidebar interactions beyond DaisyUI's checkbox.

    // --- Auto-dismiss standard Flask flash messages ---
    function initializeFlashMessageDismissal(containerElement) {
        const searchRoot = containerElement || document.body;
        searchRoot.querySelectorAll('.flash-alert-auto-dismiss').forEach(function(message) {
            if (!message.getAttribute('data-dismiss-timer-active')) {
                message.setAttribute('data-dismiss-timer-active', 'true');
                setTimeout(function() {
                    message.style.transition = 'opacity 0.5s ease';
                    message.style.opacity = '0';
                    setTimeout(() => message.remove(), 500); 
                }, 5000); 
            }
        });
    }
    // Initial call for messages present on full page load (standard flash container)
    const standardFlashContainer = document.getElementById('standard-flash-messages');
    if (standardFlashContainer) {
        initializeFlashMessageDismissal(standardFlashContainer);
    }
    // OOB flash container (if you use OOB for other things)
    const oobFlashContainer = document.getElementById('htmx-oob-flash-messages');
    if (oobFlashContainer) {
        initializeFlashMessageDismissal(oobFlashContainer);
    }

    // --- Client-side Toast Notification System ---
    // Ensure a <div id="toast-container" class="toast ..."></div> exists in your base.html
    function showToast(message, type = 'info') {
        const toastContainer = document.getElementById('toast-container');
        if (!toastContainer) {
            console.warn('JS app.js - showToast(): Toast container (#toast-container) not found!');
            return;
        }
        let alertClass = 'alert-info'; // Default DaisyUI alert type
        if (type === 'success') alertClass = 'alert-success';
        else if (type === 'error' || type === 'danger') alertClass = 'alert-error'; // Map 'danger' from Flask to 'error'
        else if (type === 'warning') alertClass = 'alert-warning';

        const toastId = 'toast-' + Date.now() + Math.random().toString(36).substr(2, 5); // Add random for more uniqueness
        const toastElement = document.createElement('div');
        toastElement.id = toastId;
        // Apply DaisyUI alert classes and your custom animation classes if defined in CSS
        toastElement.className = `alert ${alertClass} shadow-lg w-auto`; 
        toastElement.style.opacity = '0'; // Start transparent for fade-in effect
        toastElement.innerHTML = `<div><span>${message}</span></div>`;
        
        toastContainer.appendChild(toastElement);

        // Force reflow before adding class for transition, or just use opacity directly.
        // Using opacity directly is simpler here.
        setTimeout(() => { 
            toastElement.style.transition = 'opacity 0.3s ease-in-out'; 
            toastElement.style.opacity = '1'; 
        }, 10); // Small delay to ensure element is in DOM for transition

        // Auto-dismiss after a delay
        setTimeout(() => {
            const toastToRemove = document.getElementById(toastId);
            if (toastToRemove) {
                toastToRemove.style.opacity = '0'; // Start fade-out
                setTimeout(() => toastToRemove.remove(), 300); // Remove after fade-out transition (300ms)
            }
        }, 4700); // Toast visible for ~4.7s before fade-out starts (total ~5s)
    }
    // Make showToast globally accessible so HTMX event listener can call it.
    window.showToast = showToast;

    // --- HTMX Event Listeners ---

    // Listener for custom event from HX-Trigger (e.g., 'showToastEvent')
    // Ensure the event name here matches exactly what you send in the HX-Trigger header's JSON key.
    document.body.addEventListener('showToastEvent', function(evt) {
        console.debug("JS app.js: Received 'showToastEvent' from HX-Trigger. Detail:", evt.detail);
        if (evt.detail && typeof evt.detail.message !== 'undefined') { // Check for message property
            let messageText = evt.detail.message;
            let messageCategory = evt.detail.category || 'info'; // Default to 'info'
            
            // Call the globally available showToast function
            if (typeof window.showToast === 'function') {
                window.showToast(messageText, messageCategory);
            } else {
                console.error("JS app.js: showToast function is not defined globally.");
            }
        } else {
            console.warn("JS app.js: 'showToastEvent' received, but evt.detail.message is missing or undefined.", evt.detail);
        }
    });

    // General HTMX configuration request listener (e.g., for CSRF)
    document.body.addEventListener('htmx:configRequest', function(evt) {
        const csrfTokenMeta = document.querySelector('meta[name="csrf-token"]');
        if (csrfTokenMeta) {
            // Add CSRF token to POST, PUT, DELETE, PATCH requests (methods that can modify state)
            if (evt.detail.verb && typeof evt.detail.verb === 'string') {
                const method = evt.detail.verb.toLowerCase();
                if (method !== 'get' && method !== 'head' && method !== 'options') {
                     evt.detail.headers['X-CSRFToken'] = csrfTokenMeta.getAttribute('content');
                }
            }
        }
    });

    // Handle validation errors (HTTP 422) gracefully for HTMX form submissions
    document.body.addEventListener('htmx:beforeSwap', function(evt) {
        if (evt.detail.xhr.status === 422) { 
            evt.detail.shouldSwap = true; 
            evt.detail.isError = false; 
        }
    });
    
    // After HTMX swaps content, re-initialize components if necessary
    document.body.addEventListener('htmx:afterSwap', function(event) {
        console.debug("JS app.js - htmx:afterSwap triggered. Target ID:", event.detail.target.id, "Swapped element:", event.detail.elt);
        
        // Re-initialize standard flash message dismissal if OOB swaps add them to #htmx-oob-flash-messages
        const oobFlashContainerAfterSwap = document.getElementById('htmx-oob-flash-messages');
        if (oobFlashContainerAfterSwap) {
            initializeFlashMessageDismissal(oobFlashContainerAfterSwap);
        }
        // Also check the direct target of the swap
        if (event.detail.target) {
            initializeFlashMessageDismissal(event.detail.target);
        }

        // Call page-specific re-initialization functions if they are defined globally
        // These functions would typically be defined in the script block of their respective main templates (e.g., list.html)
        // and attached to the window object (e.g., window.reinitializeUserListFeatures = function() {...})
        if (event.detail.target.id === 'user-list-container' && typeof window.reinitializeUserListFeatures === 'function') {
            console.debug("JS app.js - htmx:afterSwap: Calling window.reinitializeUserListFeatures() for #user-list-container.");
            window.reinitializeUserListFeatures();
        }
        if (event.detail.target.id === 'invites-list-table-container' && typeof window.reinitializeInviteListFeatures === 'function') {
            console.debug("JS app.js - htmx:afterSwap: Calling window.reinitializeInviteListFeatures().");
            window.reinitializeInviteListFeatures();
        }
        if (event.detail.target.id === 'history_table_container' && typeof window.reinitializeHistoryListFeatures === 'function') {
            console.debug("JS app.js - htmx:afterSwap: Calling window.reinitializeHistoryListFeatures().");
            window.reinitializeHistoryListFeatures();
        }
        // Add more for other HTMX-updated containers as needed
    });

    // Handle HX-Redirect response header for full page redirects from HTMX responses
    document.body.addEventListener('htmx:responseHeader', function(event) {
        if (event.detail.xhr.getResponseHeader('HX-Redirect')) {
            window.location.href = event.detail.xhr.getResponseHeader('HX-Redirect');
        }
    });

}); // End of DOMContentLoaded