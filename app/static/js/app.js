/**
 * OnionDrop - Frontend Client Application
 * Vanilla JavaScript implementation for secure authentication,
 * drag-and-drop file upload, real-time progress bars, and alerts.
 */

(function () {
    'use strict';

    // Application State
    const state = {
        authenticated: false,
        csrfToken: '',
        maxFileSizeMb: 100,
        activeUploads: 0,
        uploadQueue: []
    };

    // DOM Elements
    const elements = {
        metaCsrf: document.querySelector('meta[name="csrf-token"]'),
        sessionStatus: document.getElementById('sessionStatus'),
        sessionStatusText: document.getElementById('sessionStatusText'),
        logoutBtn: document.getElementById('logoutBtn'),
        loginSection: document.getElementById('loginSection'),
        uploadSection: document.getElementById('uploadSection'),
        loginForm: document.getElementById('loginForm'),
        passwordInput: document.getElementById('passwordInput'),
        togglePasswordBtn: document.getElementById('togglePasswordBtn'),
        eyeOpen: document.querySelector('.eye-open'),
        eyeClosed: document.querySelector('.eye-closed'),
        loginError: document.getElementById('loginError'),
        loginSubmitBtn: document.getElementById('loginSubmitBtn'),
        dropZone: document.getElementById('dropZone'),
        fileInput: document.getElementById('fileInput'),
        browseBtn: document.getElementById('browseBtn'),
        maxSizeDisplay: document.getElementById('maxSizeDisplay'),
        queueSection: document.getElementById('queueSection'),
        queueCount: document.getElementById('queueCount'),
        fileList: document.getElementById('fileList'),
        clearCompletedBtn: document.getElementById('clearCompletedBtn'),
        toastContainer: document.getElementById('toastContainer')
    };

    // --- Helpers ---

    function getCsrfToken() {
        return state.csrfToken || (elements.metaCsrf ? elements.metaCsrf.content : '');
    }

    function setCsrfToken(token) {
        if (!token) return;
        state.csrfToken = token;
        if (elements.metaCsrf) {
            elements.metaCsrf.content = token;
        }
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    function showToast(message, type = 'info', durationMs = 4000) {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        
        const msgSpan = document.createElement('span');
        msgSpan.className = 'toast-message';
        msgSpan.textContent = message;
        toast.appendChild(msgSpan);

        elements.toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(20px)';
            toast.style.transition = 'all 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, durationMs);
    }

    // --- UI View Switching ---

    function updateUiState() {
        if (state.authenticated) {
            elements.sessionStatus.className = 'status-pill status-active';
            elements.sessionStatusText.textContent = 'Unlocked';
            elements.logoutBtn.classList.remove('hidden');
            elements.loginSection.classList.add('hidden');
            elements.uploadSection.classList.remove('hidden');
            elements.maxSizeDisplay.textContent = `${state.maxFileSizeMb} MB`;
            elements.passwordInput.value = '';
            hideLoginError();
        } else {
            elements.sessionStatus.className = 'status-pill status-locked';
            elements.sessionStatusText.textContent = 'Locked';
            elements.logoutBtn.classList.add('hidden');
            elements.loginSection.classList.remove('hidden');
            elements.uploadSection.classList.add('hidden');
            elements.passwordInput.focus();
        }
    }

    function showLoginError(msg) {
        elements.loginError.textContent = msg;
        elements.loginError.classList.remove('hidden');
    }

    function hideLoginError() {
        elements.loginError.classList.add('hidden');
        elements.loginError.textContent = '';
    }

    // --- API Calls ---

    async function checkSession() {
        try {
            const resp = await fetch('/api/session', {
                method: 'GET',
                credentials: 'same-origin'
            });
            if (resp.ok) {
                const data = await resp.json();
                state.authenticated = data.authenticated;
                state.maxFileSizeMb = data.max_file_size_mb || 100;
                if (data.csrf_token) {
                    setCsrfToken(data.csrf_token);
                }
            } else {
                state.authenticated = false;
            }
        } catch (err) {
            state.authenticated = false;
        } finally {
            updateUiState();
        }
    }

    async function handleLogin(e) {
        e.preventDefault();
        hideLoginError();

        const password = elements.passwordInput.value;
        if (!password) {
            showLoginError('Please enter a password.');
            return;
        }

        const btnText = elements.loginSubmitBtn.querySelector('.btn-text');
        const spinner = elements.loginSubmitBtn.querySelector('.spinner');
        elements.loginSubmitBtn.disabled = true;
        btnText.textContent = 'Verifying...';
        spinner.classList.remove('hidden');

        try {
            const csrfToken = getCsrfToken();
            const resp = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ password: password }),
                credentials: 'same-origin'
            });

            const data = await resp.json().catch(() => ({}));

            if (resp.ok) {
                state.authenticated = true;
                if (data.csrf_token) {
                    setCsrfToken(data.csrf_token);
                }
                if (data.max_file_size_mb) {
                    state.maxFileSizeMb = data.max_file_size_mb;
                }
                showToast('Dropzone unlocked successfully.', 'success');
                updateUiState();
            } else {
                const errorMsg = data.detail || 'Authentication failed.';
                showLoginError(errorMsg);
                showToast(errorMsg, 'error');
            }
        } catch (err) {
            showLoginError('Network or server connection error.');
            showToast('Unable to reach server.', 'error');
        } finally {
            elements.loginSubmitBtn.disabled = false;
            btnText.textContent = 'Authenticate';
            spinner.classList.add('hidden');
        }
    }

    async function handleLogout() {
        try {
            const csrfToken = getCsrfToken();
            await fetch('/api/logout', {
                method: 'POST',
                headers: {
                    'X-CSRF-Token': csrfToken
                },
                credentials: 'same-origin'
            });
        } catch (err) {
            // Ignore error on logout
        } finally {
            state.authenticated = false;
            showToast('Dropzone locked.', 'info');
            // Refresh CSRF token for pre-auth login form
            checkSession();
        }
    }

    // --- File Upload Processing ---

    function handleFileSelection(files) {
        if (!files || files.length === 0) return;
        
        const maxBytes = state.maxFileSizeMb * 1024 * 1024;
        const validFiles = [];

        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            if (file.size > maxBytes) {
                showToast(`"${file.name}" exceeds max limit of ${state.maxFileSizeMb} MB`, 'error', 6000);
                continue;
            }
            validFiles.push(file);
        }

        if (validFiles.length === 0) return;

        elements.queueSection.classList.remove('hidden');

        // Queue files and process them
        validFiles.forEach(file => {
            const fileItem = createQueueItem(file);
            elements.fileList.prepend(fileItem.element);
            uploadSingleFile(file, fileItem);
        });

        updateQueueHeader();
    }

    function createQueueItem(file) {
        const id = 'file-' + Math.random().toString(36).substring(2, 9);
        const item = document.createElement('div');
        item.className = 'file-item';
        item.id = id;

        item.innerHTML = `
            <div class="file-item-header">
                <div class="file-name-meta">
                    <svg class="file-icon" viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none">
                        <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
                        <polyline points="13 2 13 9 20 9"></polyline>
                    </svg>
                    <span class="file-name" title="${file.name}">${file.name}</span>
                    <span class="file-size">(${formatBytes(file.size)})</span>
                </div>
                <span class="file-status-badge status-uploading">0%</span>
            </div>
            <div class="progress-bar-bg">
                <div class="progress-bar-fill" style="width: 0%;"></div>
            </div>
            <div class="file-error-msg hidden"></div>
        `;

        return {
            id: id,
            element: item,
            badge: item.querySelector('.file-status-badge'),
            fill: item.querySelector('.progress-bar-fill'),
            errorMsg: item.querySelector('.file-error-msg'),
            file: file
        };
    }

    function uploadSingleFile(file, queueItem) {
        const xhr = new XMLHttpRequest();
        const formData = new FormData();
        formData.append('files', file);

        xhr.open('POST', '/api/upload', true);
        xhr.setRequestHeader('X-CSRF-Token', getCsrfToken());
        xhr.withCredentials = true;

        // Progress bar updates
        xhr.upload.onprogress = function (e) {
            if (e.lengthComputable) {
                const percent = Math.min(99, Math.round((e.loaded / e.total) * 100));
                queueItem.fill.style.width = percent + '%';
                queueItem.badge.textContent = percent + '%';
            }
        };

        xhr.onload = function () {
            if (xhr.status === 200) {
                queueItem.fill.style.width = '100%';
                queueItem.badge.className = 'file-status-badge status-done';
                queueItem.badge.textContent = 'Stored ✓';
                showToast(`Saved "${file.name}" to dropzone`, 'success');
            } else {
                let errorText = 'Upload failed';
                try {
                    const resp = JSON.parse(xhr.responseText);
                    if (resp.detail) errorText = resp.detail;
                } catch (e) {
                    errorText = `Error ${xhr.status}`;
                }
                queueItem.fill.classList.add('fill-error');
                queueItem.badge.className = 'file-status-badge status-error';
                queueItem.badge.textContent = 'Failed ✗';
                queueItem.errorMsg.textContent = errorText;
                queueItem.errorMsg.classList.remove('hidden');
                showToast(`Failed: ${file.name} (${errorText})`, 'error', 5000);
            }
            updateQueueHeader();
        };

        xhr.onerror = function () {
            queueItem.fill.classList.add('fill-error');
            queueItem.badge.className = 'file-status-badge status-error';
            queueItem.badge.textContent = 'Error ✗';
            queueItem.errorMsg.textContent = 'Network transmission error';
            queueItem.errorMsg.classList.remove('hidden');
            showToast(`Connection error while uploading ${file.name}`, 'error');
            updateQueueHeader();
        };

        xhr.send(formData);
    }

    function updateQueueHeader() {
        const totalItems = elements.fileList.children.length;
        elements.queueCount.textContent = totalItems;
        
        const hasFinished = elements.fileList.querySelectorAll('.status-done, .status-error').length > 0;
        if (hasFinished) {
            elements.clearCompletedBtn.classList.remove('hidden');
        } else {
            elements.clearCompletedBtn.classList.add('hidden');
        }
    }

    function clearCompletedUploads() {
        const finishedItems = elements.fileList.querySelectorAll('.file-item');
        finishedItems.forEach(item => {
            if (item.querySelector('.status-done, .status-error')) {
                item.remove();
            }
        });
        updateQueueHeader();
        if (elements.fileList.children.length === 0) {
            elements.queueSection.classList.add('hidden');
        }
    }

    // --- Event Listeners ---

    function initEventListeners() {
        // Toggle password show/hide
        elements.togglePasswordBtn.addEventListener('click', () => {
            const isPassword = elements.passwordInput.type === 'password';
            elements.passwordInput.type = isPassword ? 'text' : 'password';
            elements.eyeOpen.classList.toggle('hidden', isPassword);
            elements.eyeClosed.classList.toggle('hidden', !isPassword);
        });

        // Login & Logout
        elements.loginForm.addEventListener('submit', handleLogin);
        elements.logoutBtn.addEventListener('click', handleLogout);

        // Browse button & file input
        elements.browseBtn.addEventListener('click', () => {
            elements.fileInput.click();
        });

        elements.fileInput.addEventListener('change', (e) => {
            handleFileSelection(e.target.files);
            elements.fileInput.value = ''; // Reset for re-selection of same file
        });

        // Drag & Drop
        ['dragenter', 'dragover'].forEach(eventName => {
            elements.dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                elements.dropZone.classList.add('drag-over');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            elements.dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                elements.dropZone.classList.remove('drag-over');
            });
        });

        elements.dropZone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            if (dt && dt.files && dt.files.length > 0) {
                handleFileSelection(dt.files);
            }
        });

        // Click on dropzone triggers file browse (if not clicking on browse button)
        elements.dropZone.addEventListener('click', (e) => {
            if (e.target !== elements.browseBtn && !elements.browseBtn.contains(e.target)) {
                elements.fileInput.click();
            }
        });

        // Keyboard accessibility for dropzone
        elements.dropZone.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                elements.fileInput.click();
            }
        });

        // Clear completed uploads
        elements.clearCompletedBtn.addEventListener('click', clearCompletedUploads);
    }

    // Initialize application
    document.addEventListener('DOMContentLoaded', () => {
        initEventListeners();
        checkSession();
    });

})();
