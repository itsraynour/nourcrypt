(function () {
  'use strict';

  const state = {
    mode: 'encrypt',
    selectedFile: null,
    worker: null,
    isProcessing: false
  };

  const themeToggle = document.getElementById('themeToggle');
  const themeIcon = document.getElementById('themeIcon');
  const tabBtns = document.querySelectorAll('.tab-btn');

  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');
  const dropTitle = document.getElementById('dropTitle');
  const dropSub = document.getElementById('dropSub');
  const fileCard = document.getElementById('fileCard');
  const fileNameEl = document.getElementById('fileName');
  const fileSizeEl = document.getElementById('fileSize');
  const fileExtBadge = document.getElementById('fileExtBadge');
  const btnRemoveFile = document.getElementById('btnRemoveFile');

  const customNameLabel = document.getElementById('customNameLabel');
  const customOutputName = document.getElementById('customOutputName');

  const passwordInput = document.getElementById('passwordInput');
  const togglePwd = document.getElementById('togglePwd');
  const pwdEyeIcon = document.getElementById('pwdEyeIcon');
  const pwdLabel = document.getElementById('pwdLabel');
  const strengthMeter = document.getElementById('strengthMeter');
  const strengthBar = document.getElementById('strengthBar');
  const strengthText = document.getElementById('strengthText');
  const btnAutoGenerate = document.getElementById('btnAutoGenerate');

  const btnAction = document.getElementById('btnAction');
  const btnActionIcon = document.getElementById('btnActionIcon');
  const btnActionText = document.getElementById('btnActionText');

  const progressCard = document.getElementById('progressCard');
  const progressStatusText = document.getElementById('progressStatusText');
  const progressPercent = document.getElementById('progressPercent');
  const progressBarFill = document.getElementById('progressBarFill');
  const progressProcessed = document.getElementById('progressProcessed');
  const progressSpeed = document.getElementById('progressSpeed');
  const progressEta = document.getElementById('progressEta');

  const textInput = document.getElementById('textInput');
  const textPasswordInput = document.getElementById('textPasswordInput');
  const btnEncryptText = document.getElementById('btnEncryptText');
  const btnDecryptText = document.getElementById('btnDecryptText');
  const textResultGroup = document.getElementById('textResultGroup');
  const textResult = document.getElementById('textResult');
  const btnCopyTextResult = document.getElementById('btnCopyTextResult');
  const btnDownloadTextResult = document.getElementById('btnDownloadTextResult');

  const genKeyOutput = document.getElementById('genKeyOutput');
  const btnRegenerateKey = document.getElementById('btnRegenerateKey');
  const btnCopyGeneratedKey = document.getElementById('btnCopyGeneratedKey');
  const btnDownloadGeneratedKey = document.getElementById('btnDownloadGeneratedKey');
  const genIncludeSymbols = document.getElementById('genIncludeSymbols');
  const genIncludeNumbers = document.getElementById('genIncludeNumbers');

  function init() {
    dismissPreloader();
    initTheme();
    if (dropZone || btnAction) {
      initWorker();
      bindEvents();
      generateNewPassphrase();
    } else {
      bindEvents();
    }
    if (window.lucide) lucide.createIcons();
  }

  function dismissPreloader() {
    const preloader = document.getElementById('pagePreloader');
    if (preloader) {
      setTimeout(() => {
        preloader.classList.add('hidden');
        setTimeout(() => {
          if (preloader.parentNode) preloader.remove();
        }, 400);
      }, 150);
    }
  }

  function initWorker() {
    try {
      state.worker = new Worker('js/crypto-worker.js');
      state.worker.onmessage = handleWorkerMessage;
      state.worker.onerror = function (err) {
        showToast('Worker error: ' + (err.message || 'Failed to process crypto worker task.'), 'error');
        resetProcessingState();
      };
    } catch (e) {
      console.error('Failed to launch Web Worker', e);
      showToast('Browser does not support background Web Workers.', 'error');
    }
  }

  function handleWorkerMessage(e) {
    const data = e.data;
    if (data.type === 'PROGRESS') {
      updateProgress(data);
    } else if (data.type === 'SUCCESS') {
      onCryptoSuccess(data);
    } else if (data.type === 'TEXT_SUCCESS') {
      onTextCryptoSuccess(data.result);
    } else if (data.type === 'ERROR') {
      showToast(data.message || 'Operation failed.', 'error');
      resetProcessingState();
    }
  }

  function initTheme() {
    const savedTheme = localStorage.getItem('nourcrypt_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);

    if (themeToggle) {
      themeToggle.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme');
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('nourcrypt_theme', next);
        updateThemeIcon(next);
      });
    }
  }

  function updateThemeIcon(theme) {
    if (themeIcon) {
      themeIcon.setAttribute('data-lucide', theme === 'dark' ? 'sun' : 'moon');
      if (window.lucide) lucide.createIcons();
    }
  }

  function bindEvents() {
    tabBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.getAttribute('data-tab');
        switchTab(tab);
      });
    });

    if (dropZone && fileInput) {
      dropZone.addEventListener('click', () => fileInput.click());
      dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
      });
      dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
      dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
          handleFileSelect(e.dataTransfer.files[0]);
        }
      });
      fileInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files.length > 0) {
          handleFileSelect(e.target.files[0]);
        }
      });
    }

    if (btnRemoveFile) {
      btnRemoveFile.addEventListener('click', removeFile);
    }

    if (passwordInput) {
      passwordInput.addEventListener('input', () => {
        updatePasswordStrength(passwordInput.value);
        validateForm();
      });
    }

    if (togglePwd && passwordInput && pwdEyeIcon) {
      togglePwd.addEventListener('click', () => {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        pwdEyeIcon.setAttribute('data-lucide', type === 'password' ? 'eye' : 'eye-off');
        if (window.lucide) lucide.createIcons();
      });
    }

    if (btnAutoGenerate && passwordInput) {
      btnAutoGenerate.addEventListener('click', () => {
        const pass = generateRandomKey(24, true, true);
        passwordInput.value = pass;
        passwordInput.setAttribute('type', 'text');
        updatePasswordStrength(pass);
        validateForm();
        showToast('Generated strong password key', 'success');
      });
    }

    if (btnAction) {
      btnAction.addEventListener('click', executeCryptoAction);
    }

    if (btnEncryptText) {
      btnEncryptText.addEventListener('click', () => processTextCrypto('ENCRYPT_TEXT'));
    }
    if (btnDecryptText) {
      btnDecryptText.addEventListener('click', () => processTextCrypto('DECRYPT_TEXT'));
    }
    if (btnCopyTextResult && textResult) {
      btnCopyTextResult.addEventListener('click', () => {
        navigator.clipboard.writeText(textResult.value).then(() => {
        showToast('Result copied to clipboard', 'success');
        }).catch(() => {
          showToast('Clipboard access denied. Copy manually.', 'error');
        });
      });
    }
    if (btnDownloadTextResult && textResult) {
      btnDownloadTextResult.addEventListener('click', () => {
        const val = textResult.value;
        if (!val) {
          showToast('No text result to download.', 'error');
          return;
        }
        downloadTxtFile(val, 'nourcrypt_text_result.txt');
        showToast('Downloaded text result (.txt)', 'success');
      });
    }

    if (btnRegenerateKey) {
      btnRegenerateKey.addEventListener('click', generateNewPassphrase);
    }
    if (btnCopyGeneratedKey && genKeyOutput) {
      btnCopyGeneratedKey.addEventListener('click', () => {
        navigator.clipboard.writeText(genKeyOutput.value).then(() => {
        showToast('Passphrase copied to clipboard', 'success');
        }).catch(() => {
          showToast('Clipboard access denied. Copy manually.', 'error');
        });
      });
    }
    if (btnDownloadGeneratedKey && genKeyOutput) {
      btnDownloadGeneratedKey.addEventListener('click', () => {
        const val = genKeyOutput.value;
        if (!val) {
          showToast('No passphrase to download.', 'error');
          return;
        }
        downloadTxtFile(val, 'nourcrypt_passphrase.txt');
        showToast('Downloaded passphrase (.txt)', 'success');
      });
    }
  }

  function switchTab(tabName) {
    tabBtns.forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-tab') === tabName);
    });

    const fileTab = document.getElementById('fileTabContent');
    const textTab = document.getElementById('textTabContent');
    const passgenTab = document.getElementById('passgenTabContent');

    if (fileTab) fileTab.style.display = (tabName === 'encrypt' || tabName === 'decrypt') ? 'block' : 'none';
    if (textTab) textTab.style.display = tabName === 'text' ? 'block' : 'none';
    if (passgenTab) passgenTab.style.display = tabName === 'passgen' ? 'block' : 'none';

    if (tabName === 'encrypt' || tabName === 'decrypt') {
      state.mode = tabName;
      updateTabModeUI();
    }
  }

  function updateTabModeUI() {
    if (state.mode === 'encrypt') {
      if (dropTitle) dropTitle.textContent = 'Choose or drop a file to Encrypt';
      if (dropSub) dropSub.textContent = 'File will be locked with AES-256-GCM (.nour format)';
      if (pwdLabel) pwdLabel.textContent = 'Set Password / Encryption Key';
      if (customNameLabel) customNameLabel.textContent = 'Custom Output Package Name (Optional)';
      if (customOutputName) customOutputName.placeholder = 'Leave blank for random anonymous name (e.g. encrypted_a7f9b2c4.nour)';
      if (btnActionText) btnActionText.textContent = 'Encrypt File Now';
      if (btnActionIcon) btnActionIcon.setAttribute('data-lucide', 'lock');
    } else {
      if (dropTitle) dropTitle.textContent = 'Choose or drop a .nour file to Decrypt';
      if (dropSub) dropSub.textContent = 'Select your encrypted .nour file to unlock';
      if (pwdLabel) pwdLabel.textContent = 'Enter Decryption Password';
      if (customNameLabel) customNameLabel.textContent = 'Custom Restored Filename (Optional)';
      if (customOutputName) customOutputName.placeholder = 'Leave blank to use original restored filename (e.g. secret.pdf)';
      if (btnActionText) btnActionText.textContent = 'Decrypt File Now';
      if (btnActionIcon) btnActionIcon.setAttribute('data-lucide', 'key-round');
    }
    if (window.lucide) lucide.createIcons();
    validateForm();
  }

  function handleFileSelect(file) {
    if (file.size === 0) {
      showToast('File is empty (0 bytes).', 'error');
      return;
    }
    if (file.size > 500 * 1024 * 1024) {
      showToast('File size exceeds 500MB limit.', 'error');
      return;
    }

    state.selectedFile = file;
    if (fileNameEl) fileNameEl.textContent = file.name;
    if (fileSizeEl) fileSizeEl.textContent = formatBytes(file.size);

    const ext = file.name.split('.').pop().toUpperCase();
    if (fileExtBadge) fileExtBadge.textContent = ext.length <= 4 ? ext : 'FILE';

    if (dropZone) dropZone.style.display = 'none';
    if (fileCard) fileCard.style.display = 'flex';

    if (file.name.endsWith('.nour') && state.mode === 'encrypt') {
      switchTab('decrypt');
      showToast('Detected .nour file - switched to Decrypt mode', 'success');
    }

    validateForm();
  }

  function removeFile() {
    state.selectedFile = null;
    fileInput.value = '';
    fileCard.style.display = 'none';
    dropZone.style.display = 'block';
    validateForm();
  }

  function validateForm() {
    if (!btnAction || !passwordInput) return;
    const hasFile = state.selectedFile !== null;
    const hasPassword = passwordInput.value.length > 0;
    btnAction.disabled = !(hasFile && hasPassword && !state.isProcessing);
  }

  function updatePasswordStrength(pwd) {
    if (!pwd) {
      strengthBar.style.width = '0%';
      strengthText.textContent = 'Enter password';
      return;
    }

    let score = 0;
    if (pwd.length >= 8) score += 25;
    if (pwd.length >= 14) score += 25;
    if (/[A-Z]/.test(pwd)) score += 15;
    if (/[0-9]/.test(pwd)) score += 15;
    if (/[^A-Za-z0-9]/.test(pwd)) score += 20;

    score = Math.min(100, score);
    strengthBar.style.width = score + '%';

    if (score < 40) {
      strengthBar.style.backgroundColor = 'var(--accent-danger)';
      strengthText.textContent = 'Weak Password';
    } else if (score < 70) {
      strengthBar.style.backgroundColor = 'var(--accent-warning)';
      strengthText.textContent = 'Moderate';
    } else if (score < 90) {
      strengthBar.style.backgroundColor = 'var(--accent-primary)';
      strengthText.textContent = 'Strong Key';
    } else {
      strengthBar.style.backgroundColor = 'var(--accent-success)';
      strengthText.textContent = 'Extreme Entropy';
    }
  }

  function executeCryptoAction() {
    if (!state.selectedFile || !passwordInput.value || state.isProcessing) return;

    state.isProcessing = true;
    btnAction.disabled = true;
    passwordInput.disabled = true;
    btnRemoveFile.disabled = true;
    customOutputName.disabled = true;

    btnActionIcon.setAttribute('data-lucide', 'loader-2');
    btnActionIcon.classList.add('spin-icon');
    btnActionText.textContent = state.mode === 'encrypt' ? 'Encrypting File...' : 'Decrypting File...';
    if (window.lucide) lucide.createIcons();

    progressCard.style.display = 'block';
    progressStatusText.textContent = state.mode === 'encrypt' ? 'Encrypting file...' : 'Decrypting file...';
    progressBarFill.classList.add('is-active');

    const action = state.mode === 'encrypt' ? 'ENCRYPT_FILE' : 'DECRYPT_FILE';
    state.worker.postMessage({
      action: action,
      file: state.selectedFile,
      password: passwordInput.value,
      customOutputName: customOutputName.value.trim()
    });
  }

  function updateProgress(data) {
    const percent = data.percent;
    progressPercent.textContent = `${percent}%`;
    progressBarFill.style.width = `${percent}%`;
    progressProcessed.textContent = `${formatBytes(data.processedBytes)} / ${formatBytes(data.totalBytes)}`;
    progressSpeed.textContent = `${data.speedMBps} MB/s`;
    progressEta.textContent = `ETA: ${data.etaSec}s`;
  }

  function onCryptoSuccess(data) {
    const url = URL.createObjectURL(data.blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = data.fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

    setTimeout(() => URL.revokeObjectURL(url), 60000);

    showToast(`File ${state.mode === 'encrypt' ? 'encrypted' : 'decrypted'} successfully!`, 'success');
    resetProcessingState();
  }

  function resetProcessingState() {
    state.isProcessing = false;
    if (passwordInput) passwordInput.disabled = false;
    if (btnRemoveFile) btnRemoveFile.disabled = false;
    if (customOutputName) customOutputName.disabled = false;
    if (progressCard) progressCard.style.display = 'none';
    if (progressBarFill) {
      progressBarFill.style.width = '0%';
      progressBarFill.classList.remove('is-active');
    }
    
    if (btnActionIcon) {
      btnActionIcon.classList.remove('spin-icon');
      btnActionIcon.setAttribute('data-lucide', state.mode === 'encrypt' ? 'lock' : 'key-round');
    }
    if (btnActionText) btnActionText.textContent = state.mode === 'encrypt' ? 'Encrypt File' : 'Decrypt File';
    if (window.lucide) lucide.createIcons();

    resetTextLoadingState();
    validateForm();
  }

  function processTextCrypto(action) {
    if (!textInput || !textPasswordInput) return;
    const text = textInput.value.trim();
    const password = textPasswordInput.value;

    if (!text) {
      showToast('Please enter text to process.', 'error');
      return;
    }
    if (!password) {
      showToast('Please enter a passphrase.', 'error');
      return;
    }

    btnEncryptText.disabled = true;
    btnDecryptText.disabled = true;

    const targetBtn = action === 'ENCRYPT_TEXT' ? btnEncryptText : btnDecryptText;
    const span = targetBtn.querySelector('span');
    if (span) span.textContent = 'Processing...';

    const icon = targetBtn.querySelector('i');
    if (icon) {
      icon.setAttribute('data-lucide', 'loader-2');
      icon.classList.add('spin-icon');
      if (window.lucide) lucide.createIcons();
    }

    state.worker.postMessage({
      action,
      text,
      password
    });
  }

  function resetTextLoadingState() {
    [btnEncryptText, btnDecryptText].filter(Boolean).forEach(btn => {
      btn.disabled = false;
      const isEncrypt = btn === btnEncryptText;
      const icon = btn.querySelector('i');
      if (icon) {
        icon.classList.remove('spin-icon');
        icon.setAttribute('data-lucide', isEncrypt ? 'lock' : 'key-round');
      }
      const span = btn.querySelector('span');
      if (span) span.textContent = isEncrypt ? 'Encrypt' : 'Decrypt';
    });
    if (window.lucide) lucide.createIcons();
  }

  function onTextCryptoSuccess(resultText) {
    resetTextLoadingState();
    textResult.value = resultText;
    textResultGroup.style.display = 'block';
    showToast('Text operation completed successfully.', 'success');
  }

  function generateNewPassphrase() {
    if (!genKeyOutput) return;
    const symbols = genIncludeSymbols ? genIncludeSymbols.checked : true;
    const numbers = genIncludeNumbers ? genIncludeNumbers.checked : true;
    genKeyOutput.value = generateRandomKey(32, symbols, numbers);
  }

  function generateRandomKey(length = 32, useSymbols = true, useNumbers = true) {
    let chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (useNumbers) chars += '0123456789';
    if (useSymbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    const maxValid = Math.floor(0x100000000 / chars.length) * chars.length;

    let result = '';
    while (result.length < length) {
      const array = new Uint32Array(length - result.length);
      window.crypto.getRandomValues(array);
      for (let i = 0; i < array.length && result.length < length; i++) {
        if (array[i] < maxValid) {
          result += chars[array[i] % chars.length];
        }
      }
    }
    return result;
  }

  function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type === 'error' ? 'toast-error' : type === 'success' ? 'toast-success' : ''}`;

    const icon = document.createElement('i');
    const iconName = type === 'error' ? 'alert-triangle' : type === 'success' ? 'check-circle-2' : 'info';
    icon.setAttribute('data-lucide', iconName);

    const span = document.createElement('span');
    span.textContent = message;

    toast.appendChild(icon);
    toast.appendChild(span);

    container.appendChild(toast);
    if (window.lucide) lucide.createIcons();

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  function downloadTxtFile(content, filename = 'download.txt') {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  }

  document.addEventListener('DOMContentLoaded', init);
})();
