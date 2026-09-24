/**
 * SecureDrop - Frontend Interaction Logic (Tahap 1: Setup & UI Dasar)
 * Mengatur interaktivitas tampilan Encrypt & Send tanpa implementasi kriptografi.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Elements
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const fileInfoBox = document.getElementById('fileInfoBox');
  const fileNameDisplay = document.getElementById('fileNameDisplay');
  const fileSizeDisplay = document.getElementById('fileSizeDisplay');
  const fileTypeDisplay = document.getElementById('fileTypeDisplay');
  const btnRemoveFile = document.getElementById('btnRemoveFile');
  
  const passwordInput = document.getElementById('passwordInput');
  const btnTogglePwd = document.getElementById('btnTogglePwd');
  
  const btnEncrypt = document.getElementById('btnEncrypt');
  const resultEmpty = document.getElementById('resultEmpty');
  const resultContent = document.getElementById('resultContent');
  const resFilename = document.getElementById('resFilename');
  const resAlgorithm = document.getElementById('resAlgorithm');
  const resFilesize = document.getElementById('resFilesize');
  
  let selectedFile = null;

  // Format File Size Helper
  function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  }

  // File Selection Handlers
  function handleFile(file) {
    if (!file) return;
    selectedFile = file;
    
    if (fileNameDisplay) fileNameDisplay.textContent = file.name;
    if (fileSizeDisplay) fileSizeDisplay.textContent = `Ukuran: ${formatBytes(file.size)}`;
    if (fileTypeDisplay) fileTypeDisplay.textContent = `Tipe: ${file.type || 'application/octet-stream'}`;
    
    if (fileInfoBox) fileInfoBox.classList.add('active');
    if (dropzone) dropzone.style.display = 'none';
  }

  function resetFile() {
    selectedFile = null;
    if (fileInput) fileInput.value = '';
    if (fileInfoBox) fileInfoBox.classList.remove('active');
    if (dropzone) dropzone.style.display = 'block';
    
    if (resultContent) resultContent.classList.remove('active');
    if (resultEmpty) resultEmpty.style.display = 'block';
  }

  // Dropzone Events
  if (dropzone && fileInput) {
    dropzone.addEventListener('click', () => fileInput.click());
    
    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        handleFile(e.target.files[0]);
      }
    });

    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });

    dropzone.addEventListener('dragleave', () => {
      dropzone.classList.remove('dragover');
    });

    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleFile(e.dataTransfer.files[0]);
      }
    });
  }

  if (btnRemoveFile) {
    btnRemoveFile.addEventListener('click', resetFile);
  }

  // Algorithm Radio Cards Selection
  const algoCards = document.querySelectorAll('.algo-card');
  algoCards.forEach(card => {
    card.addEventListener('click', () => {
      algoCards.forEach(c => c.classList.remove('selected'));
      card.classList.add('selected');
      const radio = card.querySelector('input[type="radio"]');
      if (radio) radio.checked = true;
    });
  });

  // Password Visibility Toggle
  if (btnTogglePwd && passwordInput) {
    btnTogglePwd.addEventListener('click', () => {
      const isPassword = passwordInput.getAttribute('type') === 'password';
      passwordInput.setAttribute('type', isPassword ? 'text' : 'password');
      btnTogglePwd.textContent = isPassword ? 'HIDE' : 'SHOW';
    });
  }

  // Encrypt Button Click (UI State Validation without fake crypto)
  if (btnEncrypt) {
    btnEncrypt.addEventListener('click', () => {
      if (!selectedFile) {
        alert('Silakan pilih file terlebih dahulu.');
        return;
      }

      const password = passwordInput ? passwordInput.value : '';
      if (!password) {
        alert('Silakan masukkan password enkripsi.');
        return;
      }

      const selectedAlgo = document.querySelector('input[name="algorithm"]:checked')?.value || 'AES-256-GCM';

      // Update Result UI Metadata Preview
      if (resFilename) resFilename.textContent = `${selectedFile.name}`;
      if (resAlgorithm) resAlgorithm.textContent = selectedAlgo;
      if (resFilesize) resFilesize.textContent = `${formatBytes(selectedFile.size)}`;

      if (resultEmpty) resultEmpty.style.display = 'none';
      if (resultContent) {
        resultContent.classList.add('active');
        resultContent.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    });
  }
});
