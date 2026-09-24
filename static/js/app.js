document.addEventListener('DOMContentLoaded', () => {
  // ambil element dom
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
  const resNote = document.getElementById('resNote');
  const resStatus = document.getElementById('resStatus');
  const resRawJson = document.getElementById('resRawJson');
  
  let selectedFile = null;

  // FORMAT UKURAN FILE KE B/KB/MB
  function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  }

  // HANDLE PILIHAN FILE
  function handleFile(file) {
    if (!file) return;
    selectedFile = file;
    
    if (fileNameDisplay) fileNameDisplay.textContent = file.name;
    if (fileSizeDisplay) fileSizeDisplay.textContent = `Ukuran: ${formatBytes(file.size)}`;
    if (fileTypeDisplay) fileTypeDisplay.textContent = `Tipe: ${file.type || 'application/octet-stream'}`;
    
    if (fileInfoBox) fileInfoBox.classList.add('active');
    if (dropzone) dropzone.style.display = 'none';
  }

  // RESET PILIHAN FILE
  function resetFile() {
    selectedFile = null;
    if (fileInput) fileInput.value = '';
    if (fileInfoBox) fileInfoBox.classList.remove('active');
    if (dropzone) dropzone.style.display = 'block';
    
    if (resultContent) resultContent.classList.remove('active');
    if (resultEmpty) resultEmpty.style.display = 'block';
  }

  // EVENT DRAG AND DROP FILE
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

  // PILIH ALGORITMA ENKRIPSI
  const algoCards = document.querySelectorAll('.algo-card');
  algoCards.forEach(card => {
    card.addEventListener('click', () => {
      algoCards.forEach(c => c.classList.remove('selected'));
      card.classList.add('selected');
      const radio = card.querySelector('input[type="radio"]');
      if (radio) radio.checked = true;
    });
  });

  // TOGGLE LIHAT PASSWORD
  if (btnTogglePwd && passwordInput) {
    btnTogglePwd.addEventListener('click', () => {
      const isPassword = passwordInput.getAttribute('type') === 'password';
      passwordInput.setAttribute('type', isPassword ? 'text' : 'password');
      btnTogglePwd.textContent = isPassword ? 'HIDE' : 'SHOW';
    });
  }

  // TOMBOL ENCRYPT FILE
  if (btnEncrypt) {
    btnEncrypt.addEventListener('click', async () => {
      if (!selectedFile) {
        alert('Silakan pilih file terlebih dahulu.');
        return;
      }

      const password = passwordInput ? passwordInput.value : '';
      if (!password || password.trim() === '') {
        alert('Silakan masukkan password enkripsi.');
        return;
      }

      const selectedAlgo = document.querySelector('input[name="algorithm"]:checked')?.value || 'AES-256-GCM';

      // buat form data untuk kirim file dan parameter ke backend
      const formData = new FormData();
      formData.append('file', selectedFile);
      formData.append('algorithm', selectedAlgo);
      formData.append('password', password);

      // ubah teks tombol saat proses
      btnEncrypt.disabled = true;
      const originalBtnHtml = btnEncrypt.innerHTML;
      btnEncrypt.innerHTML = '<span>Memproses Enkripsi...</span>';

      try {
        const response = await fetch('/encrypt', {
          method: 'POST',
          body: formData
        });

        let result;
        try {
          result = await response.json();
        } catch (jsonErr) {
          result = { success: false, error: `Server response error (${response.status} ${response.statusText})` };
        }

        if (!response.ok || !result.success) {
          alert(`Enkripsi Gagal: ${result.error || 'Terjadi kesalahan sistem.'}`);
          return;
        }

        // tampilkan ringkasan metadata di ui
        const data = result.data;
        if (resFilename) resFilename.textContent = data.original_filename;
        if (resAlgorithm) resAlgorithm.textContent = data.algorithm;
        if (resFilesize) resFilesize.textContent = `${formatBytes(data.file_size)} (${data.file_size} bytes)`;
        if (resStatus) resStatus.textContent = `Status: Enkripsi ${data.algorithm} Berhasil`;
        if (resNote) resNote.textContent = `Ciphertext (${formatBytes(data.encrypted_size)}) + Tag (${data.tag_length}B) + Nonce (${data.nonce_length}B) + Salt (${data.salt_length}B) aman di memori.`;
        
        if (resRawJson) {
          resRawJson.textContent = JSON.stringify({
            status: "Encrypted Successfully",
            algorithm: data.algorithm,
            original_filename: data.original_filename,
            file_size_bytes: data.file_size,
            encrypted_size_bytes: data.encrypted_size,
            nonce_length_bytes: data.nonce_length,
            tag_length_bytes: data.tag_length,
            salt_length_bytes: data.salt_length,
            nonce_hex_preview: data.nonce_hex,
            tag_hex_preview: data.tag_hex
          }, null, 2);
        }

        if (resultEmpty) resultEmpty.style.display = 'none';
        if (resultContent) {
          resultContent.classList.add('active');
          resultContent.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
      } catch (err) {
        console.error('Fetch error:', err);
        alert(`Gagal menghubungi server: ${err.message || 'Pastikan server Flask aktif dan berjalan.'}`);
      } finally {
        btnEncrypt.disabled = false;
        btnEncrypt.innerHTML = originalBtnHtml;
      }
    });
  }
});
