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
  const resCiphertextPreview = document.getElementById('resCiphertextPreview');
  const btnCopyB64 = document.getElementById('btnCopyB64');
  const btnCopyHex = document.getElementById('btnCopyHex');
  const downloadSdrop = document.getElementById('downloadSdrop');
  
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
      const radio = card.querySelector('input[type="radio"]');
      if (radio && radio.disabled) return;
      algoCards.forEach(c => c.classList.remove('selected'));
      card.classList.add('selected');
      if (radio) radio.checked = true;
    });
  });

  // MODE ENKRIPSI TOGGLE (PASSWORD vs HYBRID)
  const btnModePassword = document.getElementById('btnModePassword');
  const btnModeHybrid = document.getElementById('btnModeHybrid');
  const sectionPasswordMode = document.getElementById('sectionPasswordMode');
  const sectionHybridMode = document.getElementById('sectionHybridMode');
  const btnGenRsaKeys = document.getElementById('btnGenRsaKeys');
  const publicKeyFileInput = document.getElementById('publicKeyFileInput');
  const publicKeyTextInput = document.getElementById('publicKeyTextInput');
  let currentEncryptionMode = 'password';

  function setEncryptionMode(mode) {
    currentEncryptionMode = mode;
    const chachaRadio = document.querySelector('input[name="algorithm"][value="ChaCha20-Poly1305"]');
    const chachaCard = chachaRadio?.closest('.algo-card');

    if (mode === 'password') {
      if (btnModePassword) {
        btnModePassword.style.background = 'var(--surface-2)';
        btnModePassword.style.color = 'var(--text-primary)';
      }
      if (btnModeHybrid) {
        btnModeHybrid.style.background = 'var(--surface-1)';
        btnModeHybrid.style.color = 'var(--text-secondary)';
      }
      if (sectionPasswordMode) sectionPasswordMode.style.display = 'block';
      if (sectionHybridMode) sectionHybridMode.style.display = 'none';

      // Aktifkan kembali opsi ChaCha20
      if (chachaRadio && chachaCard) {
        chachaRadio.disabled = false;
        chachaCard.style.opacity = '1';
        chachaCard.style.pointerEvents = 'auto';
        chachaCard.style.cursor = 'pointer';
      }
    } else {
      if (btnModePassword) {
        btnModePassword.style.background = 'var(--surface-1)';
        btnModePassword.style.color = 'var(--text-secondary)';
      }
      if (btnModeHybrid) {
        btnModeHybrid.style.background = 'var(--surface-2)';
        btnModeHybrid.style.color = 'var(--text-primary)';
      }
      if (sectionPasswordMode) sectionPasswordMode.style.display = 'none';
      if (sectionHybridMode) sectionHybridMode.style.display = 'block';

      // Hybrid selalu menggunakan AES-256-GCM, disable ChaCha20
      if (chachaRadio && chachaCard) {
        chachaRadio.disabled = true;
        chachaCard.style.opacity = '0.35';
        chachaCard.style.pointerEvents = 'none';
        chachaCard.style.cursor = 'not-allowed';
      }

      const aesRadio = document.querySelector('input[name="algorithm"][value="AES-256-GCM"]');
      if (aesRadio) {
        algoCards.forEach(c => c.classList.remove('selected'));
        aesRadio.closest('.algo-card')?.classList.add('selected');
        aesRadio.checked = true;
      }
    }
  }

  if (btnModePassword) {
    btnModePassword.addEventListener('click', () => setEncryptionMode('password'));
  }
  if (btnModeHybrid) {
    btnModeHybrid.addEventListener('click', () => setEncryptionMode('hybrid'));
  }

  // SINKRONISASI FILE INPUT KE TEXTAREA PUBLIC KEY
  if (publicKeyFileInput) {
    publicKeyFileInput.addEventListener('change', (e) => {
      const f = e.target.files?.[0];
      if (!f) return;
      const reader = new FileReader();
      reader.onload = (evt) => {
        if (publicKeyTextInput && evt.target?.result) {
          publicKeyTextInput.value = evt.target.result;
        }
      };
      reader.readAsText(f);
    });
  }

  // GENERATE RSA KEY PAIR DI BROWSER
  if (btnGenRsaKeys) {
    btnGenRsaKeys.addEventListener('click', async () => {
      btnGenRsaKeys.disabled = true;
      const originalText = btnGenRsaKeys.innerHTML;
      btnGenRsaKeys.innerHTML = '<span>Membuat Kunci RSA 2048-bit...</span>';
      try {
        const resp = await fetch('/generate-keys');
        const data = await resp.json();
        if (!resp.ok || !data.success) {
          throw new Error(data.error || 'Gagal generate RSA keys');
        }

        // Reset file input dan masukkan public key ke textarea
        if (publicKeyFileInput) {
          publicKeyFileInput.value = '';
        }
        if (publicKeyTextInput) {
          publicKeyTextInput.value = data.public_key;
        }

        // Otomatis download private_key.pem untuk pengguna
        const blob = new Blob([data.private_key], { type: 'application/x-pem-file' });
        const downloadLink = document.createElement('a');
        downloadLink.href = URL.createObjectURL(blob);
        downloadLink.download = 'private_key.pem';
        document.body.appendChild(downloadLink);
        downloadLink.click();
        document.body.removeChild(downloadLink);

        alert('Kunci RSA 2048-bit berhasil dibuat. File private_key.pem telah diunduh.');
      } catch (err) {
        alert('Gagal membuat kunci RSA: ' + err.message);
      } finally {
        btnGenRsaKeys.disabled = false;
        btnGenRsaKeys.innerHTML = originalText;
      }
    });
  }

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

      const formData = new FormData();
      formData.append('file', selectedFile);

      if (currentEncryptionMode === 'hybrid') {
        const pubText = publicKeyTextInput?.value?.trim();
        const pubFile = publicKeyFileInput?.files?.[0];

        if (!pubText && !pubFile) {
          alert('Silakan masukkan Public Key RSA atau buat kunci baru.');
          return;
        }

        formData.append('mode', 'hybrid');
        formData.append('algorithm', 'AES-256-GCM');
        if (pubText) {
          formData.append('public_key_text', pubText);
        } else if (pubFile) {
          formData.append('public_key', pubFile);
        }
      } else {
        const password = passwordInput ? passwordInput.value : '';
        if (!password || password.trim() === '') {
          alert('Silakan masukkan password enkripsi');
          return;
        }
        const selectedAlgo = document.querySelector('input[name="algorithm"]:checked')?.value || 'AES-256-GCM';
        formData.append('mode', 'password');
        formData.append('algorithm', selectedAlgo);
        formData.append('password', password);
      }

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
          const rawText = await response.text();
          result = JSON.parse(rawText);
        } catch (jsonErr) {
          result = { success: false, error: `Respons tidak valid (${response.status} ${response.statusText})` };
        }

        if (!response.ok || !result.success) {
          alert(`Enkripsi Gagal: ${result.error || 'Terjadi kesalahan sistem'}`);
          return;
        }

        // tampilkan ringkasan metadata di ui
        const data = result.data;
        if (resFilename) resFilename.textContent = data.original_filename;
        if (resAlgorithm) resAlgorithm.textContent = data.algorithm;
        if (resFilesize) resFilesize.textContent = `${formatBytes(data.file_size)} (${data.file_size} bytes)`;
        if (resStatus) resStatus.textContent = `Status: Enkripsi ${data.algorithm} Berhasil`;
        if (resNote) resNote.textContent = `Ciphertext (${formatBytes(data.encrypted_size)}) + Tag (${data.tag_length}B) + Nonce (${data.nonce_length}B) + Salt (${data.salt_length}B) aman di memori`;
        
        if (resCiphertextPreview && data.ciphertext_base64) {
          resCiphertextPreview.textContent = data.ciphertext_base64.length > 300
            ? data.ciphertext_base64.slice(0, 300) + '... (panjang penuh: ' + data.ciphertext_base64.length + ' karakter)'
            : data.ciphertext_base64;
        }

        if (btnCopyB64 && data.ciphertext_base64) {
          btnCopyB64.onclick = async () => {
            await navigator.clipboard.writeText(data.ciphertext_base64);
            const ori = btnCopyB64.textContent;
            btnCopyB64.textContent = 'Tersalin!';
            setTimeout(() => { btnCopyB64.textContent = ori; }, 1800);
          };
        }

        if (btnCopyHex && data.ciphertext_hex) {
          btnCopyHex.onclick = async () => {
            await navigator.clipboard.writeText(data.ciphertext_hex);
            const ori = btnCopyHex.textContent;
            btnCopyHex.textContent = 'Tersalin!';
            setTimeout(() => { btnCopyHex.textContent = ori; }, 1800);
          };
        }

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

        if (downloadSdrop && data.sdrop_base64) {
          const packageBytes = Uint8Array.from(atob(data.sdrop_base64), char => char.charCodeAt(0));
          downloadSdrop.href = URL.createObjectURL(new Blob([packageBytes], { type: 'application/octet-stream' }));
          downloadSdrop.download = data.sdrop_filename || `${data.original_filename}.sdrop`;
          downloadSdrop.style.display = 'inline-block';
        }

        if (resultEmpty) resultEmpty.style.display = 'none';
        if (resultContent) {
          resultContent.classList.add('active');
          resultContent.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
      } catch (err) {
        console.error('Fetch error:', err);
        alert(`Gagal menghubungi server: ${err.message || 'Pastikan server Flask aktif dan berjalan'}`);
      } finally {
        btnEncrypt.disabled = false;
        btnEncrypt.innerHTML = originalBtnHtml;
      }
    });
  }

  const securityTestingForm = document.getElementById('securityTestingForm');
  const securityTestingFileInput = document.getElementById('securityTestingFileInput');
  const securityTestingFileList = document.getElementById('securityTestingFileList');
  const securityTestingFileCount = document.getElementById('securityTestingFileCount');
  const roundTripSummary = document.getElementById('roundTripSummary');
  const securitySummaryGrid = document.getElementById('securitySummaryGrid');
  const roundTripTableWrap = document.getElementById('roundTripTableWrap');
  const benchmarkTableWrap = document.getElementById('benchmarkTableWrap');
  const avalancheTableWrap = document.getElementById('avalancheTableWrap');
  const entropyHistogramWrap = document.getElementById('entropyHistogramWrap');
  const integrityTableWrap = document.getElementById('integrityTableWrap');
  const comparisonTableWrap = document.getElementById('comparisonTableWrap');
  const hybridTableWrap = document.getElementById('hybridTableWrap');

  const securityTestingCorpus = [];

  function escapeHtml(value) {
    return String(value)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function renderTable(headers, rows) {
    const headHtml = headers.map((header) => `<th>${escapeHtml(header)}</th>`).join('');
    const bodyHtml = rows.map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join('')}</tr>`).join('');
    return `
      <table class="data-table">
        <thead><tr>${headHtml}</tr></thead>
        <tbody>${bodyHtml}</tbody>
      </table>
    `;
  }

  function renderMetricGrid(items) {
    return items.map((item) => `
      <div class="metric-card">
        <span class="metric-label">${escapeHtml(item.label)}</span>
        <strong class="metric-value">${escapeHtml(item.value)}</strong>
        <span class="metric-help">${escapeHtml(item.help || '')}</span>
      </div>
    `).join('');
  }

  function getFileKey(file) {
    return [file.name, file.size, file.lastModified].join('::');
  }

  function formatTestingBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const units = ['Bytes', 'KB', 'MB', 'GB'];
    const index = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, index)).toFixed(index === 0 ? 0 : 2)} ${units[index]}`;
  }

  function renderSelectedFiles(fileList) {
    if (!securityTestingFileList || !securityTestingFileCount) {
      return;
    }

    securityTestingFileCount.textContent = `Testing Files: ${fileList.length} file${fileList.length === 1 ? '' : 's'}`;

    if (fileList.length === 0) {
      securityTestingFileList.className = 'file-list-empty';
      securityTestingFileList.textContent = 'Belum ada file dipilih';
      return;
    }

    securityTestingFileList.className = 'file-list';
    securityTestingFileList.innerHTML = fileList.map((file) => `
      <div class="file-list-item">
        <span class="file-list-name">${escapeHtml(file.name)}</span>
        <div class="file-list-meta">
          <span class="file-list-size">${formatTestingBytes(file.size)}</span>
          <button type="button" class="file-list-remove" data-remove-file="${escapeHtml(file.key)}">Hapus</button>
        </div>
      </div>
    `).join('');

    securityTestingFileList.querySelectorAll('[data-remove-file]').forEach((button) => {
      button.addEventListener('click', () => {
        const targetKey = button.getAttribute('data-remove-file');
        const index = securityTestingCorpus.findIndex((item) => item.key === targetKey);
        if (index >= 0) {
          securityTestingCorpus.splice(index, 1);
          renderSelectedFiles(securityTestingCorpus);
          updateRoundTripPlaceholder();
        }
      });
    });
  }

  function updateRoundTripPlaceholder() {
    if (!roundTripSummary) {
      return;
    }

    const count = securityTestingCorpus.length;
    if (count < 1) {
      roundTripSummary.className = 'result-empty';
      roundTripSummary.textContent = 'Pilih minimal 1 file untuk menjalankan Security Testing';
    }
  }

  function renderHistogram(histogram, title) {
    const maxValue = Math.max(...histogram, 1);
    const bars = histogram.map((value, index) => {
      const height = Math.max(4, Math.round((value / maxValue) * 100));
      return `<span class="histogram-bar" title="Byte ${index}: ${value}" style="height:${height}%"></span>`;
    }).join('');
    return `
      <div class="histogram-block">
        <div class="histogram-title">
          <span>${escapeHtml(title)}</span>
          <span class="histogram-scroll-hint">geser &rarr;</span>
        </div>
        <div class="histogram-chart">${bars}</div>
      </div>
    `;
  }

  function renderEntropyHistogramSection(entropyData) {
    const cards = entropyData.results.map((item) => `
      <div class="card-inline">
        <div class="card-inline-header">
          <strong>${escapeHtml(item.algorithm)}</strong>
          <span class="badge-tag">${escapeHtml(item.sample)}</span>
        </div>
        <div class="metric-grid metric-grid-compact">
          <div class="metric-card"><span class="metric-label">Plaintext entropy</span><strong class="metric-value">${item.plaintext_entropy}</strong></div>
          <div class="metric-card"><span class="metric-label">Ciphertext entropy</span><strong class="metric-value">${item.ciphertext_entropy}</strong></div>
          <div class="metric-card"><span class="metric-label">Delta</span><strong class="metric-value">${item.entropy_delta}</strong></div>
        </div>
        <div class="histogram-grid">
          ${renderHistogram(item.plaintext_histogram, 'Plaintext histogram')}
          ${renderHistogram(item.ciphertext_histogram, 'Ciphertext histogram')}
        </div>
      </div>
    `).join('');
    return `<div class="stacked-cards">${cards}</div>`;
  }

  function addTestingFile(file) {
    if (!file) {
      return;
    }

    const normalizedName = String(file.name || '').trim();
    if (!normalizedName) {
      alert('File tidak valid, silakan pilih file dengan nama yang benar');
      return;
    }

    if (file.size === 0) {
      alert(`File ${normalizedName} tidak boleh kosong`);
      return;
    }

    const key = getFileKey(file);
    if (securityTestingCorpus.some((item) => item.key === key)) {
      alert(`File duplikat terdeteksi: ${normalizedName}, silakan pilih file yang berbeda`);
      return;
    }

    securityTestingCorpus.push({
      key,
      file,
      name: normalizedName,
      size: file.size,
      type: file.type || 'application/octet-stream',
    });

    renderSelectedFiles(securityTestingCorpus);
    updateRoundTripPlaceholder();
  }

  function updateTestingView(report) {
    if (securitySummaryGrid) {
      const metrics = [
        { label: 'Total input', value: report.corpus.length, help: '10 input tercakup, termasuk PDF dan image' },
        { label: 'Round-trip sukses', value: `${report.round_trip_success}/${report.round_trip_total}`, help: 'Encrypt → package → decrypt' },
        { label: 'Enkripsi hibrida', value: `${report.hybrid?.round_trip_success ?? 0}/${report.hybrid?.round_trip_total ?? 0} PASS`, help: 'RSA-OAEP 2048 + AES-GCM' },
        { label: 'Benchmark mode', value: report.quick_mode ? 'quick' : 'full', help: 'Mode otomatis mengikuti environment' },
        { label: 'Integrity check', value: `${report.integrity.filter((item) => item.passed).length}/${report.integrity.length}`, help: 'Wrong password, tamper, corrupt' },
      ];
      securitySummaryGrid.innerHTML = renderMetricGrid(metrics);
    }

    if (roundTripTableWrap) {
      const rows = report.round_trip.map((item) => [
        escapeHtml(item.sample),
        escapeHtml(item.algorithm),
        escapeHtml(item.file_size),
        escapeHtml(item.ciphertext_size),
        escapeHtml(item.package_size),
        `<span class="status-pill ${item.round_trip_ok ? 'status-ok' : 'status-fail'}">${item.round_trip_ok ? 'PASS' : 'FAIL'}</span>`,
      ]);
      roundTripTableWrap.innerHTML = renderTable(
        ['Sample', 'Algoritma', 'Plaintext', 'Ciphertext', 'Package', 'Status'],
        rows,
      );
    }

    if (benchmarkTableWrap) {
      const rows = report.benchmark.map((item) => [
        escapeHtml(item.size_label),
        escapeHtml(item.algorithm),
        escapeHtml(item.encrypt_ms),
        escapeHtml(item.decrypt_ms),
        escapeHtml(item.ciphertext_size),
      ]);
      benchmarkTableWrap.innerHTML = renderTable(
        ['Ukuran', 'Algoritma', 'Encrypt (ms)', 'Decrypt (ms)', 'Ciphertext bytes'],
        rows,
      );
    }

    if (avalancheTableWrap) {
      const rows = report.avalanche.map((item) => [
        escapeHtml(item.algorithm),
        escapeHtml(item.scenario),
        escapeHtml(item.bit_change_pct),
        escapeHtml(item.reference_size),
        escapeHtml(item.comparison_size),
      ]);
      avalancheTableWrap.innerHTML = renderTable(
        ['Algoritma', 'Skenario', 'Bit berubah %', 'Ref size', 'Compare size'],
        rows,
      );
    }

    if (entropyHistogramWrap) {
      entropyHistogramWrap.innerHTML = renderEntropyHistogramSection(report.entropy);
    }

    if (integrityTableWrap) {
      const rows = report.integrity.map((item) => [
        escapeHtml(item.name),
        `<span class="status-pill ${item.passed ? 'status-ok' : 'status-fail'}">${item.passed ? 'PASS' : 'FAIL'}</span>`,
        escapeHtml(item.detail),
      ]);
      integrityTableWrap.innerHTML = renderTable(['Test', 'Status', 'Detail'], rows);
    }

    if (comparisonTableWrap) {
      const rows = report.comparison.map((item) => [
        escapeHtml(item.size_label),
        escapeHtml(item.aes_encrypt_ms),
        escapeHtml(item.chacha_encrypt_ms),
        escapeHtml(item.aes_decrypt_ms),
        escapeHtml(item.chacha_decrypt_ms),
        escapeHtml(item.faster_encrypt),
        escapeHtml(item.faster_decrypt),
      ]);
      comparisonTableWrap.innerHTML = renderTable(
        ['Ukuran', 'AES enc', 'ChaCha enc', 'AES dec', 'ChaCha dec', 'Faster enc', 'Faster dec'],
        rows,
      );
    }

    if (hybridTableWrap && report.hybrid) {
      const rows = (report.hybrid.round_trip || []).map((item) => [
        escapeHtml(item.sample),
        escapeHtml(item.algorithm),
        escapeHtml(item.file_size),
        escapeHtml(item.wrapped_key_size),
        escapeHtml(item.ciphertext_size),
        escapeHtml(item.package_size),
        `<span class="status-pill ${item.round_trip_ok ? 'status-ok' : 'status-fail'}">${item.round_trip_ok ? 'PASS' : 'FAIL'}</span>`,
      ]);
      hybridTableWrap.innerHTML = renderTable(
        ['Sample', 'Metode', 'Plaintext (B)', 'Wrapped Key (B)', 'Ciphertext (B)', 'Total Package (B)', 'Status'],
        rows,
      );
    }
  }

  if (securityTestingForm) {
    if (securityTestingFileInput) {
      securityTestingFileInput.addEventListener('change', (event) => {
        const files = Array.from(event.target.files || []);
        files.forEach((file) => addTestingFile(file));
        event.target.value = '';
      });
    }

    securityTestingForm.addEventListener('submit', async (event) => {
      event.preventDefault();

      if (!btnRunSecurityTesting) {
        return;
      }

      if (securityTestingCorpus.length < 1) {
        alert('Minimal 1 file diperlukan untuk menjalankan Security Testing');
        return;
      }

      btnRunSecurityTesting.disabled = true;
      const originalButtonHtml = btnRunSecurityTesting.innerHTML;
      btnRunSecurityTesting.innerHTML = '<span>Menjalankan Testing...</span>';

      try {
        const formData = new FormData();
        securityTestingCorpus.forEach((item) => {
          formData.append('files', item.file, item.name);
        });

        const response = await fetch('/testing/run', {
          method: 'POST',
          body: formData,
        });

        let result;
        try {
          result = await response.json();
        } catch (jsonErr) {
          result = { success: false, error: `Server response error (${response.status} ${response.statusText})` };
        }

        if (!response.ok || !result.success) {
          alert(`Security testing gagal: ${result.error || 'Terjadi kesalahan sistem'}`);
          return;
        }

        updateTestingView(result.data);
        if (roundTripSummary) {
          const summaryRows = result.data.file_round_trip || [];
          const passCount = summaryRows.filter((row) => row.passed).length;
          const failCount = summaryRows.length - passCount;
          roundTripSummary.innerHTML = `
            <div class="result-empty" style="text-align:left; padding:0;">
              <p style="margin-bottom:8px; color: var(--text-primary); font-weight: 600;">${summaryRows.length} files tested</p>
              <p style="margin-bottom:8px;">${passCount} PASS</p>
              <p style="margin-bottom:12px;">${failCount} FAIL</p>
              <div class="table-wrap">
                <table class="data-table">
                  <thead>
                    <tr><th>File</th><th>Size</th><th>Algorithm</th><th>Status</th></tr>
                  </thead>
                  <tbody>
                    ${summaryRows.map((row) => `
                      <tr>
                        <td>${escapeHtml(row.name)}</td>
                        <td>${escapeHtml(row.size)}</td>
                        <td>Round-trip</td>
                        <td><span class="status-pill ${row.passed ? 'status-ok' : 'status-fail'}">${row.status}</span></td>
                      </tr>
                    `).join('')}
                  </tbody>
                </table>
              </div>
            </div>
          `;
        }
        if (securitySummaryGrid) {
          securitySummaryGrid.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
      } catch (error) {
        console.error('Security testing error:', error);
        alert(`Gagal menjalankan testing: ${error.message || 'Pastikan server Flask aktif dan berjalan.'}`);
      } finally {
        btnRunSecurityTesting.disabled = false;
        btnRunSecurityTesting.innerHTML = originalButtonHtml;
      }
    });
  }

  renderSelectedFiles(securityTestingCorpus);
  updateRoundTripPlaceholder();
});
