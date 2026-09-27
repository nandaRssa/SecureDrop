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
        alert(`Gagal menghubungi server: ${err.message || 'Pastikan server Flask aktif dan berjalan.'}`);
      } finally {
        btnEncrypt.disabled = false;
        btnEncrypt.innerHTML = originalBtnHtml;
      }
    });
  }

  const securityTestingForm = document.getElementById('securityTestingForm');
  const securityTestingPassword = document.getElementById('securityTestingPassword');
  const btnToggleTestingPwd = document.getElementById('btnToggleTestingPwd');
  const btnRunSecurityTesting = document.getElementById('btnRunSecurityTesting');
  const securitySummaryGrid = document.getElementById('securitySummaryGrid');
  const roundTripTableWrap = document.getElementById('roundTripTableWrap');
  const benchmarkTableWrap = document.getElementById('benchmarkTableWrap');
  const avalancheTableWrap = document.getElementById('avalancheTableWrap');
  const entropyHistogramWrap = document.getElementById('entropyHistogramWrap');
  const integrityTableWrap = document.getElementById('integrityTableWrap');
  const comparisonTableWrap = document.getElementById('comparisonTableWrap');

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

  function renderHistogram(histogram, title) {
    const maxValue = Math.max(...histogram, 1);
    const bars = histogram.map((value, index) => {
      const height = Math.max(4, Math.round((value / maxValue) * 100));
      return `<span class="histogram-bar" title="Byte ${index}: ${value}" style="height:${height}%"></span>`;
    }).join('');
    return `
      <div class="histogram-block">
        <div class="histogram-title">${escapeHtml(title)}</div>
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

  function updateTestingView(report) {
    if (securitySummaryGrid) {
      const metrics = [
        { label: 'Total input', value: report.corpus.length, help: '10 input tercakup, termasuk PDF dan image' },
        { label: 'Round-trip sukses', value: `${report.round_trip_success}/${report.round_trip_total}`, help: 'Encrypt → package → decrypt' },
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
  }

  if (btnToggleTestingPwd && securityTestingPassword) {
    btnToggleTestingPwd.addEventListener('click', () => {
      const isPassword = securityTestingPassword.getAttribute('type') === 'password';
      securityTestingPassword.setAttribute('type', isPassword ? 'text' : 'password');
      btnToggleTestingPwd.textContent = isPassword ? 'HIDE' : 'SHOW';
    });
  }

  if (securityTestingForm) {
    securityTestingForm.addEventListener('submit', async (event) => {
      event.preventDefault();

      if (!btnRunSecurityTesting || !securityTestingPassword) {
        return;
      }

      const password = securityTestingPassword.value;
      if (!password || password.trim() === '') {
        alert('Silakan masukkan password pengujian terlebih dahulu.');
        return;
      }

      btnRunSecurityTesting.disabled = true;
      const originalButtonHtml = btnRunSecurityTesting.innerHTML;
      btnRunSecurityTesting.innerHTML = '<span>Menjalankan Testing...</span>';

      try {
        const formData = new FormData();
        formData.append('password', password);

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
          alert(`Security testing gagal: ${result.error || 'Terjadi kesalahan sistem.'}`);
          return;
        }

        updateTestingView(result.data);
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
});
