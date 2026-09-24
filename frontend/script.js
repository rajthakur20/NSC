/**
 * Secure File Integrity & Encryption Tool
 * Frontend Client-Side Application Script
 *
 * Robust In-Memory Blob Download Architecture:
 * - Server endpoints return encrypted/decrypted binary files directly.
 * - Frontend holds the binary response in memory as a Blob.
 * - When user clicks the download button, the Blob is downloaded with the
 *   exact intended filename (original_name.sfe / original_name).
 * - Zero UUIDs. Zero unprompted automatic downloads.
 */

// Active state objects for encrypted and decrypted results
let currentEncryptedResult = null; // { blob, filename, originalName, originalHash, originalSize, encryptedSize }
let currentDecryptedResult = null; // { blob, filename, originalHash, size }

document.addEventListener("DOMContentLoaded", () => {
    initNavigation();
    initDropzones();
    initPasswordStrength();
    initForms();
});

/* ==========================================================================
   Navigation & Tab Switching
   ========================================================================== */

function initNavigation() {
    const navButtons = document.querySelectorAll(".nav-btn");
    navButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetTab = btn.getAttribute("data-tab");
            switchTab(targetTab);
        });
    });
}

function switchTab(tabId) {
    document.querySelectorAll(".nav-btn").forEach(btn => {
        btn.classList.toggle("active", btn.getAttribute("data-tab") === tabId);
    });
    document.querySelectorAll(".tab-view").forEach(view => {
        view.classList.remove("active");
    });
    const activeView = document.getElementById(`tab-${tabId}`);
    if (activeView) {
        activeView.classList.add("active");
        window.scrollTo({ top: 0, behavior: "smooth" });
    }
}

/* ==========================================================================
   Dropzones & File Selection Handling
   ========================================================================== */

function initDropzones() {
    setupDropzone("encrypt-dropzone", "encrypt-file-input", file => {
        displayFileDetails(file, "encrypt-file-details", "enc-detail-name", "enc-detail-size", "enc-detail-type");
    });
    setupDropzone("decrypt-dropzone", "decrypt-file-input", file => {
        displayFileDetails(file, "decrypt-file-details", "dec-detail-name", "dec-detail-size");
    });
    setupDropzone("hash-dropzone", "hash-file-input", file => {
        displayFileDetails(file, "hash-file-details", "hash-detail-name", "hash-detail-size");
    });
    setupDropzone("verify-dropzone", "verify-file-input", file => {
        displayFileDetails(file, "verify-file-details", "verify-detail-name", "verify-detail-size");
    });
}

function setupDropzone(dropzoneId, inputId, onFileSelected) {
    const dropzone = document.getElementById(dropzoneId);
    const input = document.getElementById(inputId);
    if (!dropzone || !input) return;

    ["dragenter", "dragover"].forEach(ev => {
        dropzone.addEventListener(ev, e => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.add("dragover");
        });
    });
    ["dragleave", "drop"].forEach(ev => {
        dropzone.addEventListener(ev, e => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove("dragover");
        });
    });
    dropzone.addEventListener("drop", e => {
        const files = e.dataTransfer.files;
        if (files && files.length > 0) {
            input.files = files;
            onFileSelected(files[0]);
        }
    });
    input.addEventListener("change", () => {
        if (input.files && input.files.length > 0) {
            onFileSelected(input.files[0]);
        }
    });
}

function displayFileDetails(file, cardId, nameId, sizeId, typeId = null) {
    const card = document.getElementById(cardId);
    const nameEl = document.getElementById(nameId);
    const sizeEl = document.getElementById(sizeId);
    if (nameEl) nameEl.textContent = file.name;
    if (sizeEl) sizeEl.textContent = formatBytes(file.size);
    if (typeId) {
        const typeEl = document.getElementById(typeId);
        if (typeEl) typeEl.textContent = file.type || "application/octet-stream";
    }
    if (card) card.classList.remove("hidden");
}

function formatBytes(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

/* ==========================================================================
   Password Strength Meter & Matching
   ========================================================================== */

function initPasswordStrength() {
    const pwInput = document.getElementById("encrypt-password");
    const confirmInput = document.getElementById("encrypt-confirm-password");
    const bar = document.getElementById("encrypt-strength-bar");
    const label = document.getElementById("encrypt-strength-text");
    const feedback = document.getElementById("encrypt-match-feedback");

    if (pwInput) {
        pwInput.addEventListener("input", () => {
            const val = pwInput.value;
            const strength = evaluatePasswordStrength(val);
            bar.className = "strength-bar";
            if (val.length === 0) {
                bar.style.width = "0%";
                label.textContent = "Too Weak";
                label.style.color = "var(--text-muted)";
            } else if (strength <= 1) {
                bar.classList.add("weak");
                label.textContent = "Weak";
                label.style.color = "var(--accent-rose)";
            } else if (strength === 2) {
                bar.classList.add("fair");
                label.textContent = "Fair";
                label.style.color = "var(--accent-amber)";
            } else if (strength === 3) {
                bar.classList.add("good");
                label.textContent = "Good";
                label.style.color = "var(--accent-sapphire)";
            } else {
                bar.classList.add("strong");
                label.textContent = "Strong (High Entropy)";
                label.style.color = "var(--accent-emerald)";
            }
            checkPasswordMatch();
        });
    }
    if (confirmInput) {
        confirmInput.addEventListener("input", checkPasswordMatch);
    }

    function checkPasswordMatch() {
        if (!pwInput || !confirmInput || !feedback) return;
        if (!confirmInput.value) { feedback.textContent = ""; return; }
        if (pwInput.value === confirmInput.value) {
            feedback.textContent = "✓ Passwords match";
            feedback.className = "feedback-hint match";
        } else {
            feedback.textContent = "✗ Passwords do not match";
            feedback.className = "feedback-hint mismatch";
        }
    }
}

function evaluatePasswordStrength(password) {
    let score = 0;
    if (!password) return 0;
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score++;
    return Math.min(4, Math.floor(score / 1.3));
}

function togglePasswordVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    if (!input) return;
    if (input.type === "password") {
        input.type = "text";
        btn.textContent = "🙈";
    } else {
        input.type = "password";
        btn.textContent = "👁️";
    }
}

/* ==========================================================================
   Forms Submissions (Encrypt, Decrypt, Hash, Verify)
   ========================================================================== */

function initForms() {
    // ── Download Button Handlers (User Gesture Driven) ──
    const btnDownEnc = document.getElementById("btn-download-encrypted");
    if (btnDownEnc) {
        btnDownEnc.addEventListener("click", e => {
            e.preventDefault();
            if (!currentEncryptedResult || !currentEncryptedResult.blob) {
                showToast("No encrypted file available to download. Please encrypt a file first.", true);
                return;
            }
            downloadBlob(currentEncryptedResult.blob, currentEncryptedResult.filename);
            showToast(`✓ Downloaded ${currentEncryptedResult.filename}`);
        });
    }

    const btnDownDec = document.getElementById("btn-download-decrypted");
    if (btnDownDec) {
        btnDownDec.addEventListener("click", e => {
            e.preventDefault();
            if (!currentDecryptedResult || !currentDecryptedResult.blob) {
                showToast("No decrypted file available to download. Please decrypt a file first.", true);
                return;
            }
            downloadBlob(currentDecryptedResult.blob, currentDecryptedResult.filename);
            showToast(`✓ Downloaded ${currentDecryptedResult.filename}`);
        });
    }

    // ── 1. Encrypt Form ──
    const encForm = document.getElementById("encrypt-form");
    if (encForm) {
        encForm.addEventListener("submit", async e => {
            e.preventDefault();
            const fileInput = document.getElementById("encrypt-file-input");
            const pwInput = document.getElementById("encrypt-password");
            const confirmInput = document.getElementById("encrypt-confirm-password");
            const btn = document.getElementById("btn-encrypt-submit");

            if (!fileInput.files || fileInput.files.length === 0) {
                showToast("Please choose a file to encrypt.", true);
                return;
            }
            if (!pwInput.value) {
                showToast("Password cannot be empty.", true);
                return;
            }
            if (pwInput.value !== confirmInput.value) {
                showToast("Passwords do not match.", true);
                return;
            }

            setLoading(btn, true);
            const formData = new FormData();
            formData.append("file", fileInput.files[0]);
            formData.append("password", pwInput.value);

            try {
                const response = await fetch("/api/encrypt", {
                    method: "POST",
                    body: formData,
                });

                if (!response.ok) {
                    const errText = await response.text();
                    let errMsg = "Encryption failed.";
                    try {
                        const json = JSON.parse(errText);
                        errMsg = json.error || errMsg;
                    } catch (_) {}
                    throw new Error(errMsg);
                }

                // Read binary response directly as Blob
                const blob = await response.blob();
                if (!blob || blob.size === 0) {
                    throw new Error("Received empty encrypted payload from server.");
                }

                // Extract metadata and filename
                const originalFile = fileInput.files[0];
                const originalName = response.headers.get("X-Original-Filename") || originalFile.name;
                let encryptedName = response.headers.get("X-Encrypted-Filename");
                if (!encryptedName) {
                    encryptedName = extractFilenameFromResponse(response, originalName + ".sfe");
                }
                if (!encryptedName.endsWith(".sfe")) {
                    encryptedName = encryptedName + ".sfe";
                }

                const originalHash = response.headers.get("X-Original-Hash") || "";
                const originalSize = parseInt(response.headers.get("X-Original-Size") || originalFile.size, 10);
                const encryptedSize = blob.size;

                // Retain actual encrypted Blob and intended filename in frontend state
                currentEncryptedResult = {
                    blob: blob,
                    filename: encryptedName,
                    originalName: originalName,
                    originalHash: originalHash,
                    originalSize: originalSize,
                    encryptedSize: encryptedSize,
                };

                // Render Security Report
                renderEncryptSuccess(currentEncryptedResult);
                showToast(`✓ Encrypted! Click "Download Encrypted File (.sfe)" to save.`);
            } catch (err) {
                showToast(err.message, true);
            } finally {
                setLoading(btn, false);
            }
        });
    }

    // ── 2. Decrypt Form ──
    const decForm = document.getElementById("decrypt-form");
    if (decForm) {
        decForm.addEventListener("submit", async e => {
            e.preventDefault();
            const fileInput = document.getElementById("decrypt-file-input");
            const pwInput = document.getElementById("decrypt-password");
            const btn = document.getElementById("btn-decrypt-submit");

            if (!fileInput.files || fileInput.files.length === 0) {
                showToast("Please choose an .sfe file to decrypt.", true);
                return;
            }
            if (!pwInput.value) {
                showToast("Password cannot be empty.", true);
                return;
            }

            setLoading(btn, true);
            const formData = new FormData();
            formData.append("file", fileInput.files[0]);
            formData.append("password", pwInput.value);

            try {
                const response = await fetch("/api/decrypt", {
                    method: "POST",
                    body: formData,
                });

                if (!response.ok) {
                    const errText = await response.text();
                    let errMsg = "Decryption failed. The password may be incorrect or the encrypted file may have been modified.";
                    try {
                        const json = JSON.parse(errText);
                        errMsg = json.error || errMsg;
                    } catch (_) {}
                    renderDecryptError(errMsg);
                    showToast("✗ Decryption failed.", true);
                    return;
                }

                // Read binary response directly as Blob
                const blob = await response.blob();
                if (!blob || blob.size === 0) {
                    throw new Error("Received empty decrypted payload from server.");
                }

                // Extract original filename
                let originalName = response.headers.get("X-Original-Filename");
                if (!originalName) {
                    originalName = extractFilenameFromResponse(response, "");
                }
                if (!originalName) {
                    originalName = fileInput.files[0].name.replace(/\.sfe$/i, "") || "decrypted_file";
                }

                const originalHash = response.headers.get("X-Original-Hash") || "";
                const fileSize = blob.size;

                // Retain actual recovered Blob and original filename in frontend state
                currentDecryptedResult = {
                    blob: blob,
                    filename: originalName,
                    originalHash: originalHash,
                    file_size: fileSize,
                };

                // Render Security Report
                renderDecryptSuccess(currentDecryptedResult);
                showToast(`✓ Decrypted! Click "Download Original File" to save.`);
            } catch (err) {
                renderDecryptError(err.message);
                showToast("✗ Decryption failed.", true);
            } finally {
                setLoading(btn, false);
            }
        });
    }

    // ── 3. Hash Form ──
    const hashForm = document.getElementById("hash-form");
    if (hashForm) {
        hashForm.addEventListener("submit", async e => {
            e.preventDefault();
            const fileInput = document.getElementById("hash-file-input");
            const btn = document.getElementById("btn-hash-submit");

            if (!fileInput.files || fileInput.files.length === 0) {
                showToast("Please choose a file to hash.", true);
                return;
            }

            setLoading(btn, true);
            const formData = new FormData();
            formData.append("file", fileInput.files[0]);

            try {
                const response = await fetch("/api/hash", { method: "POST", body: formData });
                const result = await response.json();
                if (!response.ok || !result.success) {
                    throw new Error(result.error || "Hashing failed.");
                }
                document.getElementById("calc-hash-value").textContent = result.sha256;
                document.getElementById("hash-output-box").classList.remove("hidden");
                showToast("✓ SHA-256 hash generated!");
            } catch (err) {
                showToast(err.message, true);
            } finally {
                setLoading(btn, false);
            }
        });
    }

    // ── 4. Verify Form ──
    const verifyForm = document.getElementById("verify-form");
    if (verifyForm) {
        verifyForm.addEventListener("submit", async e => {
            e.preventDefault();
            const fileInput = document.getElementById("verify-file-input");
            const refInput = document.getElementById("reference-hash-input");
            const btn = document.getElementById("btn-verify-submit");

            if (!fileInput.files || fileInput.files.length === 0) {
                showToast("Please choose a file to verify.", true);
                return;
            }
            if (!refInput.value.trim()) {
                showToast("Please enter a reference SHA-256 hash.", true);
                return;
            }

            setLoading(btn, true);
            const formData = new FormData();
            formData.append("file", fileInput.files[0]);
            formData.append("reference_hash", refInput.value.trim());

            try {
                const response = await fetch("/api/verify", { method: "POST", body: formData });
                const result = await response.json();
                if (!response.ok || !result.success) {
                    throw new Error(result.error || "Verification request failed.");
                }
                renderVerifyResult(result);
            } catch (err) {
                showToast(err.message, true);
            } finally {
                setLoading(btn, false);
            }
        });
    }
}

/* ==========================================================================
   UI Renderers
   ========================================================================== */

function renderEncryptSuccess(data) {
    document.getElementById("encrypt-placeholder").classList.add("hidden");
    document.getElementById("encrypt-result-content").classList.remove("hidden");

    document.getElementById("rep-enc-file").textContent = data.originalName || data.filename;
    document.getElementById("rep-enc-size").textContent = formatBytes(data.originalSize);
    document.getElementById("rep-enc-encsize").textContent = formatBytes(data.encryptedSize);
    document.getElementById("enc-result-hash").textContent = data.originalHash;
}

function renderDecryptSuccess(data) {
    document.getElementById("decrypt-placeholder").classList.add("hidden");
    document.getElementById("decrypt-error-content").classList.add("hidden");
    document.getElementById("decrypt-result-content").classList.remove("hidden");

    document.getElementById("rep-dec-file").textContent = data.filename;
    document.getElementById("rep-dec-size").textContent = formatBytes(data.file_size);
    document.getElementById("dec-result-hash").textContent = data.originalHash;
    const decBtnSpan = document.getElementById("dec-btn-filename");
    if (decBtnSpan) decBtnSpan.textContent = data.filename;
}

function renderDecryptError(message) {
    document.getElementById("decrypt-placeholder").classList.add("hidden");
    document.getElementById("decrypt-result-content").classList.add("hidden");
    const errBox = document.getElementById("decrypt-error-content");
    const errMsg = document.getElementById("decrypt-error-msg");
    if (errMsg) errMsg.textContent = message;
    errBox.classList.remove("hidden");
}

function renderVerifyResult(data) {
    const resBox = document.getElementById("verify-result-box");
    const bannerSuccess = document.getElementById("verify-banner-success");
    const bannerError = document.getElementById("verify-banner-error");

    resBox.classList.remove("hidden");
    if (data.verified) {
        bannerSuccess.classList.remove("hidden");
        bannerError.classList.add("hidden");
        document.getElementById("rep-ver-status").textContent = "✓ Verified (Identical)";
        document.getElementById("rep-ver-status").className = "val text-success";
    } else {
        bannerSuccess.classList.add("hidden");
        bannerError.classList.remove("hidden");
        document.getElementById("rep-ver-status").textContent = "✗ Integrity Check Failed";
        document.getElementById("rep-ver-status").className = "val text-danger";
    }
    document.getElementById("rep-ver-file").textContent = data.filename;
    document.getElementById("rep-ver-ref").textContent = data.reference_hash;
    document.getElementById("rep-ver-cur").textContent = data.current_hash;
}

/* ==========================================================================
   Robust In-Memory Blob File Download
   Downloads binary Blob with intended filename strictly triggered by
   user click gesture. Zero UUIDs, zero synthetic programmatic clicks on
   unprompted actions.
   ========================================================================== */

function downloadBlob(blob, filename) {
    if (!blob) {
        showToast("Error: No file data found to download.", true);
        return;
    }
    const objectUrl = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = objectUrl;
    a.download = filename;
    a.setAttribute("download", filename);
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
        if (a.parentNode) {
            a.parentNode.removeChild(a);
        }
        URL.revokeObjectURL(objectUrl);
    }, 1500);
}

function extractFilenameFromResponse(response, fallbackName) {
    if (!response) return fallbackName;

    // 1. Try custom headers
    const encHeader = response.headers.get("X-Encrypted-Filename");
    if (encHeader) return encHeader.trim();

    const origHeader = response.headers.get("X-Original-Filename");
    if (origHeader) return origHeader.trim();

    // 2. Parse Content-Disposition header (RFC 6266 / RFC 5987)
    const disposition = response.headers.get("Content-Disposition");
    if (disposition) {
        // UTF-8 filename (filename*=UTF-8''...)
        const utf8Match = disposition.match(/filename\*=UTF-8''([^;]+)/i);
        if (utf8Match && utf8Match[1]) {
            try {
                return decodeURIComponent(utf8Match[1].trim());
            } catch (_) {}
        }
        // Quoted filename (filename="...")
        const quotedMatch = disposition.match(/filename="([^"]+)"/i);
        if (quotedMatch && quotedMatch[1]) {
            return quotedMatch[1].trim();
        }
        // Simple unquoted filename (filename=...)
        const simpleMatch = disposition.match(/filename=([^; ]+)/i);
        if (simpleMatch && simpleMatch[1]) {
            return simpleMatch[1].trim();
        }
    }

    return fallbackName;
}

/* ==========================================================================
   Utility Functions
   ========================================================================== */

function copyText(elementId, btn) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const text = el.textContent.trim();
    navigator.clipboard.writeText(text).then(() => {
        const orig = btn.textContent;
        btn.textContent = "✓ Copied!";
        setTimeout(() => { btn.textContent = orig; }, 2000);
    }).catch(err => {
        console.error("Clipboard copy failed:", err);
    });
}

function setLoading(button, isLoading) {
    if (!button) return;
    const btnText = button.querySelector(".btn-text");
    const spinner = button.querySelector(".spinner");
    if (isLoading) {
        button.disabled = true;
        if (btnText) btnText.style.opacity = "0.5";
        if (spinner) spinner.classList.remove("hidden");
    } else {
        button.disabled = false;
        if (btnText) btnText.style.opacity = "1";
        if (spinner) spinner.classList.add("hidden");
    }
}

function showToast(message, isError = false) {
    const toast = document.getElementById("toast");
    if (!toast) return;
    toast.textContent = message;
    toast.className = isError ? "toast error" : "toast";
    toast.style.borderColor = isError ? "var(--accent-rose)" : "var(--accent-cyan)";
    toast.style.boxShadow = isError ? "var(--shadow-rose)" : "var(--shadow-glow)";
    toast.classList.remove("hidden");
    setTimeout(() => { toast.classList.add("hidden"); }, 4000);
}
