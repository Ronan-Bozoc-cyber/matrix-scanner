// =====================================================================================
// MATRIX SCANNER - script.js
// =====================================================================================

// --- ÉTAT GLOBAL DE SCAN & CHRONOMÈTRE ---
window.isScanning = false;
let scanStartTime = 0;
let stopwatchInterval = null;

function setScanningState(state, toolName = "", currentStep = "", totalSteps = "") {
  window.isScanning = state;
  const overlay = document.getElementById('navigation-lock-overlay');
  const stickyBar = document.getElementById('sticky-progress-bar');
  const stickyText = document.getElementById('sticky-progress-text');
  const stickySteps = document.getElementById('sticky-progress-steps');
  const stopwatchContainer = document.getElementById('sticky-progress-stopwatch');
  const stopwatchText = stopwatchContainer ? stopwatchContainer.querySelector('span') : null;
  const loader = document.getElementById('sticky-loader');
  const closeBtn = document.getElementById('sticky-close-btn');

  if (state) {
    if (overlay) overlay.classList.remove('hidden');
    if (stickyBar) {
      stickyBar.classList.remove('hidden');
      stickyBar.style.borderTopColor = 'var(--matrix-green)';
    }
    if (stickyText) {
      stickyText.textContent = toolName + " en cours...";
      stickyText.style.color = 'var(--matrix-green)';
    }
    if (stickySteps && currentStep && totalSteps) stickySteps.textContent = `Étape ${currentStep}/${totalSteps}`;
    if (loader) loader.style.display = 'block';
    if (closeBtn) closeBtn.classList.add('hidden');
    if (stopwatchContainer) stopwatchContainer.style.color = '#fff';

    if (!stopwatchInterval && stopwatchText) {
      scanStartTime = Date.now();
      stopwatchText.textContent = "00:00:00";
      stopwatchInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
        const h = String(Math.floor(elapsed / 3600)).padStart(2, '0');
        const m = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0');
        const s = String(elapsed % 60).padStart(2, '0');
        stopwatchText.textContent = `${h}:${m}:${s}`;
      }, 1000);
    }
  } else {
    if (overlay) overlay.classList.add('hidden');
    if (stopwatchInterval) {
      clearInterval(stopwatchInterval);
      stopwatchInterval = null;
    }
    if (stickyText) {
      stickyText.textContent = "✅ Scan terminé.";
      stickyText.style.color = '#00ff41';
    }
    if (stickyBar) stickyBar.style.borderTopColor = '#00ff41';
    if (loader) loader.style.display = 'none';
    if (stopwatchContainer) stopwatchContainer.style.color = '#00ff41';
    if (closeBtn) {
      closeBtn.classList.remove('hidden');
      closeBtn.onclick = () => {
        if (stickyBar) stickyBar.classList.add('hidden');
      };
    }
  }
}

// Navigation Lock
document.addEventListener('DOMContentLoaded', () => {
  setScanningState(false);

  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
      if (window.isScanning) {
        e.preventDefault();
        const overlayBox = document.querySelector('#navigation-lock-overlay > div');
        if (overlayBox) {
          overlayBox.style.transform = 'scale(1.08)';
          overlayBox.style.backgroundColor = 'rgba(120, 0, 0, 0.95)';
          overlayBox.style.boxShadow = '0 4px 30px rgba(255, 0, 0, 0.9)';
          setTimeout(() => {
            overlayBox.style.transform = 'scale(1)';
            overlayBox.style.backgroundColor = 'rgba(20, 0, 0, 0.92)';
            overlayBox.style.boxShadow = '0 4px 20px rgba(255, 0, 0, 0.5)';
          }, 250);
        }
      }
    });
  });

  initMatrixRain();
  initModeSelectorButtons();
  initScanHandlers();
  initSettingsHandlers();
  initHistoryHandlers();
  initStopScanHandler();
  initSystemMonitor();
  initRealtimeClock();

  // If on home page with deps-card, run checkDependencies
  if (document.getElementById("deps-card")) {
    checkDependencies();
  }
});

/* -------------------------------------------------------------------------------
 * 1. ANIMATION MATRIX RAIN
 * ------------------------------------------------------------------------------- */
function initMatrixRain() {
  const canvas = document.getElementById("matrix-bg");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const chars = "アカサタナハマヤラワ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  let columns, drops;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    columns = Math.floor(canvas.width / 16);
    drops = new Array(columns).fill(1);
  }
  window.addEventListener("resize", resize);
  resize();

  function draw() {
    ctx.fillStyle = "rgba(0, 0, 0, 0.06)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = "#00ff41";
    ctx.font = "14px monospace";

    for (let i = 0; i < drops.length; i++) {
      const char = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(char, i * 16, drops[i] * 16);

      if (drops[i] * 16 > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i]++;
    }
  }
  setInterval(draw, 45);
}

/* -------------------------------------------------------------------------------
 * 2. PRÉREQUIS SYSTÈME (DEPENDENCIES)
 * ------------------------------------------------------------------------------- */
async function checkDependencies() {
  const listEl = document.getElementById("deps-list");
  const missingAlert = document.getElementById("deps-missing-alert");
  if (!listEl) return;

  try {
    const res = await fetch("/api/check-deps");
    const data = await res.json();

    const toolEntries = Object.entries(data.tools);
    const totalCount = toolEntries.length;
    const installedCount = toolEntries.filter(([_, info]) => info.installed).length;
    const missingCount = totalCount - installedCount;

    listEl.innerHTML = "";

    const counterDiv = document.createElement("div");
    counterDiv.style.width = "100%";
    counterDiv.style.marginBottom = "16px";
    counterDiv.style.fontSize = "0.95rem";
    counterDiv.style.color = "#fff";
    counterDiv.style.padding = "10px 14px";
    counterDiv.style.background = "rgba(0,0,0,0.4)";
    counterDiv.style.border = "1px solid rgba(0, 255, 65, 0.3)";
    counterDiv.style.borderRadius = "6px";
    counterDiv.innerHTML = `
      <span style="font-weight: bold;"><i class="fa-solid fa-microchip"></i> Statut global du système : <b>${installedCount}/${totalCount}</b> outils installés et prêts.</span>
      ${missingCount > 0 ? `<span style="color:#ff5555; margin-left:12px; font-weight: bold;">⚠️ (<b>${missingCount}</b> outil(s) manquant(s))</span>` : `<span style="color:#00ff41; margin-left:12px; font-weight: bold;"><i class="fa-solid fa-circle-check"></i> Tous les ${totalCount} outils sont prêts !</span>`}
    `;
    listEl.appendChild(counterDiv);

    // Groupement par rubriques
    const categoriesMap = {};
    toolEntries.forEach(([name, info]) => {
      const cat = info.category || "Divers / Système";
      if (!categoriesMap[cat]) categoriesMap[cat] = [];
      categoriesMap[cat].push({ name, ...info });
    });

    const categoryOrder = [
      "Reconnaissance & OSINT",
      "Scans Réseau & Exploration LAN",
      "Audit Web & CMS Spécifiques",
      "Fuzzing & Recherche de Vulnérabilités",
      "Audit & Injections Bases de Données",
      "Rendus Visuels, Rapports & Télémétrie"
    ];

    Object.keys(categoriesMap).forEach(catName => {
      if (!categoryOrder.includes(catName)) {
        categoryOrder.push(catName);
      }
    });

    categoryOrder.forEach(catName => {
      if (!categoriesMap[catName]) return;

      const catHeader = document.createElement("div");
      catHeader.style.width = "100%";
      catHeader.style.marginTop = "14px";
      catHeader.style.marginBottom = "8px";
      catHeader.style.color = "#00ff41";
      catHeader.style.fontSize = "0.85rem";
      catHeader.style.fontWeight = "bold";
      catHeader.style.textTransform = "uppercase";
      catHeader.style.letterSpacing = "1px";
      catHeader.style.borderBottom = "1px solid rgba(0, 255, 65, 0.2)";
      catHeader.style.paddingBottom = "4px";
      catHeader.innerHTML = `<i class="fa-solid fa-layer-group"></i> ${catName}`;
      listEl.appendChild(catHeader);

      // Tri par ordre alphabétique au sein de la rubrique
      const toolsInCat = categoriesMap[catName].sort((a, b) => a.name.localeCompare(b.name, 'fr', { sensitivity: 'base' }));

      const gridDiv = document.createElement("div");
      gridDiv.className = "deps-grid";
      gridDiv.style.display = "grid";
      gridDiv.style.gridTemplateColumns = "repeat(auto-fit, minmax(280px, 1fr))";
      gridDiv.style.gap = "8px";
      gridDiv.style.marginBottom = "10px";

      toolsInCat.forEach(tool => {
        const item = document.createElement("div");
        item.className = "dep-item " + (tool.installed ? "ok" : "missing");
        item.style.margin = "0";
        item.style.padding = "6px 10px";
        item.style.fontSize = "0.8rem";
        item.innerHTML = `
          <span style="font-weight: bold; font-family: monospace;">${tool.installed ? "✔" : "✘"} ${tool.name}</span>
          <span style="color: #aaa; font-size: 0.75rem; display: block; margin-top: 2px;">${tool.description}</span>
        `;
        gridDiv.appendChild(item);
      });

      listEl.appendChild(gridDiv);
    });

    if (missingAlert) {
      if (!data.all_installed) {
        missingAlert.classList.remove("hidden");
        missingAlert.dataset.packages = JSON.stringify(data.missing_apt_packages);
      } else {
        missingAlert.classList.add("hidden");
      }
    }
  } catch (err) {
    listEl.textContent = "Erreur lors de la vérification des dépendances : " + err.message;
  }
}

document.getElementById("install-btn")?.addEventListener("click", async () => {
  const btn = document.getElementById("install-btn");
  const logEl = document.getElementById("install-log");
  const missingAlert = document.getElementById("deps-missing-alert");
  const packages = JSON.parse(missingAlert.dataset.packages || "[]");

  btn.disabled = true;
  btn.textContent = "⏳ Authentification système en cours (une fenêtre va s'ouvrir)...";
  logEl.classList.remove("hidden");
  logEl.textContent = "";

  try {
    const startRes = await fetch("/api/install-deps", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ packages }),
    });
    
    let startData;
    const contentType = startRes.headers.get("content-type");
    if (contentType && contentType.includes("application/json")) {
      startData = await startRes.json();
    } else {
      const text = await startRes.text();
      logEl.textContent = `Erreur réseau/serveur (${startRes.status}) : ${text.substring(0, 150)}`;
      btn.disabled = false;
      btn.textContent = "⚡ Installer les dépendances";
      return;
    }

    if (startRes.status !== 200) {
      logEl.textContent = "Erreur : " + (startData.error || "inconnue");
      btn.disabled = false;
      btn.textContent = "⚡ Installer les dépendances";
      return;
    }

    const poll = setInterval(async () => {
      const statusRes = await fetch("/api/install-status");
      const status = await statusRes.json();
      logEl.textContent = status.log;
      logEl.scrollTop = logEl.scrollHeight;

      if (!status.running && status.finished_at) {
        clearInterval(poll);
        btn.disabled = false;
        btn.textContent = "⚡ Installer les dépendances";
        if (status.success) {
          logEl.textContent += "\n\n[✔ Installation terminée avec succès]";
          setTimeout(checkDependencies, 1000);
        } else {
          logEl.textContent += "\n\n[✘ L'installation a échoué ou a été annulée]";
        }
      }
    }, 1500);
  } catch (err) {
    logEl.textContent = "Erreur réseau : " + err.message;
    btn.disabled = false;
    btn.textContent = "⚡ Installer les dépendances";
  }
});

/* -------------------------------------------------------------------------------
 * 3. GESTION DES MODES (AUTOMATIQUE / MANUEL)
 * ------------------------------------------------------------------------------- */
function initModeSelectorButtons() {
  document.querySelectorAll('.mode-selector-buttons .btn-mode').forEach(btn => {
    btn.addEventListener('click', function() {
      const container = this.closest('.mode-selector-buttons');
      container.querySelectorAll('.btn-mode').forEach(b => b.classList.remove('active'));
      this.classList.add('active');

      const targetToggleId = container.dataset.targetToggle;
      const hiddenInput = document.getElementById(targetToggleId);
      const mode = this.dataset.mode;
      if (hiddenInput) hiddenInput.value = mode;

      const manualSettings = document.getElementById('shared-manual-settings');
      if (manualSettings) {
        if (mode === 'manual') {
          manualSettings.classList.remove('hidden');
        } else {
          manualSettings.classList.add('hidden');
        }
      }
    });
  });
}

function collectOptions() {
  const getVal = id => document.getElementById(id)?.value || "";
  const getChecked = id => document.getElementById(id)?.checked || false;

  return {
    scan_type: getVal("scan_type") || "sS",
    port_mode: getVal("port_mode") || "top_1000",
    custom_ports: getVal("custom_ports") || "",
    timing: getVal("timing") || "3",
    service_version: getChecked("service_version"),
    os_detection: getChecked("os_detection"),
    default_scripts: getChecked("default_scripts"),
    vuln_scripts: getChecked("vuln_scripts"),
    vulners_script: getChecked("vulners_script"),
    aggressive_scan: getChecked("aggressive_scan"),
    skip_host_discovery: getChecked("skip_host_discovery")
  };
}

/* -------------------------------------------------------------------------------
 * 4. HANDLERS DE SCAN (WEB & LOCAL)
 * ------------------------------------------------------------------------------- */
function initScanHandlers() {
  // Web Pentest
  const btnWeb = document.getElementById("btn-scan-web");
  if (btnWeb) {
    btnWeb.addEventListener("click", () => startScan("web"));
  }

  // Local Pentest
  const btnLocal = document.getElementById("btn-scan-local");
  if (btnLocal) {
    btnLocal.addEventListener("click", () => startScan("local"));
  }
}

async function startScan(mode, customTarget = null) {
  const targetInput = document.getElementById(mode === "web" ? "target-web" : "target-local");
  const target = customTarget || (targetInput ? targetInput.value.trim() : "");
  const errorBox = document.getElementById("scan-error");
  const progressBox = document.getElementById("scan-progress");
  const previewBox = document.getElementById("command-preview");
  const terminalBox = document.getElementById("scan-terminal");
  const terminalContent = document.getElementById("scan-terminal-content");
  const netdiscoverCard = document.getElementById("netdiscover-card");

  if (!target) {
    if (errorBox) {
      errorBox.textContent = "Veuillez saisir une cible valide.";
      errorBox.classList.remove("hidden");
    }
    return;
  }

  if (errorBox) errorBox.classList.add("hidden");
  document.getElementById("results-card")?.classList.add("hidden");
  document.getElementById("cve-card")?.classList.add("hidden");
  
  // Masquer netdiscoverCard uniquement si c'est un nouveau scan depuis le formulaire principal
  if (!customTarget && netdiscoverCard) netdiscoverCard.classList.add("hidden");

  const modeToggle = document.getElementById(`mode-toggle-${mode}`)?.value || "auto";

  // Exécuter Netdiscover uniquement si pas de customTarget et si la cible est un sous-réseau complet (contient '/' ou '-')
  const isSubnet = target.includes("/") || target.includes("-");

  if (!customTarget && mode === "local" && modeToggle === "auto" && isSubnet) {
    // Mode Auto Local sur un réseau complet : Netdiscover puis sélection Nmap
    if (!window.isSudoConfigured) {
      showSudoPrompt(target);
      return;
    }
    runAutoLocalPipeline(target);
    return;
  }

  if (!customTarget && mode === "web") {
    // Pipeline Web Pentest complet : WAF -> Screenshot -> Nmap/WhatWeb/Nuclei
    runWebPentestPipeline(target, modeToggle);
    return;
  }

  // Normal / Manual / Selected Scan via /api/scan
  runNmapScan(target, mode, modeToggle);
}

// =====================================================================================
// GESTIONNAIRE DE MOT DE PASSE SUDO POUR NETDISCOVER
// =====================================================================================

function showSudoPrompt(target) {
  const modal = document.getElementById("modal-sudo-prompt");
  if (!modal) return runAutoLocalPipeline(target); // Fallback

  modal.classList.remove("hidden");
  const input = document.getElementById("prompt-sudo-password");
  if (input) {
    input.value = "";
    setTimeout(() => input.focus(), 100);
  }

  const btnConfirm = document.getElementById("btn-confirm-sudo-prompt");
  const btnCancel = document.getElementById("btn-cancel-sudo-prompt");
  const errBox = document.getElementById("sudo-prompt-error");
  if (errBox) errBox.classList.add("hidden");

  // Clonage pour retirer les anciens écouteurs d'événements
  const newConfirm = btnConfirm.cloneNode(true);
  btnConfirm.parentNode.replaceChild(newConfirm, btnConfirm);
  const newCancel = btnCancel.cloneNode(true);
  btnCancel.parentNode.replaceChild(newCancel, btnCancel);

  newCancel.addEventListener("click", () => {
    modal.classList.add("hidden");
  });

  // Valider si touche Entrée
  if (input) {
    input.onkeydown = (e) => {
      if (e.key === "Enter") newConfirm.click();
    };
  }

  newConfirm.addEventListener("click", async () => {
    const pwd = input ? input.value : "";
    newConfirm.disabled = true;
    newConfirm.textContent = "Vérification...";
    
    try {
      const res = await fetch("/api/settings/sudo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: pwd })
      });
      const data = await res.json();
      
      if (res.status === 200 && data.success) {
        window.isSudoConfigured = true;
        modal.classList.add("hidden");
        runAutoLocalPipeline(target);
      } else {
        if (errBox) {
          errBox.textContent = data.error || "Mot de passe root invalide.";
          errBox.classList.remove("hidden");
        }
      }
    } catch (e) {
      if (errBox) {
        errBox.textContent = "Erreur de communication avec le serveur.";
        errBox.classList.remove("hidden");
      }
    } finally {
      newConfirm.disabled = false;
      newConfirm.innerHTML = `<i class="fa-solid fa-bolt"></i> Lancer l'exploration`;
    }
  });
}

// =====================================================================================
// GESTIONNAIRE DE PAUSE ET CHRONOMÈTRE ANTI-BLOCAGE POUR LA CIBLE
// =====================================================================================

let pauseTimerInterval = null;
let currentPauseState = {
  active: false,
  target: "",
  stepName: "",
  retryCount: 0,
  maxRetries: 3,
  intervalSeconds: 30,
  timeRemaining: 30,
  resumeCallback: null
};

function triggerPauseModal(stepName, target, reasonMsg, resumeCallback) {
  const modal = document.getElementById("modal-scan-pause");
  if (!modal) return;

  const retryIntervalEl = document.getElementById("retry_interval");
  const maxRetriesEl = document.getElementById("max_retries");

  const intervalSec = retryIntervalEl ? parseInt(retryIntervalEl.value, 10) || 30 : 30;
  const maxRetries = maxRetriesEl ? parseInt(maxRetriesEl.value, 10) || 3 : 3;

  currentPauseState = {
    active: true,
    target: target,
    stepName: stepName,
    retryCount: currentPauseState.retryCount + 1,
    maxRetries: maxRetries,
    intervalSeconds: intervalSec,
    timeRemaining: intervalSec,
    resumeCallback: resumeCallback
  };

  const reasonEl = document.getElementById("pause-reason-text");
  const attemptsEl = document.getElementById("pause-attempts-text");

  if (reasonEl) reasonEl.textContent = `${stepName} - ${reasonMsg}`;
  if (attemptsEl) attemptsEl.textContent = `Tentative ${currentPauseState.retryCount} sur ${currentPauseState.maxRetries}`;

  updateCountdownDisplay();
  modal.classList.remove("hidden");

  if (pauseTimerInterval) clearInterval(pauseTimerInterval);

  pauseTimerInterval = setInterval(() => {
    currentPauseState.timeRemaining--;
    updateCountdownDisplay();

    if (currentPauseState.timeRemaining <= 0) {
      clearInterval(pauseTimerInterval);
      testTargetConnectivityNow();
    }
  }, 1000);
}

function updateCountdownDisplay() {
  const countdownEl = document.getElementById("pause-countdown");
  if (!countdownEl) return;
  const mins = Math.floor(currentPauseState.timeRemaining / 60);
  const secs = currentPauseState.timeRemaining % 60;
  const formatted = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
  countdownEl.textContent = formatted;
}

async function testTargetConnectivityNow() {
  if (pauseTimerInterval) clearInterval(pauseTimerInterval);
  const countdownEl = document.getElementById("pause-countdown");
  if (countdownEl) countdownEl.textContent = "Test...";

  try {
    const res = await fetch("/api/check-ping", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: currentPauseState.target })
    });
    const data = await res.json();

    if (data.reachable) {
      closePauseModal();
      if (currentPauseState.resumeCallback) {
        currentPauseState.resumeCallback();
      }
    } else {
      if (currentPauseState.retryCount >= currentPauseState.maxRetries) {
        alert(`La cible ${currentPauseState.target} ne répond pas après ${currentPauseState.maxRetries} essais (${data.error || 'Délai d\'attente dépassé'}).`);
        currentPauseState.timeRemaining = currentPauseState.intervalSeconds;
        updateCountdownDisplay();
      } else {
        triggerPauseModal(currentPauseState.stepName, currentPauseState.target, data.error || "Le serveur cible ne répond pas aux tests ICMP/TCP.", currentPauseState.resumeCallback);
      }
    }
  } catch (err) {
    triggerPauseModal(currentPauseState.stepName, currentPauseState.target, "Erreur réseau lors du test : " + err.message, currentPauseState.resumeCallback);
  }
}

function closePauseModal() {
  if (pauseTimerInterval) clearInterval(pauseTimerInterval);
  const modal = document.getElementById("modal-scan-pause");
  if (modal) modal.classList.add("hidden");
  currentPauseState.active = false;
}

function initPauseModalButtons() {
  const btnRetryNow = document.getElementById("btn-pause-retry-now");
  const btnForceResume = document.getElementById("btn-pause-resume-force");
  const btnCancel = document.getElementById("btn-pause-cancel");

  if (btnRetryNow) btnRetryNow.onclick = () => testTargetConnectivityNow();
  if (btnForceResume) {
    btnForceResume.onclick = () => {
      const cb = currentPauseState.resumeCallback;
      closePauseModal();
      if (cb) cb();
    };
  }
  if (btnCancel) {
    btnCancel.onclick = () => {
      closePauseModal();
      setScanningState(false);
      const progressBox = document.getElementById("scan-progress");
      if (progressBox) progressBox.classList.add("hidden");
    };
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initPauseModalButtons();
});

async function runWebPentestPipeline(target, modeToggle) {
  const whoisCard = document.getElementById("whois-card");
  const whoisProgress = document.getElementById("whois-progress");
  const whoisContent = document.getElementById("whois-results-content");

  const subdomainsCard = document.getElementById("subdomains-card");
  const subdomainsProgress = document.getElementById("subdomains-progress");
  const subdomainsContent = document.getElementById("subdomains-results-content");

  const harvesterCard = document.getElementById("harvester-card");
  const harvesterProgress = document.getElementById("harvester-progress");
  const harvesterContent = document.getElementById("harvester-results-content");
  const harvesterTerminal = document.getElementById("harvester-terminal-content");

  const wafCard = document.getElementById("waf-card");
  const wafProgress = document.getElementById("waf-progress");
  const wafContent = document.getElementById("waf-results-content");

  const screenshotCard = document.getElementById("screenshot-card");
  const screenshotProgress = document.getElementById("screenshot-progress");
  const screenshotContent = document.getElementById("screenshot-results-content");

  const cmsCard = document.getElementById("cms-card");
  const cmsProgress = document.getElementById("cms-progress");
  const cmsContent = document.getElementById("cms-results-content");

  const progressBox = document.getElementById("scan-progress");
  const progressText = document.getElementById("scan-progress-text");

  // Re-masquer anciennes cartes
  document.getElementById("results-card")?.classList.add("hidden");
  document.getElementById("cve-card")?.classList.add("hidden");
  document.getElementById("topology-card")?.classList.add("hidden");
  document.getElementById("netdiscover-card")?.classList.add("hidden");

  setScanningState(true, "Pentest Web Distant en cours...");
  if (progressBox) progressBox.classList.remove("hidden");

  // --- ÉTAPE 1 : ENREGISTREMENT DU DOMAINE (WHOIS) ---
  setScanningState(true, "Consultation du Registre de Domaine (WHOIS)", "1", "7");
  if (progressText) progressText.textContent = "Consultation du Registre de Domaine (WHOIS)...";
  if (whoisCard) whoisCard.classList.remove("hidden");
  if (whoisProgress) whoisProgress.classList.remove("hidden");
  if (whoisContent) whoisContent.innerHTML = "";

  try {
    const wRes = await fetch("/api/whois-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: target })
    });
    const wData = await wRes.json();
    if (whoisProgress) whoisProgress.classList.add("hidden");

    if (wData.error) {
      whoisContent.innerHTML = `<div style="color: #888; font-size: 0.85rem;">Impossible de récupérer le WHOIS (${wData.error}).</div>`;
    } else {
      const nsHtml = (wData.name_servers && wData.name_servers.length > 0)
        ? wData.name_servers.map(n => `<span style="background: rgba(155, 89, 182, 0.2); border: 1px solid #9b59b6; color: #d6a2e8; padding: 2px 8px; border-radius: 3px; font-size: 0.8rem; font-family: monospace; margin-right: 4px;">${n}</span>`).join("")
        : "<span style='color:#aaa;'>Non détecté</span>";

      const statusHtml = (wData.statuses && wData.statuses.length > 0)
        ? wData.statuses.map(s => `<span style="background: rgba(52, 152, 219, 0.15); border: 1px solid #3498db; color: #7ec8ff; padding: 2px 6px; border-radius: 3px; font-size: 0.75rem; margin-right: 4px;">${s}</span>`).join("")
        : "<span style='color:#aaa;'>Aucune restriction</span>";

      whoisContent.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; margin-bottom: 12px;">
          <div style="background: rgba(0,0,0,0.4); border: 1px solid rgba(155, 89, 182, 0.3); padding: 10px; border-radius: 6px;">
            <div style="font-size: 0.75rem; color: #888; text-transform: uppercase;">Domaine Racine</div>
            <div style="font-weight: bold; color: #9b59b6; font-size: 0.95rem; margin-top: 3px;">${wData.domain}</div>
          </div>
          <div style="background: rgba(0,0,0,0.4); border: 1px solid rgba(155, 89, 182, 0.3); padding: 10px; border-radius: 6px;">
            <div style="font-size: 0.75rem; color: #888; text-transform: uppercase;">Registrar (Bureau)</div>
            <div style="font-weight: bold; color: #fff; font-size: 0.9rem; margin-top: 3px;">${wData.registrar}</div>
          </div>
          <div style="background: rgba(0,0,0,0.4); border: 1px solid rgba(155, 89, 182, 0.3); padding: 10px; border-radius: 6px;">
            <div style="font-size: 0.75rem; color: #888; text-transform: uppercase;">Date de Création</div>
            <div style="font-weight: bold; color: #fff; font-size: 0.85rem; margin-top: 3px;">${wData.created_date}</div>
          </div>
          <div style="background: rgba(0,0,0,0.4); border: 1px solid rgba(155, 89, 182, 0.3); padding: 10px; border-radius: 6px;">
            <div style="font-size: 0.75rem; color: #888; text-transform: uppercase;">Dernière Modification</div>
            <div style="font-weight: bold; color: #fff; font-size: 0.85rem; margin-top: 3px;">${wData.updated_date}</div>
          </div>
          <div style="background: rgba(0,0,0,0.4); border: 1px solid rgba(155, 89, 182, 0.3); padding: 10px; border-radius: 6px;">
            <div style="font-size: 0.75rem; color: #888; text-transform: uppercase;">Date d'Expiration</div>
            <div style="font-weight: bold; color: #fff; font-size: 0.85rem; margin-top: 3px;">${wData.expiry_date}</div>
          </div>
          <div style="background: rgba(0,0,0,0.4); border: 1px solid rgba(155, 89, 182, 0.3); padding: 10px; border-radius: 6px;">
            <div style="font-size: 0.75rem; color: #888; text-transform: uppercase;">DNSSEC</div>
            <div style="font-weight: bold; color: #a3e9a4; font-size: 0.85rem; margin-top: 3px;">${wData.dnssec}</div>
          </div>
        </div>

        <div style="margin-top: 10px; font-size: 0.85rem; color: #ccc;">
          <div style="margin-bottom: 6px;"><strong>Serveurs DNS (NS) :</strong> ${nsHtml}</div>
          <div style="margin-bottom: 10px;"><strong>Statuts EPP :</strong> ${statusHtml}</div>
        </div>

        <details style="margin-top: 12px; background: rgba(0,0,0,0.5); border: 1px solid rgba(155, 89, 182, 0.3); border-radius: 6px; padding: 8px;">
          <summary style="cursor: pointer; color: #d6a2e8; font-size: 0.85rem; font-weight: bold;">
            <i class="fa-solid fa-file-lines"></i> Afficher le rapport WHOIS brut complet
          </summary>
          <pre style="margin-top: 8px; font-size: 0.75rem; color: #aaa; white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow-y: auto;">${wData.raw_text || "Non disponible."}</pre>
        </details>
      `;
    }
  } catch (err) {
    if (whoisProgress) whoisProgress.classList.add("hidden");
    if (whoisContent) whoisContent.innerHTML = `<div style="color: #888; font-size: 0.85rem;">Données WHOIS indisponibles (${err.message}).</div>`;
  }

  // --- ÉTAPE 2 : ÉNUMÉRATION SOUS-DOMAINES (Subfinder/Sublist3r/theHarvester) ---
  setScanningState(true, "Énumération OSINT des Sous-domaines (Subfinder/theHarvester)", "2", "7");
  if (progressText) progressText.textContent = "Énumération OSINT des Sous-domaines (Subfinder/theHarvester)...";
  if (subdomainsCard) subdomainsCard.classList.remove("hidden");
  if (subdomainsProgress) subdomainsProgress.classList.remove("hidden");
  if (subdomainsContent) subdomainsContent.innerHTML = "";

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 120000);

    const subRes = await fetch("/api/subdomains-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: target }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    const subData = await subRes.json();
    if (subdomainsProgress) subdomainsProgress.classList.add("hidden");

    if (subRes.status !== 200) {
      subdomainsContent.innerHTML = `<div style="color: #ffaa00; font-size: 0.85rem;">⚠️ Énumération des sous-domaines non disponible (${subData.error || "Erreur serveur"}).</div>`;
    } else if (subData.subdomains && subData.subdomains.length > 0) {
      let subHtml = `
        <div style="font-size: 0.85rem; color: #f1c40f; margin-bottom: 8px; font-weight: bold; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
          <span><i class="fa-solid fa-circle-check"></i> ${subData.count} sous-domaine(s) public(s) découvert(s) via OSINT & DNS :</span>
          ${subData.wildcard_detected ? `<span style="background: rgba(241, 196, 15, 0.2); border: 1px solid #f1c40f; color: #f7dc6f; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem;"><i class="fa-solid fa-filter"></i> Filtre anti-Wildcard DNS actif</span>` : ''}
        </div>
        <div style="max-height: 160px; overflow-y: auto; background: rgba(0,0,0,0.5); border: 1px solid rgba(241, 196, 15, 0.3); padding: 8px; border-radius: 6px;">
          <ul style="margin: 0; padding-left: 20px; font-family: monospace; font-size: 0.85rem; color: #fff;">
      `;
      subData.subdomains.forEach(sd => {
        subHtml += `<li style="margin-bottom: 3px;"><a href="http://${sd}" target="_blank" style="color: #f7dc6f; text-decoration: none;">${sd}</a></li>`;
      });
      subHtml += `</ul></div>`;
      subdomainsContent.innerHTML = subHtml;
    } else {
      let subHtml = `
        <div style="font-size: 0.85rem; color: #aaa;">
          Aucun sous-domaine public supplémentaire identifié par OSINT pour <b>${target}</b>.
          ${subData.wildcard_detected ? `<div style="margin-top: 8px; padding: 6px 10px; background: rgba(241, 196, 15, 0.15); border-left: 3px solid #f1c40f; color: #f7dc6f; font-size: 0.8rem;"><i class="fa-solid fa-filter"></i> <strong>Filtre anti-Wildcard</strong> : les adresses miroirs (*.${subData.domain}) ont été automatiquement filtrées.</div>` : ''}
        </div>
      `;
      subdomainsContent.innerHTML = subHtml;
    }
  } catch (err) {
    if (subdomainsProgress) subdomainsProgress.classList.add("hidden");
    const errMsg = err.name === "AbortError" ? "Délai d'attente dépassé (120s)" : err.message;
    if (subdomainsContent) subdomainsContent.innerHTML = `<div style="color: #aaa; font-size: 0.85rem;">Recherche de sous-domaines non disponible (${errMsg}).</div>`;
    
    // Déclenchement de la modale de pause si timeout ou coupure réseau
    if (err.name === "AbortError" || err.message.includes("NetworkError") || err.message.includes("fetch")) {
      triggerPauseModal("Énumération sous-domaines", target, "La cible n'a pas répondu dans les délais (120s).", () => runWebPentestPipeline(target, modeToggle));
      return;
    }
  }

  // --- ÉTAPE 2.5 : THEHARVESTER (Live Stream) ---
  if (harvesterCard) harvesterCard.classList.remove("hidden");
  if (harvesterProgress) harvesterProgress.classList.remove("hidden");
  if (harvesterContent) harvesterContent.innerHTML = "";
  if (harvesterTerminal) harvesterTerminal.textContent = "Lancement de theHarvester...";

  try {
    const harvRes = await fetch("/api/harvester-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: target })
    });
    const harvData = await harvRes.json();
    
    if (harvRes.status === 200 && harvData.job_id) {
        // Poll for harvester status using the existing scan status endpoint since it writes to SCAN_JOBS
        const result = await pollScanStatus(harvData.job_id, true, "harvester-terminal-content");
        if (harvesterProgress) harvesterProgress.classList.add("hidden");
        
        if (result && result.subdomains && result.subdomains.length > 0) {
            let harvHtml = `
              <div style="font-size: 0.85rem; color: #f39c12; margin-bottom: 8px; font-weight: bold;">
                <i class="fa-solid fa-tractor"></i> ${result.subdomains.length} sous-domaine(s) trouvé(s) par theHarvester :
              </div>
              <div style="max-height: 160px; overflow-y: auto; background: rgba(0,0,0,0.5); border: 1px solid rgba(243, 156, 18, 0.3); padding: 8px; border-radius: 6px;">
                <ul style="margin: 0; padding-left: 20px; font-family: monospace; font-size: 0.85rem; color: #fff;">
            `;
            result.subdomains.forEach(sd => {
              harvHtml += `<li style="margin-bottom: 3px;"><a href="http://${sd}" target="_blank" style="color: #f8c471; text-decoration: none;">${sd}</a></li>`;
            });
            harvHtml += `</ul></div>`;
            harvesterContent.innerHTML = harvHtml;
        } else {
             harvesterContent.innerHTML = `<div style="font-size: 0.85rem; color: #aaa;">Aucun sous-domaine supplémentaire trouvé par theHarvester.</div>`;
        }
    } else {
        if (harvesterProgress) harvesterProgress.classList.add("hidden");
        if (harvesterContent) harvesterContent.innerHTML = `<div style="color: #ffaa00; font-size: 0.85rem;">⚠️ theHarvester non disponible (${harvData.error || "Erreur serveur"}).</div>`;
    }
  } catch (err) {
      if (harvesterProgress) harvesterProgress.classList.add("hidden");
      if (harvesterContent) harvesterContent.innerHTML = `<div style="color: #ffaa00; font-size: 0.85rem;">⚠️ Erreur réseau theHarvester (${err.message}).</div>`;
  }

  // --- ÉTAPE 3 : DÉTECTION WAF (Wafw00f) ---
  setScanningState(true, "Analyse du Pare-Feu Applicatif (Wafw00f)", "3", "7");
  if (progressText) progressText.textContent = "Analyse du Pare-Feu Applicatif (Wafw00f)...";
  if (wafCard) wafCard.classList.remove("hidden");
  if (wafProgress) wafProgress.classList.remove("hidden");
  if (wafContent) wafContent.innerHTML = "";

  try {
    const wafRes = await fetch("/api/waf-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: target })
    });
    const wafData = await wafRes.json();
    if (wafProgress) wafProgress.classList.add("hidden");

    if (wafData.detected) {
      wafContent.innerHTML = `
        <div style="padding: 12px 16px; background: rgba(231, 76, 60, 0.15); border-left: 4px solid #e74c3c; border-radius: 4px; color: #ff9999;">
          <strong>🔴 PARE-FEU WAF DÉTECTÉ :</strong> La cible est protégée par un WAF <b>${wafData.firewall || 'Inconnu'}</b> ${wafData.manufacturer ? `(${wafData.manufacturer})` : ''}.
          <div style="font-size: 0.8rem; color: #ccc; margin-top: 5px;">Les tentatives d'attaque directe ou d'injection pourront être filtrées ou bloquées par cette sécurité.</div>
        </div>
      `;
    } else {
      wafContent.innerHTML = `
        <div style="padding: 12px 16px; background: rgba(46, 204, 113, 0.15); border-left: 4px solid #2ecc71; border-radius: 4px; color: #a3e9a4;">
          <strong>🟢 AUCUN WAF DÉTECTÉ :</strong> Aucun pare-feu applicatif web actif identifié par Wafw00f. La cible semble directement accessible.
        </div>
      `;
    }
  } catch (err) {
    if (wafProgress) wafProgress.classList.add("hidden");
    if (wafContent) wafContent.innerHTML = `<div style="color: #ffaa00; font-size: 0.85rem;">⚠️ Analyse WAF non disponible (${err.message}).</div>`;
  }

  // --- ÉTAPE 4 : CAPTURE D'ÉCRAN SITE WEB (Gowitness) ---
  setScanningState(true, "Prise de vue du site Web (Gowitness)", "4", "7");
  if (progressText) progressText.textContent = "Prise de vue du site Web (Gowitness)...";
  await executeGowitnessScreenshot(target);

  // --- ÉTAPE 5 : EMPREINTE CMS & TECHNOLOGIES WEB (WhatWeb) ---
  setScanningState(true, "Détection des technologies web & CMS (WhatWeb)", "5", "7");
  if (progressText) progressText.textContent = "Détection des technologies web & CMS (WhatWeb)...";
  if (cmsCard) cmsCard.classList.remove("hidden");
  if (cmsProgress) cmsProgress.classList.remove("hidden");
  if (cmsContent) cmsContent.innerHTML = "";

  try {
    const cmsRes = await fetch("/api/whatweb-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: target, options: { aggression: 1 } })
    });
    const cmsData = await cmsRes.json();

    if (cmsRes.status === 200 && cmsData.job_id) {
      const detectedCms = await pollWhatwebJob(cmsData.job_id, cmsProgress, cmsContent);
      window._lastDetectedCms = detectedCms; // Mémorise pour l'étape Audit
    } else {
      window._lastDetectedCms = null;
      if (cmsProgress) cmsProgress.classList.add("hidden");
      if (cmsContent) cmsContent.innerHTML = `<div style="color: #aaa; font-size: 0.85rem;">Empreinte CMS non disponible (${cmsData.error || 'Erreur WhatWeb'}).</div>`;
    }
  } catch (err) {
    window._lastDetectedCms = null;
    if (cmsProgress) cmsProgress.classList.add("hidden");
    if (cmsContent) cmsContent.innerHTML = `<div style="color: #aaa; font-size: 0.85rem;">Détection CMS indisponible (${err.message}).</div>`;
  }

  // --- ÉTAPE 6 : PENTEST DE VULNÉRABILITÉS (Nmap) ---
  setScanningState(true, "Détection des services, ports & vulnérabilités (Nmap)", "6", "7");
  if (progressText) progressText.textContent = "Détection des services, ports & vulnérabilités (Nmap)...";
  await runNmapScan(target, "web", modeToggle);

  // --- ÉTAPE 7 : AUDIT COMPLET (Gobuster + SQLMap + CMS Scanner / Nuclei) ---
  setScanningState(true, "Audit de sécurité approfondi (Gobuster, SQLMap, CMS/Nuclei)", "7", "7");
  if (progressText) progressText.textContent = "Audit de sécurité approfondi (Gobuster, SQLMap, CMS/Nuclei)...";

  // Lancer le scan CMS ou Nuclei (Smart Branching)
  let specializedAuditPromise;
  if (window._lastDetectedCms && window._lastDetectedCms !== "Non identifié / Personnalisé") {
      specializedAuditPromise = runAuditCMSScan(target, window._lastDetectedCms);
  } else {
      specializedAuditPromise = runAuditNuclei(target);
  }
  await Promise.all([specializedAuditPromise]);

  // Gobuster séquentiel
  await runAuditGobuster(target);

  // SQLMap sur l'URL cible
  await runAuditSQLMap(target);

  if (progressText) progressText.textContent = "✅ Pentest Web complet — Toutes les étapes sont terminées.";
  const stickyText = document.getElementById('sticky-progress-text');
  if (stickyText) stickyText.textContent = "✅ Pentest Web complet — Toutes les étapes sont terminées.";
  const stickySteps = document.getElementById('sticky-progress-steps');
  if (stickySteps) stickySteps.textContent = "Terminé";
  setScanningState(false);
}

async function executeGowitnessScreenshot(target) {
  const screenshotCard = document.getElementById("screenshot-card");
  const screenshotProgress = document.getElementById("screenshot-progress");
  const screenshotContent = document.getElementById("screenshot-results-content");

  if (screenshotCard) screenshotCard.classList.remove("hidden");
  if (screenshotProgress) screenshotProgress.classList.remove("hidden");
  if (screenshotContent) screenshotContent.innerHTML = "";

  try {
    const ssRes = await fetch("/api/screenshot", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: target })
    });
    const ssData = await ssRes.json();
    if (screenshotProgress) screenshotProgress.classList.add("hidden");

    if (ssData.screenshot_url) {
      screenshotContent.innerHTML = `
        <div style="text-align: center;">
          <a href="${ssData.screenshot_url}" target="_blank" title="Cliquer pour agrandir l'aperçu">
            <img src="${ssData.screenshot_url}" style="max-width: 100%; max-height: 400px; border: 1px solid #3498db; border-radius: 6px; box-shadow: 0 0 15px rgba(52,152,219,0.3); transition: transform 0.2s;" onmouseover="this.style.transform='scale(1.01)'" onmouseout="this.style.transform='scale(1)'">
          </a>
          <p style="font-size: 0.8rem; color: #aaa; margin-top: 8px;">Aperçu visuel de l'application web rendu par Gowitness (Cliquer pour ouvrir)</p>
        </div>
      `;
    } else {
      screenshotContent.innerHTML = `
        <div style="padding: 12px; background: rgba(241, 196, 15, 0.1); border-left: 3px solid #f1c40f; color: #f7dc6f; font-size: 0.85rem; text-align: left;">
          <strong>⚠️ Capture d'écran indisponible :</strong> ${ssData.error || "Le service web n'a pas répondu à la prise de vue Gowitness."}
          <div style="margin-top: 8px;">
            <button onclick="executeGowitnessScreenshot('${target}')" class="btn btn-small" style="background: rgba(52, 152, 219, 0.2); border: 1px solid #3498db; color: #7ec8ff;">
              <i class="fa-solid fa-rotate-right"></i> Réessayer la capture visuelle
            </button>
          </div>
        </div>
      `;
    }
  } catch (err) {
    if (screenshotProgress) screenshotProgress.classList.add("hidden");
    if (screenshotContent) screenshotContent.innerHTML = `
      <div style="padding: 12px; background: rgba(241, 196, 15, 0.1); border-left: 3px solid #f1c40f; color: #f7dc6f; font-size: 0.85rem; text-align: left;">
        <strong>⚠️ Capture d'écran indisponible :</strong> ${err.message}
        <div style="margin-top: 8px;">
          <button onclick="executeGowitnessScreenshot('${target}')" class="btn btn-small" style="background: rgba(52, 152, 219, 0.2); border: 1px solid #3498db; color: #7ec8ff;">
            <i class="fa-solid fa-rotate-right"></i> Réessayer la capture visuelle
          </button>
        </div>
      </div>
    `;
  }
}

function pollWhatwebJob(jobId, cmsProgress, cmsContent) {
  return new Promise((resolve) => {
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/whatweb-status/${jobId}`);
        const data = await res.json();

        if (data.status === "done") {
          clearInterval(interval);
          if (cmsProgress) cmsProgress.classList.add("hidden");
          const detectedCms = renderWhatWebCmsResults(data.result, cmsContent);
          resolve(detectedCms);
        } else if (data.status === "error") {
          clearInterval(interval);
          if (cmsProgress) cmsProgress.classList.add("hidden");
          if (cmsContent) cmsContent.innerHTML = `<div style="color: #ffaa00; font-size: 0.85rem;">⚠️ ${data.error}</div>`;
          resolve(null);
        }
      } catch (err) {
        clearInterval(interval);
        if (cmsProgress) cmsProgress.classList.add("hidden");
        if (cmsContent) cmsContent.innerHTML = `<div style="color: #888; font-size: 0.85rem;">Erreur de suivi WhatWeb (${err.message}).</div>`;
        resolve(null);
      }
    }, 2000);
  });
}

function renderWhatWebCmsResults(results, cmsContent) {
  if (!cmsContent) return null;
  if (!results || results.length === 0) {
    cmsContent.innerHTML = `<div style="color: #aaa; font-size: 0.85rem;">Aucune technologie ou CMS identifié pour cette cible.</div>`;
    return null;
  }

  const targetData = results[0] || {};
  const plugins = targetData.plugins || {};

  let cmsDetected = "Non identifié / Personnalisé";
  let cmsKey = null; // Clé machine: wordpress, joomla, drupal, moodle
  let phpVersion = "Non détectée";
  let serverInfo = "Non détecté";
  let techBadges = [];

  const KNOWN_CMS = ["wordpress", "joomla", "drupal", "moodle", "prestashop", "shopify", "magento", "typo3", "spip", "ghost", "wix", "squarespace", "bitrix"];
  const SCANNABLE_CMS = ["wordpress", "joomla", "drupal", "moodle"]; // CMS ayant un scanner dédié

  for (const [pluginName, pluginInfo] of Object.entries(plugins)) {
    const nameLower = pluginName.toLowerCase();
    const versionStr = (pluginInfo.version && pluginInfo.version.length > 0) ? pluginInfo.version.join(", ") : "";

    // CMS connus
    if (KNOWN_CMS.includes(nameLower)) {
      cmsDetected = `<strong style="color:#2ecc71;">${pluginName}</strong> ${versionStr ? `(v${versionStr})` : ''}`;
      if (SCANNABLE_CMS.includes(nameLower)) cmsKey = nameLower;
    }

    // PHP
    if (nameLower === "php") {
      phpVersion = versionStr ? `PHP ${versionStr}` : "PHP (Version détectée)";
    }

    // Server
    if (["apache", "nginx", "lighttpd", "microsoft-iis"].includes(nameLower)) {
      serverInfo = `${pluginName} ${versionStr ? `v${versionStr}` : ''}`;
    }

    // Badges généraux
    const badgeText = `${pluginName}${versionStr ? ` (${versionStr})` : ''}`;
    techBadges.push(`<span style="background: rgba(46, 204, 113, 0.15); border: 1px solid #2ecc71; color: #a3e9a4; padding: 3px 8px; border-radius: 4px; font-size: 0.78rem; font-family: monospace; display: inline-block; margin-bottom: 4px; margin-right: 4px;">${badgeText}</span>`);
  }

  const cvesFound = targetData.cves_found || [];
  let cveTableHtml = "";

  if (cvesFound.length > 0) {
    cveTableHtml = `
      <div style="margin-top: 15px; background: rgba(231, 76, 60, 0.08); border: 1px solid rgba(231, 76, 60, 0.3); border-radius: 6px; padding: 12px;">
        <div style="font-size: 0.85rem; color: #ff8888; font-weight: bold; margin-bottom: 8px;">
          <i class="fa-solid fa-bug"></i> ${cvesFound.length} CVE & Exploits Connus Détectés pour les Composants Web :
        </div>
        <table style="width: 100%; border-collapse: collapse; font-size: 0.8rem; color: #fff;">
          <thead>
            <tr style="background: rgba(231, 76, 60, 0.2); color: #ff9999; text-align: left;">
              <th style="padding: 6px 8px;">Composant</th>
              <th style="padding: 6px 8px;">CVSS v3</th>
              <th style="padding: 6px 8px;">Vulnérabilité / Exploit</th>
              <th style="padding: 6px 8px;">Ref / EDB-ID</th>
            </tr>
          </thead>
          <tbody>
    `;

    cvesFound.forEach(item => {
      const isHigh = parseFloat(item.cvss_score) >= 7.0;
      const cvssBg = isHigh ? "background: #e74c3c; color: #fff;" : "background: #f39c12; color: #000;";
      cveTableHtml += `
        <tr style="border-bottom: 1px solid rgba(255,255,255,0.08);">
          <td style="padding: 6px 8px; font-weight: bold; color: #a3e9a4;">${item.plugin} ${item.version || ''}</td>
          <td style="padding: 6px 8px;"><span style="${cvssBg} font-weight: bold; padding: 2px 6px; border-radius: 3px; font-size: 0.75rem;">${item.cvss_score} (${item.severity})</span></td>
          <td style="padding: 6px 8px;">${item.title}</td>
          <td style="padding: 6px 8px; font-family: monospace; color: #3498db;">EDB-${item.edb_id}</td>
        </tr>
      `;
    });

    cveTableHtml += `</tbody></table></div>`;
  }

  cmsContent.innerHTML = `
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; margin-bottom: 12px;">
      <div style="background: rgba(0,0,0,0.4); border: 1px solid rgba(46, 204, 113, 0.3); padding: 10px; border-radius: 6px;">
        <div style="font-size: 0.75rem; color: #888; text-transform: uppercase;">CMS Identifié</div>
        <div style="font-weight: bold; color: #2ecc71; font-size: 0.95rem; margin-top: 3px;">${cmsDetected}</div>
      </div>
      <div style="background: rgba(0,0,0,0.4); border: 1px solid rgba(46, 204, 113, 0.3); padding: 10px; border-radius: 6px;">
        <div style="font-size: 0.75rem; color: #888; text-transform: uppercase;">Version PHP</div>
        <div style="font-weight: bold; color: #fff; font-size: 0.85rem; margin-top: 3px;">${phpVersion}</div>
      </div>
      <div style="background: rgba(0,0,0,0.4); border: 1px solid rgba(46, 204, 113, 0.3); padding: 10px; border-radius: 6px;">
        <div style="font-size: 0.75rem; color: #888; text-transform: uppercase;">Serveur Web</div>
        <div style="font-weight: bold; color: #fff; font-size: 0.85rem; margin-top: 3px;">${serverInfo}</div>
      </div>
    </div>

    <div style="margin-top: 10px;">
      <div style="font-size: 0.85rem; color: #aaa; margin-bottom: 6px;"><strong>Technologies Web Identifiées par WhatWeb (${techBadges.length}) :</strong></div>
      <div>${techBadges.length > 0 ? techBadges.join(" ") : "<span style='color:#888;'>Aucune technologie spécifique détectée</span>"}</div>
    </div>

    ${cveTableHtml}
  `;

  // Retourner la clé CMS machine pour le Smart Branching Audit
  return cmsKey;
}

// =====================================================================================
// AUDIT PHASE — Nikto, Gobuster, SQLMap, CMS-Specific Scanner
// =====================================================================================

function pollAuditJob(jobId, onDone) {
  return new Promise((resolve) => {
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/audit/status/${jobId}`);
        const data = await res.json();
        if (data.status === "done" || data.status === "error") {
          clearInterval(interval);
          resolve(data);
          if (onDone) onDone(data);
        }
      } catch (err) {
        clearInterval(interval);
        resolve({ status: "error", error: err.message });
        if (onDone) onDone({ status: "error", error: err.message });
      }
    }, 2500);
  });
}


async function runAuditGobuster(target) {
  const card = document.getElementById("gobuster-card");
  const progress = document.getElementById("gobuster-progress");
  const content = document.getElementById("gobuster-results-content");
  const progressText = document.getElementById("gobuster-progress-text");

  if (card) card.classList.remove("hidden");
  if (progress) progress.classList.remove("hidden");
  if (progressText) progressText.textContent = "📁 Gobuster — Exploration de répertoires et fichiers cachés (5 min)...";
  if (content) content.innerHTML = "";
  try {
    const res = await fetch("/api/audit/gobuster", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: target })
    });
    const data = await res.json();

    if (res.status === 412) {
      if (progress) progress.classList.add("hidden");
      if (content) content.innerHTML += `<div style="color: #f39c12; font-size: 0.85rem; margin-top: 8px;">⚠️ Gobuster non installé — installez-le via la page Vérification Système.</div>`;
      return;
    }

    if (data.job_id) {
      const result = await pollAuditJob(data.job_id, null);
      if (progress) progress.classList.add("hidden");
      renderGobusterResults(result, content);
    }
  } catch (err) {
    if (progress) progress.classList.add("hidden");
    if (content) content.innerHTML += `<div style="color: #888; font-size: 0.85rem; margin-top: 8px;">Gobuster indisponible (${err.message}).</div>`;
  }
}

function renderGobusterResults(data, container) {
  if (!container) return;
  if (data.status === "error") {
    container.innerHTML += `<div style="color: #e74c3c; font-size: 0.85rem; margin-top: 8px;">❌ Erreur Gobuster : ${data.error}</div>`;
    return;
  }
  const paths = data.found_paths || [];
  const allLines = data.output || [];

  let html = `<div style="margin-top: 10px; padding: 10px 14px; background: rgba(155, 89, 182, 0.08); border-left: 3px solid #8e44ad; border-radius: 4px;">`;
  html += `<div style="font-size: 0.85rem; color: #c39bd3; font-weight: bold; margin-bottom: 8px;"><i class="fa-solid fa-folder-tree"></i> Gobuster — ${paths.length} Chemin(s) Découvert(s)</div>`;

  if (paths.length > 0) {
    html += `<div style="font-family: monospace; font-size: 0.78rem; color: #fff; max-height: 200px; overflow-y: auto; background: rgba(0,0,0,0.4); padding: 8px; border-radius: 4px; margin-bottom: 10px;">`;
    paths.forEach(line => {
      const statusMatch = line.match(/\(Status: (\d+)\)/);
      const status = statusMatch ? parseInt(statusMatch[1]) : 0;
      const color = status === 200 ? "#2ecc71" : status === 301 || status === 302 ? "#f1c40f" : "#aaa";
      html += `<div style="color: ${color}; margin-bottom: 2px;">${escapeHtml(line)}</div>`;
    });
    html += `</div>`;
  } else {
    html += `<div style="color: #888; font-size: 0.83rem; margin-bottom: 10px;"><i class="fa-solid fa-check"></i> Aucun répertoire ou fichier caché découvert.</div>`;
  }
  
  if (allLines.length > 0) {
    html += `
      <details style="margin-top: 5px;">
        <summary style="cursor: pointer; font-size: 0.78rem; color: #8e44ad; user-select: none;"><i class="fa-solid fa-terminal"></i> Voir les retours complets de la console</summary>
        <div style="font-family: monospace; font-size: 0.7rem; color: #aaa; max-height: 250px; overflow-y: auto; background: rgba(0,0,0,0.5); padding: 8px; border-radius: 4px; margin-top: 8px; white-space: pre-wrap;">${escapeHtml(allLines.join("\n"))}</div>
      </details>
    `;
  }
  html += `</div>`;
  container.innerHTML += html;
}

async function runAuditSQLMap(target) {
  const card = document.getElementById("db-audit-card");
  const progress = document.getElementById("db-audit-progress");
  const content = document.getElementById("db-audit-results-content");
  const progressText = document.getElementById("db-audit-progress-text");

  if (card) card.classList.remove("hidden");
  if (progress) progress.classList.remove("hidden");
  if (progressText) progressText.textContent = "💉 SQLMap — Analyse d'injections SQL sur la cible (3-5 min)...";
  if (content) content.innerHTML = "";

  try {
    const res = await fetch("/api/audit/sqlmap", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: target })
    });
    const data = await res.json();

    if (res.status === 412) {
      if (progress) progress.classList.add("hidden");
      if (content) content.innerHTML = `<div style="color: #f39c12; font-size: 0.85rem;">⚠️ SQLMap non installé — installez-le via la page Vérification Système.</div>`;
      return;
    }

    if (data.job_id) {
      const result = await pollAuditJob(data.job_id, null);
      if (progress) progress.classList.add("hidden");
      renderSQLMapResults(result, content);
    }
  } catch (err) {
    if (progress) progress.classList.add("hidden");
    if (content) content.innerHTML = `<div style="color: #888; font-size: 0.85rem;">SQLMap indisponible (${err.message}).</div>`;
  }
}

function renderSQLMapResults(data, container) {
  if (!container) return;
  if (data.status === "error") {
    container.innerHTML = `<div style="color: #e74c3c; font-size: 0.85rem;">❌ Erreur SQLMap : ${data.error}</div>`;
    return;
  }
  const vulns = data.vulnerabilities || [];
  const summary = data.summary_lines || [];
  const allLines = data.output || [];
  const isVulnerable = vulns.length > 0;

  let html = `<div style="padding: 10px 14px; background: rgba(230, 126, 34, 0.08); border-left: 3px solid #e67e22; border-radius: 4px;">`;

  if (isVulnerable) {
    html += `<div style="font-size: 0.85rem; color: #ff8888; font-weight: bold; margin-bottom: 8px;">
      <i class="fa-solid fa-triangle-exclamation"></i> 🚨 ${vulns.length} INJECTION(S) SQL DÉTECTÉE(S)</div>`;
    html += `<div style="font-family: monospace; font-size: 0.78rem; color: #ff9999; background: rgba(231,76,60,0.1); padding: 8px; border-radius: 4px; max-height: 200px; overflow-y: auto; margin-bottom: 10px;">`;
    vulns.forEach(v => { html += `<div style="margin-bottom: 2px;">${escapeHtml(v)}</div>`; });
    html += `</div>`;
  } else {
    html += `<div style="font-size: 0.85rem; color: #2ecc71; font-weight: bold; margin-bottom: 10px;">
      <i class="fa-solid fa-shield-halved"></i> Aucune injection SQL évidente détectée.</div>`;
  }

  if (summary.length > 0 && !isVulnerable) {
    html += `<div style="margin-bottom: 10px; font-size: 0.75rem; color: #e67e22; background: rgba(230, 126, 34, 0.1); padding: 6px; border-radius: 4px;">`;
    html += `<strong>Points notables :</strong><br>`;
    summary.slice(0, 15).forEach(l => { html += `<div>- ${escapeHtml(l)}</div>`; });
    html += `</div>`;
  }

  if (allLines.length > 0) {
    html += `
      <details style="margin-top: 5px;">
        <summary style="cursor: pointer; font-size: 0.78rem; color: #e67e22; user-select: none;"><i class="fa-solid fa-terminal"></i> Voir les retours complets de la console</summary>
        <div style="font-family: monospace; font-size: 0.7rem; color: #aaa; max-height: 250px; overflow-y: auto; background: rgba(0,0,0,0.5); padding: 8px; border-radius: 4px; margin-top: 8px; white-space: pre-wrap;">${escapeHtml(allLines.join("\n"))}</div>
      </details>
    `;
  }

  html += `</div>`;
  container.innerHTML = html;
}

async function runAuditCMSScan(target, cmsKey) {
  const card = document.getElementById("cms-audit-card");
  const progress = document.getElementById("cms-audit-progress");
  const content = document.getElementById("cms-audit-results-content");
  const progressText = document.getElementById("cms-audit-progress-text");
  const titleEl = document.getElementById("cms-audit-title");

  if (!cmsKey) {
    // Pas de CMS reconnu -> on masque la carte
    if (card) card.classList.add("hidden");
    return;
  }

  const cmsLabel = { wordpress: "WordPress", joomla: "Joomla", drupal: "Drupal", moodle: "Moodle" }[cmsKey] || cmsKey;
  const scannerLabel = { wordpress: "WPScan", joomla: "JoomScan", drupal: "Droopescan", moodle: "Moodlescan" }[cmsKey] || "Droopescan";

  if (card) card.classList.remove("hidden");
  if (progress) progress.classList.remove("hidden");
  if (titleEl) titleEl.textContent = `${cmsLabel} — ${scannerLabel}`;
  if (progressText) progressText.textContent = `🔍 ${scannerLabel} — Audit approfondi du CMS ${cmsLabel} en cours...`;
  if (content) content.innerHTML = "";

  try {
    const res = await fetch("/api/audit/cms-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: target, cms_type: cmsKey })
    });
    const data = await res.json();

    if (res.status === 412) {
      if (progress) progress.classList.add("hidden");
      if (content) content.innerHTML = `
        <div style="padding: 12px; background: rgba(241, 196, 15, 0.1); border-left: 3px solid #f1c40f; color: #f7dc6f; font-size: 0.85rem;">
          ⚠️ ${scannerLabel} n'est pas installé. Installez-le depuis la page <strong>Vérification Système</strong>.
        </div>`;
      return;
    }

    if (data.job_id) {
      const result = await pollAuditJob(data.job_id, null);
      if (progress) progress.classList.add("hidden");
      renderCMSScanResults(result, content, cmsLabel, scannerLabel);
    }
  } catch (err) {
    if (progress) progress.classList.add("hidden");
    if (content) content.innerHTML = `<div style="color: #888; font-size: 0.85rem;">Scanner CMS indisponible (${err.message}).</div>`;
  }
}

async function runAuditNuclei(target) {
  const card = document.getElementById("nuclei-audit-card");
  const progress = document.getElementById("nuclei-audit-progress");
  const content = document.getElementById("nuclei-audit-results-content");
  const progressText = document.getElementById("nuclei-audit-progress-text");

  if (card) card.classList.remove("hidden");
  if (progress) progress.classList.remove("hidden");
  if (progressText) progressText.textContent = `⚡ Nuclei — Audit approfondi de failles (Smart Branching Custom) en cours...`;
  if (content) content.innerHTML = "";

  try {
    const res = await fetch("/api/nuclei-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_url: target })
    });
    const data = await res.json();

    if (res.status === 412) {
      if (progress) progress.classList.add("hidden");
      if (content) content.innerHTML = `
        <div style="padding: 12px; background: rgba(241, 196, 15, 0.1); border-left: 3px solid #f1c40f; color: #f7dc6f; font-size: 0.85rem;">
          ⚠️ Nuclei n'est pas installé. Installez-le depuis la page <strong>Vérification Système</strong>.
        </div>`;
      return;
    }

    if (data.job_id) {
      // Use the generic pollScanStatus endpoint because nuclei uses NUCLEI_JOBS internally but pollScanStatus polls SCAN_JOBS.
      // Wait, let's look at app.py: /api/nuclei-status/<job_id> exists. We should write a specific poller or use a simple loop.
      const nucleiResult = await new Promise((resolve) => {
        const interval = setInterval(async () => {
          try {
            const r = await fetch(`/api/nuclei-status/${data.job_id}`);
            const d = await r.json();
            if (d.status === "done" || d.status === "error") {
              clearInterval(interval);
              resolve(d);
            }
          } catch (e) {
            clearInterval(interval);
            resolve({ status: "error", error: e.message });
          }
        }, 2000);
      });

      if (progress) progress.classList.add("hidden");
      
      if (nucleiResult.status === "error") {
        if (content) content.innerHTML = `<div style="color: #e74c3c; font-size: 0.85rem;">❌ Erreur Nuclei : ${nucleiResult.error}</div>`;
      } else {
        const findings = nucleiResult.result || [];
        if (findings.length === 0) {
            content.innerHTML = `<div style="color: #aaa; font-size: 0.85rem;"><i class="fa-solid fa-check"></i> Aucun modèle Nuclei n'a matché. La cible semble saine face aux failles connues.</div>`;
        } else {
            let html = `<div style="padding: 10px 14px; background: rgba(52, 152, 219, 0.08); border-left: 3px solid #3498db; border-radius: 4px;">`;
            html += `<div style="font-size: 0.85rem; color: #7ec8ff; font-weight: bold; margin-bottom: 8px;"><i class="fa-solid fa-bolt"></i> Nuclei — ${findings.length} faille(s) / info(s) détectée(s)</div>`;
            html += `<div style="font-family: monospace; font-size: 0.78rem; color: #fff; max-height: 250px; overflow-y: auto; background: rgba(0,0,0,0.4); padding: 8px; border-radius: 4px; margin-bottom: 10px;">`;
            findings.forEach(finding => {
                let color = "#ddd";
                if (finding.info && finding.info.severity) {
                    const sev = finding.info.severity.toLowerCase();
                    if (sev === "critical" || sev === "high") color = "#ff4444";
                    else if (sev === "medium") color = "#f39c12";
                    else if (sev === "low") color = "#f1c40f";
                    else if (sev === "info") color = "#3498db";
                }
                const name = (finding.info && finding.info.name) ? finding.info.name : finding.template || "Alerte";
                html += `<div style="color: ${color}; margin-bottom: 4px;"><strong>[${(finding.info && finding.info.severity) ? finding.info.severity.toUpperCase() : "INFO"}]</strong> ${name} <span style="color:#aaa;">(${finding.matched_at || target})</span></div>`;
            });
            html += `</div></div>`;
            content.innerHTML = html;
        }
      }
    }
  } catch (err) {
    if (progress) progress.classList.add("hidden");
    if (content) content.innerHTML = `<div style="color: #888; font-size: 0.85rem;">Nuclei indisponible (${err.message}).</div>`;
  }
}

function renderCMSScanResults(data, container, cmsLabel, scannerLabel) {
  if (!container) return;
  if (data.status === "error") {
    container.innerHTML = `<div style="color: #e74c3c; font-size: 0.85rem;">❌ Erreur ${scannerLabel} : ${data.error}</div>`;
    return;
  }
  const lines = data.output || [];
  // Filtrer les lignes significatives pour le résumé
  const keyLines = lines.filter(l => {
    const lower = l.toLowerCase();
    return l.trim() && (
      lower.includes("vulnerab") || lower.includes("plugin") || lower.includes("theme") ||
      lower.includes("user") || lower.includes("version") || lower.includes("cve") ||
      lower.includes("error") || lower.includes("found") || lower.includes("detected") ||
      lower.includes("exploit") || lower.includes("critical") || l.startsWith("[") || l.startsWith("+")
    );
  });

  let html = `<div style="padding: 10px 14px; background: rgba(22, 160, 133, 0.08); border-left: 3px solid #16a085; border-radius: 4px;">`;
  html += `<div style="font-size: 0.85rem; color: #1abc9c; font-weight: bold; margin-bottom: 8px;">
    <i class="fa-solid fa-cube"></i> Résumé Audit ${cmsLabel} — ${keyLines.length} élément(s) notable(s)
  </div>`;

  if (keyLines.length > 0) {
    html += `<div style="font-family: monospace; font-size: 0.78rem; color: #fff; max-height: 250px; overflow-y: auto; background: rgba(0,0,0,0.4); padding: 8px; border-radius: 4px; margin-bottom: 10px;">`;
    keyLines.forEach(line => {
      const lower = line.toLowerCase();
      let color = "#ddd";
      if (lower.includes("vulnerab") || lower.includes("cve") || lower.includes("exploit") || lower.includes("critical")) color = "#ff8888";
      else if (lower.includes("found") || lower.includes("detected") || lower.includes("version")) color = "#f1c40f";
      else if (line.startsWith("+") || lower.includes("plugin") || lower.includes("theme")) color = "#a3e9a4";
      html += `<div style="color: ${color}; margin-bottom: 2px;">${escapeHtml(line)}</div>`;
    });
    html += `</div>`;
  } else {
    html += `<div style="color: #888; font-size: 0.83rem; margin-bottom: 10px;"><i class="fa-solid fa-check"></i> Aucun élément critique ou particulier mis en évidence.</div>`;
  }
  
  if (lines.length > 0) {
    html += `
      <details style="margin-top: 5px;">
        <summary style="cursor: pointer; font-size: 0.78rem; color: #16a085; user-select: none;"><i class="fa-solid fa-terminal"></i> Voir les retours complets de la console</summary>
        <div style="font-family: monospace; font-size: 0.7rem; color: #aaa; max-height: 350px; overflow-y: auto; background: rgba(0,0,0,0.5); padding: 8px; border-radius: 4px; margin-top: 8px; white-space: pre-wrap;">${escapeHtml(lines.join("\n"))}</div>
      </details>
    `;
  }

  html += `</div>`;
  container.innerHTML = html;
}

function escapeHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function runNmapScan(target, mode, modeToggle) {
  const errorBox = document.getElementById("scan-error");
  const progressBox = document.getElementById("scan-progress");
  const terminalBox = document.getElementById("scan-terminal");
  const terminalContent = document.getElementById("scan-terminal-content");

  if (progressBox) progressBox.classList.remove("hidden");
  setScanningState(true, `Scanner Nmap (${mode === "web" ? "Web" : "Local"})`, "1", "7");

  if (terminalBox) terminalBox.classList.remove("hidden");
  if (terminalContent) terminalContent.textContent = "";

  const options = modeToggle === "manual" ? collectOptions() : {
    scan_type: "sS",
    port_mode: mode === "web" ? "all" : "top_1000",
    service_version: true,
    os_detection: false,
    default_scripts: false,
    vuln_scripts: false,
    skip_host_discovery: true,
    max_retries: 2,
    host_timeout: "5m",
    min_rate: mode === "web" ? 3000 : 200
  };
  options.is_local = (mode === "local");

  let use_masscan = false;
  if (mode === "local") {
    const cb = document.getElementById("use-masscan-local");
    if (cb) use_masscan = cb.checked;
  }

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, mode, options, use_masscan }),
    });

    let data;
    const contentType = res.headers.get("content-type");
    if (contentType && contentType.includes("application/json")) {
      data = await res.json();
    } else {
      const text = await res.text();
      throw new Error(`Réponse serveur invalide (${res.status}) : ${text.substring(0, 150)}`);
    }

    if (res.status !== 200) {
      if (errorBox) {
        errorBox.textContent = "Erreur : " + (data.error || "inconnue");
        errorBox.classList.remove("hidden");
      }
      setScanningState(false);
      if (progressBox) progressBox.classList.add("hidden");
      return;
    }

    return pollScanStatus(data.job_id, mode === "web" && modeToggle !== "manual");
  } catch (err) {
    if (errorBox) {
      errorBox.textContent = "Erreur de communication : " + err.message;
      errorBox.classList.remove("hidden");
    }
    setScanningState(false);
    if (progressBox) progressBox.classList.add("hidden");
    return null;
  }
}

async function runAutoLocalPipeline(target) {
  const netdiscoverCard = document.getElementById("netdiscover-card");
  const netdiscoverProgress = document.getElementById("netdiscover-progress");
  const netdiscoverResults = document.getElementById("netdiscover-results");
  const netdiscoverList = document.getElementById("netdiscover-results-list");
  const errorBox = document.getElementById("scan-error");

  setScanningState(true, "Découverte ARP (Netdiscover)");

  if (netdiscoverCard) netdiscoverCard.classList.remove("hidden");
  if (netdiscoverProgress) netdiscoverProgress.classList.remove("hidden");
  if (netdiscoverResults) netdiscoverResults.classList.add("hidden");

  try {
    const res = await fetch("/api/netdiscover-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });
    const data = await res.json();

    if (res.status !== 200) {
      if (errorBox) {
        errorBox.textContent = "Erreur Netdiscover : " + (data.error || "Inconnue");
        errorBox.classList.remove("hidden");
      }
      setScanningState(false);
      if (netdiscoverProgress) netdiscoverProgress.classList.add("hidden");
      return;
    }

    // Poll Netdiscover
    const pollNd = setInterval(async () => {
      try {
        const statusRes = await fetch(`/api/netdiscover-status/${data.job_id}`);
        if (statusRes.status !== 200) {
          clearInterval(pollNd);
          setScanningState(false);
          if (netdiscoverProgress) netdiscoverProgress.classList.add("hidden");
          return;
        }
        const job = await statusRes.json();

        if (job.status === "done") {
          clearInterval(pollNd);
          if (netdiscoverProgress) netdiscoverProgress.classList.add("hidden");
          if (netdiscoverResults) netdiscoverResults.classList.remove("hidden");

          const devices = job.result || [];
          if (netdiscoverList) {
            if (devices.length === 0) {
              netdiscoverList.innerHTML = "<p>Aucun équipement détecté par ARP.</p>";
            } else {
              let html = `
                <div style="margin-bottom: 12px; display: flex; gap: 10px; align-items: center; justify-content: space-between;">
                  <div style="display: flex; gap: 8px;">
                    <button id="btn-select-all-netdiscover" class="btn btn-small" style="background: rgba(0,255,65,0.2); color: #00ff41; border: 1px solid #00ff41; padding: 5px 10px; cursor: pointer;">✔ Tout sélectionner</button>
                    <button id="btn-deselect-all-netdiscover" class="btn btn-small" style="background: rgba(255,255,255,0.1); color: #ccc; border: 1px solid #555; padding: 5px 10px; cursor: pointer;">✘ Tout désélectionner</button>
                  </div>
                  <span style="font-size: 0.85em; color: #aaa;">Sélectionnez les hôtes à scanner avec Nmap</span>
                </div>
                <table class="ports-table">
                  <thead>
                    <tr>
                      <th style="width: 40px; text-align: center;"><input type="checkbox" id="chk-toggle-all-netdiscover" checked style="cursor: pointer;"></th>
                      <th>IP</th>
                      <th>Nom Réseau / NetBIOS</th>
                      <th>Catégorie / Type</th>
                      <th>MAC</th>
                      <th>Constructeur / Marque</th>
                    </tr>
                  </thead>
                  <tbody>`;
              devices.forEach(d => {
                const icon = d.icon || "fa-server";
                const cat = d.category || "Équipement Réseau";
                const hostName = d.hostname || d.netbios_name || "-";
                html += `<tr>
                  <td style="text-align: center;"><input type="checkbox" class="netdiscover-chk" value="${d.ip}" checked style="cursor: pointer;"></td>
                  <td><b>${d.ip}</b></td>
                  <td><span style="color:#00ff41;">${hostName}</span> ${d.workgroup ? `<small style="color:#aaa;">(${d.workgroup})</small>` : ''}</td>
                  <td><i class="fa-solid ${icon}" style="margin-right: 5px; color: #ffaa00;"></i> ${cat}</td>
                  <td style="font-family: monospace; font-size: 0.9em;">${d.mac}</td>
                  <td>${d.vendor}</td>
                </tr>`;
              });
              html += `</tbody></table>
              <button id="btn-scan-selected-netdiscover" class="btn btn-primary btn-large" style="width: 100%; margin-top: 15px; background: #1a5e20; border-color: #1a5e20; box-shadow: 0 0 10px rgba(26,94,32,0.6); color: white; cursor: pointer;">
                ▶ LANCER LE SCAN NMAP SUR LES ÉQUIPEMENTS SÉLECTIONNÉS
              </button>`;

              netdiscoverList.innerHTML = html;
              attachNetdiscoverEvents();
            }
          }
          setScanningState(false);

        } else if (job.status === "error") {
          clearInterval(pollNd);
          if (netdiscoverProgress) netdiscoverProgress.classList.add("hidden");
          if (errorBox) {
            errorBox.textContent = "Erreur Netdiscover : " + job.error;
            errorBox.classList.remove("hidden");
          }
          setScanningState(false);
        }
      } catch (err) {
        clearInterval(pollNd);
        setScanningState(false);
      }
    }, 1000);
    window.activePollInterval = pollNd;

  } catch (err) {
    if (errorBox) {
      errorBox.textContent = "Erreur réseau Netdiscover : " + err.message;
      errorBox.classList.remove("hidden");
    }
    setScanningState(false);
  }
}

function attachNetdiscoverEvents() {
  const masterChk = document.getElementById("chk-toggle-all-netdiscover");
  const btnSelectAll = document.getElementById("btn-select-all-netdiscover");
  const btnDeselectAll = document.getElementById("btn-deselect-all-netdiscover");
  const btnScanSelected = document.getElementById("btn-scan-selected-netdiscover");

  const getCheckboxes = () => document.querySelectorAll(".netdiscover-chk");

  if (masterChk) {
    masterChk.addEventListener("change", (e) => {
      getCheckboxes().forEach(chk => chk.checked = e.target.checked);
    });
  }

  if (btnSelectAll) {
    btnSelectAll.addEventListener("click", () => {
      getCheckboxes().forEach(chk => chk.checked = true);
      if (masterChk) masterChk.checked = true;
    });
  }

  if (btnDeselectAll) {
    btnDeselectAll.addEventListener("click", () => {
      getCheckboxes().forEach(chk => chk.checked = false);
      if (masterChk) masterChk.checked = false;
    });
  }

  if (btnScanSelected) {
    btnScanSelected.addEventListener("click", () => {
      const selectedIps = Array.from(getCheckboxes())
        .filter(chk => chk.checked)
        .map(chk => chk.value);

      if (selectedIps.length === 0) {
        const errorBox = document.getElementById("scan-error");
        if (errorBox) {
          errorBox.textContent = "Veuillez cocher au moins un équipement à scanner.";
          errorBox.classList.remove("hidden");
        }
        return;
      }

      // Joindre les cibles séparées par un espace et lancer le scan Nmap
      const customTarget = selectedIps.join(" ");
      startScan("local", customTarget);
    });
  }
}

function pollScanStatus(jobId, keepScanningState = false, customTerminalId = null) {
  return new Promise((resolve) => {
    const progressBox = document.getElementById("scan-progress");
    const progressText = document.getElementById("scan-progress-text");
    const errorBox = document.getElementById("scan-error");
    const terminalContent = document.getElementById(customTerminalId || "scan-terminal-content");

    const poll = setInterval(async () => {
      try {
        const res = await fetch(`/api/scan-status/${jobId}`);
        if (res.status !== 200) {
          clearInterval(poll);
          if (!keepScanningState) setScanningState(false);
          if (progressBox && !customTerminalId) progressBox.classList.add("hidden");
          if (errorBox && !customTerminalId) {
            errorBox.textContent = "Erreur : Tâche de scan introuvable ou serveur réinitialisé.";
            errorBox.classList.remove("hidden");
          }
          resolve(null);
          return;
        }
        
        let job;
        const contentType = res.headers.get("content-type");
        if (contentType && contentType.includes("application/json")) {
          job = await res.json();
        } else {
          const text = await res.text();
          throw new Error(`Statut non JSON (${res.status}) : ${text.substring(0, 150)}`);
        }

        if (progressText && !customTerminalId) progressText.textContent = `Scan en cours (statut: ${job.status})...`;
        if (terminalContent) updateTerminal(terminalContent, job.log || []);

        if (job.status === "done") {
          if (!keepScanningState) setScanningState(false);
          clearInterval(poll);
          if (progressBox && !customTerminalId) progressBox.classList.add("hidden");
          if (!customTerminalId) renderResults(job.result);
          resolve(job.result);
        } else if (job.status === "error") {
          if (!keepScanningState) setScanningState(false);
          clearInterval(poll);
          if (progressBox && !customTerminalId) progressBox.classList.add("hidden");
          if (errorBox && !customTerminalId) {
            errorBox.textContent = "Erreur pendant le scan : " + job.error;
            errorBox.classList.remove("hidden");
          }
          resolve(null);
        }
      } catch (err) {
        clearInterval(poll);
        if (!keepScanningState) setScanningState(false);
        resolve(null);
      }
    }, 1000);
    window.activePollInterval = poll;
  });
}

function updateTerminal(terminalEl, logLines) {
  const previousLineCount = parseInt(terminalEl.dataset.lineCount || "0", 10);
  if (logLines.length === previousLineCount) return;

  const wasNearBottom = terminalEl.scrollHeight - terminalEl.scrollTop - terminalEl.clientHeight < 40;

  terminalEl.textContent = logLines.join("\n");
  terminalEl.dataset.lineCount = logLines.length;

  if (wasNearBottom || previousLineCount === 0) {
    terminalEl.scrollTop = terminalEl.scrollHeight;
  }
}

/* -------------------------------------------------------------------------------
 * 5. AFFICHAGE DES RÉSULTATS
 * ------------------------------------------------------------------------------- */
let portsChartInstance = null;

function renderResults(hosts) {
  const resultsCard = document.getElementById("results-card");
  const summaryEl = document.getElementById("results-summary");
  const hostsDetailEl = document.getElementById("hosts-detail");

  if (!resultsCard || !summaryEl || !hostsDetailEl) return;

  resultsCard.classList.remove("hidden");
  summaryEl.innerHTML = "";
  hostsDetailEl.innerHTML = "";
  window.autoCveSearched = false;

  // Afficher la topologie réseau dynamique pour les scans locaux
  const isLocalScan = (window.currentViewId === "view-local") || (hosts && hosts.length > 0 && hosts.some(h => h.mac || h.netbios_name || h.ip.match(/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/)));
  if (isLocalScan) {
    renderLocalTopology(hosts);
  } else {
    document.getElementById("topology-card")?.classList.add("hidden");
  }

  let totalOpen = 0, totalClosed = 0, totalFiltered = 0;
  const serviceCounts = {};

  hosts.forEach((host) => {
    const hostBlock = document.createElement("div");
    hostBlock.className = "host-block";

    const titleContainer = document.createElement("div");
    titleContainer.style.display = "flex";
    titleContainer.style.justifyContent = "space-between";
    titleContainer.style.alignItems = "center";
    titleContainer.style.flexWrap = "wrap";
    titleContainer.style.gap = "10px";
    titleContainer.style.marginBottom = "8px";

    const title = document.createElement("h4");
    title.style.margin = "0";
    const icon = host.icon || "fa-server";
    const cat = host.category ? ` [${host.category}]` : "";
    const nameStr = host.hostname || host.netbios_name ? ` (${host.hostname || host.netbios_name})` : "";
    title.innerHTML = `<i class="fa-solid ${icon}" style="color:#00ff41; margin-right:8px;"></i> ${host.ip}${nameStr} <small style="color:#ffaa00; font-size:0.8em;">${cat}</small>`;

    const addHostBtn = document.createElement("button");
    addHostBtn.className = "btn btn-small btn-add-single-host-to-report";
    addHostBtn.setAttribute("data-host-ip", host.ip);
    addHostBtn.style.fontSize = "0.75rem";
    addHostBtn.style.padding = "3px 8px";
    addHostBtn.style.background = "rgba(0, 255, 65, 0.12)";
    addHostBtn.style.borderColor = "#00ff41";
    addHostBtn.style.color = "#00ff41";
    addHostBtn.innerHTML = `<i class="fa-solid fa-plus"></i> Ajouter cet hôte au rapport`;

    titleContainer.appendChild(title);
    titleContainer.appendChild(addHostBtn);
    hostBlock.appendChild(titleContainer);

    if (host.vendor || host.netbios_name) {
      const infoP = document.createElement("p");
      infoP.style.fontSize = "0.85rem";
      infoP.style.color = "#aaa";
      infoP.style.marginTop = "-5px";
      infoP.innerHTML = `Constructeur : <b>${host.vendor || 'Inconnu'}</b> ${host.workgroup ? `· Groupe de travail : <b>${host.workgroup}</b>` : ''}`;
      hostBlock.appendChild(infoP);
    }

    if (host.os_matches && host.os_matches.length > 0) {
      const osP = document.createElement("p");
      osP.style.fontSize = "0.8rem";
      osP.style.color = "#9fdcb0";
      osP.textContent = "OS probable : " + host.os_matches[0].name + ` (${host.os_matches[0].accuracy}% de confiance)`;
      hostBlock.appendChild(osP);
    }

    if (host.ports.length === 0) {
      const p = document.createElement("p");
      p.textContent = "Aucun port scanné / hôte down.";
      hostBlock.appendChild(p);
    } else {
      const table = document.createElement("table");
      table.className = "ports-table";
      table.innerHTML = `
        <thead>
          <tr><th>Port</th><th>Protocole</th><th>État</th><th>Service</th><th>Produit / Version</th><th>CVE / Exploits</th><th>Outils Recommandés</th></tr>
        </thead>
        <tbody></tbody>
      `;
      const tbody = table.querySelector("tbody");

      host.ports.forEach((p) => {
        if (p.state === "open") totalOpen++;
        else if (p.state === "closed") totalClosed++;
        else totalFiltered++;

        if (p.state === "open" && p.service) {
          serviceCounts[p.service] = (serviceCounts[p.service] || 0) + 1;
        }

        const tr = document.createElement("tr");
        const productVersion = [p.product, p.version].filter(Boolean).join(" ");
        const searchQuery = p.product || p.service || "";
        const hasQuery = p.state === "open" && searchQuery && searchQuery !== "unknown";

        const badgeId = `cve-badge-${Math.random().toString(36).substr(2, 9)}`;

        // Génération des boutons d'outils recommandés spécifiques au port/service avec popovers d'explication
        let toolBtnsHtml = "-";
        if (p.state === "open") {
          const portNum = parseInt(p.port, 10);
          const sName = (p.service || "").toLowerCase();
          const tools = [];

          if (portNum === 80 || portNum === 443 || portNum === 8080 || sName.includes("http")) {
            tools.push({ name: "WhatWeb", icon: "fa-code", desc: "Identification des technologies Web, CMS, serveurs et frameworks.", cmd: `whatweb http://${host.ip}:${portNum}` });

            tools.push({ name: "Nuclei", icon: "fa-bolt", desc: "Détection de failles récentes basée sur des modèles communautaires.", cmd: `nuclei -u http://${host.ip}:${portNum}` });
          }
          if (sName.includes("wordpress") || sName.includes("wp")) {
            tools.push({ name: "WPScan", icon: "fa-wordpress", desc: "Audit de sécurité spécifique WordPress (plugins, thèmes, utilisateurs).", cmd: `wpscan --url http://${host.ip}:${portNum} --enumerate p,t,u` });
          }
          if (portNum === 445 || portNum === 139 || sName.includes("smb") || sName.includes("netbios")) {
            tools.push({ name: "Enum4linux", icon: "fa-network-wired", desc: "Énumération complète des partages Windows/Samba et des utilisateurs.", cmd: `enum4linux -a ${host.ip}` });
            tools.push({ name: "SMBMap", icon: "fa-folder-open", desc: "Cartographie visuelle des droits d'accès sur les partages réseau.", cmd: `smbmap -H ${host.ip}` });
          }
          if (portNum === 22 || sName.includes("ssh")) {
            tools.push({ name: "SSH-Audit", icon: "fa-key", desc: "Analyse de la robustesse des algorithmes de chiffrement SSH.", cmd: `ssh-audit ${host.ip}` });
          }
          if (portNum === 21 || sName.includes("ftp")) {
            tools.push({ name: "FTP-Anon", icon: "fa-folder-tree", desc: "Vérification de l'accès FTP anonyme sans mot de passe.", cmd: `nmap --script ftp-anon -p 21 ${host.ip}` });
          }
          if (portNum === 3306 || portNum === 5432 || sName.includes("sql")) {
            tools.push({ name: "SQLMap", icon: "fa-database", desc: "Détection et exploitation automatique d'injections SQL sur la base.", cmd: `sqlmap -u "http://${host.ip}/..." --batch` });
          }

          if (tools.length > 0) {
            toolBtnsHtml = `<div class="tool-btns-wrapper">` + tools.map(t => `
              <div class="tool-btn-container">
                <button class="tool-btn" onclick="navigator.clipboard.writeText('${t.cmd}'); alert('Commande copiée : ${t.cmd}');" title="Cliquer pour copier la commande">
                  <i class="fa-solid ${t.icon}"></i> ${t.name}
                </button>
                <div class="tool-explanation-popover">
                  <strong style="color:#00ff41; display:block; margin-bottom:3px;">${t.name}</strong>
                  ${t.desc}<br/>
                  <code style="color:#7ec8ff; font-size:0.7em; margin-top:4px; display:block;">$ ${t.cmd}</code>
                </div>
              </div>
            `).join("") + `</div>`;
          }
        }

        tr.innerHTML = `
          <td>${p.port}</td>
          <td>${p.protocol}</td>
          <td class="state-${p.state}">${p.state}</td>
          <td>${p.service || "-"}</td>
          <td>${productVersion || p.service || "-"}</td>
          <td>
            ${hasQuery ? `<span id="${badgeId}" class="cve-badge cve-badge-loading" style="cursor:pointer;" title="Cliquer pour voir les détails des CVE"><i class="fa-solid fa-spinner fa-spin"></i> Recherche...</span>` : "-"}
          </td>
          <td>${toolBtnsHtml}</td>
        `;

        tbody.appendChild(tr);

        if (hasQuery) {
          const badgeEl = tr.querySelector(".cve-badge");
          const openModalHandler = (e) => {
            if (e) e.stopPropagation();
            showCveModal(searchQuery, p.version || "");
          };

          fetchCveBadgeData(searchQuery, p.version || "", badgeEl);

          if (badgeEl) badgeEl.onclick = openModalHandler;
        }
      });

      hostBlock.appendChild(table);

      // Recommandations d'outils Kali Linux spécifiques selon les services et ports découverts
      const openPorts = host.ports.filter(p => p.state === "open");
      if (openPorts.length > 0) {
        const kaliBox = document.createElement("div");
        kaliBox.style.marginTop = "12px";
        kaliBox.style.padding = "10px 14px";
        kaliBox.style.background = "rgba(0, 255, 65, 0.05)";
        kaliBox.style.border = "1px solid rgba(0, 255, 65, 0.3)";
        kaliBox.style.borderRadius = "4px";

        let recommendations = [];

        openPorts.forEach(p => {
          const portNum = parseInt(p.port, 10);
          const sName = (p.service || "").toLowerCase();

          if (portNum === 80 || portNum === 443 || portNum === 8080 || sName.includes("http")) {
            recommendations.push(`<li><b>WhatWeb</b> : <code>whatweb http://${host.ip}:${portNum}</code> pour l'analyse des technologies Web.</li>`);
            recommendations.push(`<li><b>Nuclei</b> : <code>nuclei -u http://${host.ip}:${portNum}</code> pour scanner avec des modèles d'exploits d'actualité.</li>`);
          }
          if (sName.includes("wordpress") || sName.includes("wp")) {
            recommendations.push(`<li><b>WPScan</b> : <code>wpscan --url http://${host.ip}:${portNum} --enumerate p,t,u</code> (Scanner spécifique WordPress).</li>`);
          }
          if (portNum === 445 || portNum === 139 || sName.includes("smb") || sName.includes("netbios")) {
            recommendations.push(`<li><b>Enum4linux / SMBMap</b> : <code>enum4linux -a ${host.ip}</code> ou <code>smbmap -H ${host.ip}</code> pour énumérer les partages Windows/Samba.</li>`);
          }
          if (portNum === 22 || sName.includes("ssh")) {
            recommendations.push(`<li><b>Hydra / SSH-Audit</b> : <code>ssh-audit ${host.ip}</code> pour auditer les algorithmes et chiffrements SSH.</li>`);
          }
          if (portNum === 21 || sName.includes("ftp")) {
            recommendations.push(`<li><b>Nmap FTP Scripts</b> : <code>nmap --script ftp-anon,ftp-bounce -p 21 ${host.ip}</code> (Vérification anonyme FTP).</li>`);
          }
          if (portNum === 3306 || portNum === 5432 || sName.includes("sql")) {
            recommendations.push(`<li><b>SQLMap</b> : <code>sqlmap -u "http://${host.ip}/..." --batch</code> pour tester les injections SQL.</li>`);
          }
        });

        if (recommendations.length > 0) {
          // Supprimer les doublons
          recommendations = [...new Set(recommendations)];
          kaliBox.innerHTML = `
            <div style="font-weight: bold; color: #00ff41; margin-bottom: 6px; font-size: 0.9em;">
              🐉 Outils Kali Linux recommandés pour ${host.ip} :
            </div>
            <ul style="margin: 0; padding-left: 20px; font-size: 0.85em; color: #d0d0d0; line-height: 1.5;">
              ${recommendations.join("")}
            </ul>
          `;
          hostBlock.appendChild(kaliBox);
        }
      }

      // --- AFFICHAGE POST-SCAN AUTO (SMB & FTP) ---
      if (host.smb_enum) {
        const smbBox = document.createElement("div");
        smbBox.style.marginTop = "12px";
        smbBox.style.padding = "10px";
        smbBox.style.background = "rgba(46, 204, 113, 0.05)";
        smbBox.style.border = "1px solid #2ecc71";
        smbBox.style.borderRadius = "4px";
        smbBox.innerHTML = `<h5 style="color:#2ecc71; margin:0 0 8px 0; font-size: 0.95rem;"><i class="fa-solid fa-folder-tree"></i> Énumération SMB Automatique (smbclient)</h5>
        <pre style="margin:0; font-size:0.8rem; color:#ccc; white-space:pre-wrap;">${host.smb_enum}</pre>`;
        hostBlock.appendChild(smbBox);
      }

      if (host.ftp_anon !== undefined) {
        const ftpBox = document.createElement("div");
        ftpBox.style.marginTop = "12px";
        ftpBox.style.padding = "10px";
        ftpBox.style.background = host.ftp_anon ? "rgba(231,76,60,0.1)" : "rgba(255,255,255,0.05)";
        ftpBox.style.border = host.ftp_anon ? "1px solid #e74c3c" : "1px solid #555";
        ftpBox.style.borderRadius = "4px";
        
        let content = host.ftp_anon ? 
          `<strong style="color:#ff4444; font-size: 0.9rem;"><i class="fa-solid fa-triangle-exclamation"></i> ALERTE : Connexion FTP Anonyme Autorisée !</strong><br/><pre style="margin-top:8px; font-size:0.8rem; color:#ccc; max-height:200px; overflow:auto;">${host.ftp_files}</pre>` : 
          `<span style="color:#aaa; font-size: 0.9rem;"><i class="fa-solid fa-shield"></i> Connexion FTP Anonyme refusée.</span>`;
          
        ftpBox.innerHTML = `<h5 style="color:#f1c40f; margin:0 0 8px 0; font-size: 0.95rem;"><i class="fa-solid fa-file-ftp"></i> Vérification FTP Anonymous</h5>${content}`;
        hostBlock.appendChild(ftpBox);
      }

      // Auto-déclenchement de la recherche CVE pour le premier port ouvert globale
      if (!window.autoCveSearched) {
        const firstOpenPort = host.ports.find(p => p.state === "open" && (p.product || p.service));
        if (firstOpenPort) {
          window.autoCveSearched = true;
          const queryTerm = firstOpenPort.product || firstOpenPort.service;
          showCveModal(queryTerm, firstOpenPort.version || "");
        }
      }
    }

    hostsDetailEl.appendChild(hostBlock);
  });

  const stats = [
    { label: "Hôtes actifs", value: hosts.length },
    { label: "Ports ouverts", value: totalOpen },
    { label: "Ports fermés", value: totalClosed },
    { label: "Ports filtrés", value: totalFiltered },
  ];
  stats.forEach((s) => {
    const div = document.createElement("div");
    div.className = "summary-stat";
    div.innerHTML = `<span class="value">${s.value}</span><span class="label">${s.label}</span>`;
    summaryEl.appendChild(div);
  });

  renderPortsChart(serviceCounts);
}

function renderPortsChart(serviceCounts) {
  const chartCanvas = document.getElementById("ports-chart");
  if (!chartCanvas) return;
  const ctx = chartCanvas.getContext("2d");
  if (portsChartInstance) portsChartInstance.destroy();

  const labels = Object.keys(serviceCounts);
  const values = Object.values(serviceCounts);

  portsChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels.length ? labels : ["Aucun port ouvert"],
      datasets: [{
        label: "Ports ouverts par service",
        data: values.length ? values : [0],
        backgroundColor: "rgba(0, 255, 65, 0.5)",
        borderColor: "#00ff41",
        borderWidth: 1,
      }],
    },
    options: {
      scales: {
        x: { ticks: { color: "#9fdcb0" }, grid: { color: "rgba(0,255,65,0.1)" } },
        y: { ticks: { color: "#9fdcb0", stepSize: 1 }, grid: { color: "rgba(0,255,65,0.1)" }, beginAtZero: true },
      },
      plugins: {
        legend: { labels: { color: "#9fdcb0" } },
      },
    },
  });
}

/* ---------- TOPOLOGIE DYNAMIQUE DU RÉSEAU LOCAL (vis-network) ---------- */
let localNetworkInstance = null;

function renderLocalTopology(hosts) {
  const topoCard = document.getElementById("topology-card");
  const container = document.getElementById("local-topology-container");
  if (!topoCard || !container || typeof vis === "undefined") return;

  topoCard.classList.remove("hidden");

  // Déterminer la passerelle (IP finissant par .254 ou .1 ou premier équipement routeur)
  let gatewayHost = hosts.find(h => h.ip.endsWith(".254") || h.ip.endsWith(".1") || (h.category && h.category.toLowerCase().includes("routeur"))) || hosts[0];
  const gatewayIp = gatewayHost ? gatewayHost.ip : "192.168.1.254";

  const nodes = [];
  const edges = [];

  // Nœud Passerelle / Central Hub
  nodes.push({
    id: gatewayIp,
    label: `📶 Passerelle / Box\n${gatewayIp}`,
    shape: "box",
    margin: 10,
    color: {
      background: "#062812",
      border: "#00ff41",
      highlight: { background: "#0c4820", border: "#00ff41" }
    },
    font: { color: "#00ff41", face: "Share Tech Mono", size: 14 },
    shadow: true,
  });

  hosts.forEach(h => {
    if (h.ip === gatewayIp) return;

    const nameStr = h.hostname || h.netbios_name || h.vendor || "Équipement";
    const labelText = `${h.ip}\n(${nameStr})`;

    // Évaluer le niveau de risque selon les ports et services
    const openPorts = h.ports ? h.ports.filter(p => p.state === "open") : [];
    let nodeColor = { background: "#092411", border: "#00C851" }; // Vert par défaut
    let riskLevel = "safe";

    const hasCriticalPorts = openPorts.some(p => [21, 22, 139, 445, 3306].includes(parseInt(p.port, 10)));
    if (openPorts.length >= 4 || hasCriticalPorts) {
      nodeColor = { background: "#330a0a", border: "#ff4444" }; // Rouge (Risque)
      riskLevel = "high";
    } else if (openPorts.length > 0) {
      nodeColor = { background: "#2b1c04", border: "#ffbb33" }; // Orange (Attention)
      riskLevel = "warning";
    }

    nodes.push({
      id: h.ip,
      label: labelText,
      shape: "box",
      margin: 8,
      color: {
        background: nodeColor.background,
        border: nodeColor.border,
        highlight: { background: "#1a1a1a", border: "#00ff41" }
      },
      font: { color: "#ffffff", face: "Share Tech Mono", size: 11 },
      riskLevel: riskLevel
    });

    // Liaison vers la passerelle
    edges.push({
      from: gatewayIp,
      to: h.ip,
      color: { color: "rgba(0, 255, 65, 0.4)", highlight: "#00ff41" },
      width: 1.5,
      smooth: { type: "continuous" }
    });
  });

  const nodesDataSet = new vis.DataSet(nodes);
  const edgesDataSet = new vis.DataSet(edges);

  const data = { nodes: nodesDataSet, edges: edgesDataSet };

  const options = {
    physics: {
      solver: "forceAtlas2Based",
      forceAtlas2Based: {
        gravitationalConstant: -50,
        centralGravity: 0.01,
        springLength: 100,
        springConstant: 0.08
      },
      maxVelocity: 50,
      minVelocity: 0.1,
      stabilization: { iterations: 150 }
    },
    interaction: {
      hover: true,
      zoomView: true,
      dragView: true
    }
  };

  if (localNetworkInstance) {
    localNetworkInstance.destroy();
  }

  localNetworkInstance = new vis.Network(container, data, options);

  // Désactiver le moteur physique après stabilisation pour libérer à 100% le CPU et éviter le gel de la page
  localNetworkInstance.once("stabilizationIterationsDone", function() {
    localNetworkInstance.setOptions({ physics: false });
  });
  setTimeout(() => {
    if (localNetworkInstance) localNetworkInstance.setOptions({ physics: false });
  }, 1000);

  // Zoom au clic sur un nœud
  localNetworkInstance.on("selectNode", function(params) {
    if (params.nodes.length > 0) {
      const selectedIp = params.nodes[0];
      localNetworkInstance.focus(selectedIp, {
        scale: 1.3,
        animation: { duration: 500, easingFunction: "easeInOutQuad" }
      });
    }
  });

  // Gérer les filtres de topologie
  const btnFilterAll = document.getElementById("btn-topo-filter-all");
  const btnFilterRisk = document.getElementById("btn-topo-filter-risk");
  const btnReset = document.getElementById("btn-topo-reset");

  if (btnFilterAll) {
    btnFilterAll.onclick = function() {
      this.classList.add("active");
      if (btnFilterRisk) btnFilterRisk.classList.remove("active");
      nodesDataSet.clear();
      nodesDataSet.add(nodes);
      localNetworkInstance.setOptions({ physics: true });
      setTimeout(() => { if (localNetworkInstance) localNetworkInstance.setOptions({ physics: false }); }, 600);
    };
  }

  if (btnFilterRisk) {
    btnFilterRisk.onclick = function() {
      this.classList.add("active");
      if (btnFilterAll) btnFilterAll.classList.remove("active");
      const riskNodes = nodes.filter(n => n.id === gatewayIp || n.riskLevel === "high" || n.riskLevel === "warning");
      nodesDataSet.clear();
      nodesDataSet.add(riskNodes);
      localNetworkInstance.setOptions({ physics: true });
      setTimeout(() => { if (localNetworkInstance) localNetworkInstance.setOptions({ physics: false }); }, 600);
    };
  }

  if (btnReset) {
    btnReset.onclick = function() {
      localNetworkInstance.fit({ animation: { duration: 600 } });
    };
  }
}

async function fetchCveBadgeData(product, version, badgeEl) {
  if (!badgeEl) return;

  badgeEl.onclick = (e) => {
    if (e) e.stopPropagation();
    showCveModal(product, version);
  };

  try {
    const res = await fetch("/api/cve-search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ product, version }),
    });
    const data = await res.json();
    const count = data.results ? data.results.length : 0;

    badgeEl.classList.remove("cve-badge-loading");

    if (count >= 5) {
      badgeEl.classList.add("cve-badge-critical");
      badgeEl.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> ${count} CVE`;
    } else if (count > 0) {
      badgeEl.classList.add("cve-badge-warning");
      badgeEl.innerHTML = `<i class="fa-solid fa-bug"></i> ${count} CVE`;
    } else {
      badgeEl.classList.add("cve-badge-safe");
      badgeEl.innerHTML = `<i class="fa-solid fa-shield-check"></i> 0 CVE`;
    }
  } catch (err) {
    if (badgeEl) {
      badgeEl.classList.remove("cve-badge-loading");
      badgeEl.classList.add("cve-badge-safe");
      badgeEl.innerHTML = `CVE ?`;
    }
  }
}

async function showCveModal(product, version) {
  const modal = document.getElementById("cve-modal");
  const modalTitle = document.getElementById("cve-modal-title");
  const modalBody = document.getElementById("cve-modal-body");

  if (!modal || !modalBody) return;

  modalTitle.innerHTML = `<i class="fa-solid fa-bug" style="color:#ff4444; margin-right:8px;"></i> Vulnérabilités & CVE : ${product} ${version}`;
  modalBody.innerHTML = `<p style="color:#aaa;"><i class="fa-solid fa-spinner fa-spin"></i> Recherche des exploits dans Exploit-DB pour ${product} ${version}...</p>`;
  modal.classList.remove("hidden");
  modal.style.display = "flex";

  modal.dataset.openedAt = Date.now();

  // Gérer la fermeture
  const closeModal = () => {
    modal.classList.add("hidden");
    modal.style.display = "none";
  };

  const closeBtn = document.getElementById("cve-modal-close");
  if (closeBtn) closeBtn.onclick = closeModal;
  modal.onclick = (e) => {
    if (e.target === modal && (Date.now() - (parseInt(modal.dataset.openedAt) || 0) > 300)) {
      closeModal();
    }
  };

  try {
    const res = await fetch("/api/cve-search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ product, version }),
    });
    const data = await res.json();

    if (res.status !== 200 || !data.results || data.results.length === 0) {
      modalBody.innerHTML = `
        <div style="text-align: center; padding: 20px; color: #00C851;">
          <i class="fa-solid fa-shield-cat" style="font-size: 3em; margin-bottom: 10px;"></i>
          <p style="font-size: 1.1em; font-weight: bold;">Aucun exploit critique répertorié</p>
          <p style="color: #aaa; font-size: 0.85em;">Aucune entrée trouvée dans Exploit-DB pour la recherche "${data.query || product}".</p>
        </div>
      `;
      return;
    }

    let html = `
      <div style="margin-bottom: 15px; padding: 10px; background: rgba(255, 68, 68, 0.1); border-left: 4px solid #ff4444; border-radius: 4px;">
        <span style="color: #ff4444; font-weight: bold;">${data.results.length} vulnérabilité(s) / exploit(s) identifié(s)</span>
      </div>
      <div style="display: flex; flex-direction: column; gap: 10px;">
    `;

    data.results.forEach((r) => {
      html += `
        <div class="cve-result-item" style="border: 1px solid rgba(255, 68, 68, 0.3); background: rgba(30, 0, 0, 0.4); border-radius: 6px; padding: 12px;">
          <div style="font-weight: bold; color: #ff8888; font-size: 0.95em; margin-bottom: 6px;">${r.title}</div>
          <div style="display: flex; gap: 15px; font-size: 0.8em; color: #aaa;">
            <span><b>EDB-ID:</b> <code style="color: #00ff41;">${r.edb_id}</code></span>
            <span><b>Type:</b> ${r.type || 'N/A'}</span>
            <span><b>Plateforme:</b> ${r.platform || 'N/A'}</span>
            ${r.date ? `<span><b>Date:</b> ${r.date}</span>` : ''}
          </div>
          <div style="margin-top: 8px;">
            <a href="https://www.exploit-db.com/exploits/${r.edb_id}" target="_blank" style="color: #00ff41; font-size: 0.8em; text-decoration: underline;">
              🔗 Consulter sur Exploit-DB
            </a>
          </div>
        </div>
      `;
    });
    html += `</div>`;
    modalBody.innerHTML = html;

  } catch (err) {
    modalBody.innerHTML = `<p class="alert-box error">Erreur lors de la récupération des détails : ${err.message}</p>`;
  }
}

/* -------------------------------------------------------------------------------
 * 6. GESTION DES PARAMÈTRES (SUDO)
 * ------------------------------------------------------------------------------- */
function initSettingsHandlers() {
  const btnSaveSudo = document.getElementById("btn-save-sudo");
  const btnClearSudo = document.getElementById("btn-clear-sudo");
  const inputSudo = document.getElementById("sudo-password-input");
  const alertBox = document.getElementById("sudo-status-alert");

  if (btnSaveSudo) {
    btnSaveSudo.addEventListener("click", async () => {
      const password = inputSudo ? inputSudo.value : "";
      btnSaveSudo.disabled = true;
      btnSaveSudo.textContent = "⏳ Vérification en cours...";

      try {
        const res = await fetch("/api/settings/sudo", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password }),
        });
        const data = await res.json();

        if (alertBox) {
          alertBox.classList.remove("hidden");
          alertBox.className = "alert-box " + (data.success ? "success" : "error");
          alertBox.textContent = data.success ? data.message : (data.error || "Erreur de mot de passe");
        }
      } catch (err) {
        if (alertBox) {
          alertBox.classList.remove("hidden");
          alertBox.className = "alert-box error";
          alertBox.textContent = "Erreur réseau : " + err.message;
        }
      } finally {
        btnSaveSudo.disabled = false;
        btnSaveSudo.innerHTML = `<i class="fa-solid fa-lock"></i> Enregistrer & Tester l'accès Sudo`;
      }
    });
  }

  if (btnClearSudo) {
    btnClearSudo.addEventListener("click", async () => {
      try {
        await fetch("/api/settings/sudo/clear", { method: "POST" });
        if (inputSudo) inputSudo.value = "";
        if (alertBox) {
          alertBox.classList.remove("hidden");
          alertBox.className = "alert-box success";
          alertBox.textContent = "Mot de passe sudo effacé de la session.";
        }
      } catch (err) {
        if (alertBox) {
          alertBox.classList.remove("hidden");
          alertBox.className = "alert-box error";
          alertBox.textContent = "Erreur réseau : " + err.message;
        }
      }
    });
  }

  initCustomCommands();
}

function initCustomCommands() {
    const listEl = document.getElementById('custom-commands-list');
    const addBtn = document.getElementById('btn-add-command');
    const inputEl = document.getElementById('new-command-input');
    if (!listEl) return;

    const DEFAULT_COMMAND = "theHarvester -d url_test -b all -f results.txt";
    
    function getCommands() {
        let cmds = [];
        try {
            cmds = JSON.parse(localStorage.getItem('mscan_custom_commands')) || [];
        } catch(e) {}
        return cmds;
    }

    function saveCommands(cmds) {
        localStorage.setItem('mscan_custom_commands', JSON.stringify(cmds));
    }

    function renderCommands() {
        const cmds = getCommands();
        listEl.innerHTML = '';
        
        const trDef = document.createElement('tr');
        trDef.innerHTML = `
            <td style="padding: 8px; border-bottom: 1px solid rgba(0,255,65,0.2); color: #00ff41; font-weight: bold; text-align: center;">#1</td>
            <td style="padding: 8px; border-bottom: 1px solid rgba(0,255,65,0.2);"><code style="color:#bbb; font-family:monospace;">${DEFAULT_COMMAND}</code></td>
            <td style="padding: 8px; border-bottom: 1px solid rgba(0,255,65,0.2); text-align: center;">
                <span style="color: #666; font-size: 0.8em;"><i class="fa-solid fa-lock"></i></span>
            </td>
        `;
        listEl.appendChild(trDef);

        cmds.forEach((cmd, idx) => {
            const cmdId = idx + 2;
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="padding: 8px; border-bottom: 1px solid rgba(0,255,65,0.2); color: #00ff41; font-weight: bold; text-align: center;">#${cmdId}</td>
                <td style="padding: 8px; border-bottom: 1px solid rgba(0,255,65,0.2);">
                    <input type="text" class="edit-cmd-input" data-idx="${idx}" value="${cmd.replace(/"/g, '&quot;')}" style="width:100%; background:transparent; border:none; color:#00ff41; font-family:monospace; outline:none;" onblur="this.style.borderBottom='none'" onfocus="this.style.borderBottom='1px solid #00ff41'">
                </td>
                <td style="padding: 8px; border-bottom: 1px solid rgba(0,255,65,0.2); text-align: center;">
                    <button class="btn btn-sm btn-delete-cmd" data-idx="${idx}" style="background: rgba(255, 68, 68, 0.2); border-color: #ff4444; color: #ff8888; padding: 4px 8px;" title="Supprimer"><i class="fa-solid fa-trash"></i></button>
                </td>
            `;
            listEl.appendChild(tr);
        });

        document.querySelectorAll('.edit-cmd-input').forEach(input => {
            input.addEventListener('change', (e) => {
                const idx = parseInt(e.target.getAttribute('data-idx'));
                const cmds = getCommands();
                cmds[idx] = e.target.value;
                saveCommands(cmds);
            });
        });

        document.querySelectorAll('.btn-delete-cmd').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const idx = parseInt(e.currentTarget.getAttribute('data-idx'));
                const cmds = getCommands();
                cmds.splice(idx, 1);
                saveCommands(cmds);
                renderCommands();
            });
        });
    }

    if (addBtn && inputEl) {
        addBtn.addEventListener('click', () => {
            const val = inputEl.value.trim();
            if (val) {
                const cmds = getCommands();
                cmds.push(val);
                saveCommands(cmds);
                inputEl.value = '';
                renderCommands();
            }
        });
        
        inputEl.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                addBtn.click();
            }
        });
    }

    renderCommands();
}

/* -------------------------------------------------------------------------------
 * 7. GESTION DE L'HISTORIQUE SOUS FORME DE TABLEAU INTERACTIF
 * ------------------------------------------------------------------------------- */
function initHistoryHandlers() {
  const tableBody = document.getElementById("history-table-body");
  if (!tableBody) return;

  loadHistoryTable();

  const masterChk = document.getElementById("chk-toggle-all-history");
  const btnSelectAll = document.getElementById("btn-select-all-history");
  const btnDeselectAll = document.getElementById("btn-deselect-all-history");
  const btnDeleteSelected = document.getElementById("btn-delete-selected-history");

  const getCheckboxes = () => document.querySelectorAll(".history-chk");

  if (masterChk) {
    masterChk.addEventListener("change", (e) => {
      getCheckboxes().forEach(chk => chk.checked = e.target.checked);
    });
  }

  if (btnSelectAll) {
    btnSelectAll.addEventListener("click", () => {
      getCheckboxes().forEach(chk => chk.checked = true);
      if (masterChk) masterChk.checked = true;
    });
  }

  if (btnDeselectAll) {
    btnDeselectAll.addEventListener("click", () => {
      getCheckboxes().forEach(chk => chk.checked = false);
      if (masterChk) masterChk.checked = false;
    });
  }

  if (btnDeleteSelected) {
    btnDeleteSelected.addEventListener("click", async () => {
      const selectedIds = Array.from(getCheckboxes())
        .filter(chk => chk.checked)
        .map(chk => parseInt(chk.value, 10));

      if (selectedIds.length === 0) {
        alert("Veuillez cocher au moins un rapport à supprimer.");
        return;
      }

      if (!confirm(`Voulez-vous vraiment supprimer ${selectedIds.length} rapport(s) sélectionné(s) ?`)) return;

      try {
        const res = await fetch("/api/history/delete-batch", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ids: selectedIds })
        });
        const data = await res.json();
        if (data.success) {
          loadHistoryTable();
          document.getElementById("results-card")?.classList.add("hidden");
        } else {
          alert("Erreur lors de la suppression : " + (data.error || "Inconnue"));
        }
      } catch (err) {
        alert("Erreur réseau : " + err.message);
      }
    });
  }
}

async function loadHistoryTable() {
  const tableBody = document.getElementById("history-table-body");
  if (!tableBody) return;

  try {
    const res = await fetch("/api/history");
    const historyItems = await res.json();

    if (!Array.isArray(historyItems) || historyItems.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #aaa; padding: 25px;">Aucun rapport d'analyse dans l'historique.</td></tr>`;
      return;
    }

    let html = "";
    historyItems.forEach(item => {
      const toolIcon = item.tool === "nmap" ? "fa-tags" :
                       item.tool === "netdiscover" ? "fa-satellite-dish" :
                       item.tool === "nuclei" ? "fa-bolt" :
                       item.tool === "whatweb" ? "fa-code" : "fa-file-code";
      const modeBadge = item.mode === "local" ? `<span style="color:#00C851;">Réseau Local</span>` : `<span style="color:#7ec8ff;">Distant / Web</span>`;

      html += `
        <tr onclick="viewHistoryDetail(${item.id})" style="cursor: pointer;" class="history-row" title="Cliquer pour afficher le rapport">
          <td style="text-align: center;" onclick="event.stopPropagation();">
            <input type="checkbox" class="history-chk" value="${item.id}" style="cursor: pointer;">
          </td>
          <td style="font-family: monospace; font-size: 0.9em; color: #d0d0d0;">${item.timestamp}</td>
          <td><i class="fa-solid ${toolIcon}" style="color:#00ff41; margin-right: 6px;"></i> ${item.tool.toUpperCase()}</td>
          <td><b style="color:#00ff41;">${item.target}</b></td>
          <td>${modeBadge}</td>
          <td style="text-align: center;" onclick="event.stopPropagation();">
            <button class="btn btn-small" onclick="deleteSingleHistory(${item.id})" title="Supprimer" style="font-size: 0.75rem; padding: 4px 8px; background: rgba(255, 0, 0, 0.2); border-color: #ff4444; color: #ff8888;">
              <i class="fa-solid fa-trash"></i>
            </button>
          </td>
        </tr>
      `;
    });

    tableBody.innerHTML = html;
  } catch (err) {
    console.error("Erreur chargement tableau historique:", err);
    tableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #ff4444;">Erreur de chargement de l'historique.</td></tr>`;
  }
}

async function viewHistoryDetail(historyId) {
  try {
    setScanningState(false);
    const res = await fetch(`/api/history/${historyId}`);
    const data = await res.json();
    if (data.error) {
      alert("Erreur : " + data.error);
      return;
    }
    renderResults(data.result_json);

    // Défilement fluide vers le tableau de résultat du rapport
    const resultsCard = document.getElementById("results-card");
    if (resultsCard) {
      resultsCard.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  } catch (err) {
    alert("Erreur réseau : " + err.message);
  }
}

async function deleteSingleHistory(historyId) {
  if (!confirm("Voulez-vous vraiment supprimer ce rapport ?")) return;
  try {
    const res = await fetch(`/api/history/${historyId}`, { method: "DELETE" });
    const data = await res.json();
    if (data.success) {
      loadHistoryTable();
      document.getElementById("results-card")?.classList.add("hidden");
    } else {
      alert("Erreur lors de la suppression : " + (data.error || "Inconnue"));
    }
  } catch (err) {
    alert("Erreur réseau : " + err.message);
  }
}

// Exposer globalement pour les onclick du HTML
window.viewHistoryDetail = viewHistoryDetail;
window.deleteSingleHistory = deleteSingleHistory;

/* -------------------------------------------------------------------------------
 * 8. BOUTON D'ARRÊT DU SCAN (CHRONOMÈTRE)
 * ------------------------------------------------------------------------------- */
function initStopScanHandler() {
  const btnStop = document.getElementById("btn-stop-global-scan");
  if (btnStop) {
    btnStop.addEventListener("click", async () => {
      btnStop.disabled = true;
      btnStop.textContent = "⏳ Arrêt en cours...";

      try {
        await fetch("/api/scan/stop", { method: "POST" });
      } catch (err) {
        console.error("Erreur arrêt scan:", err);
      } finally {
        setScanningState(false);
        btnStop.disabled = false;
        btnStop.innerHTML = `<i class="fa-solid fa-hand"></i> Arrêter le scan`;

        const errorBox = document.getElementById("scan-error");
        if (errorBox) {
          errorBox.textContent = "Le scan a été interrompu à la demande de l'utilisateur.";
          errorBox.classList.remove("hidden");
        }
        const progressBox = document.getElementById("scan-progress");
        if (progressBox) progressBox.classList.add("hidden");
        const netdiscoverProgress = document.getElementById("netdiscover-progress");
        if (netdiscoverProgress) netdiscoverProgress.classList.add("hidden");
      }
    });
  }
}

/* ---------- MONITEUR SYSTÈME SIDEBAR (CPU, RAM, DEBIT INTERNET) ---------- */
let sparklineChartInstance = null;
let systemMonitorInterval = null;

function initSystemMonitor() {
  if (systemMonitorInterval) {
    clearInterval(systemMonitorInterval);
    systemMonitorInterval = null;
  }

  const cpuVal = document.getElementById("sys-cpu-val");
  const cpuBar = document.getElementById("sys-cpu-bar");
  const ramVal = document.getElementById("sys-ram-val");
  const ramBar = document.getElementById("sys-ram-bar");
  const rxVal = document.getElementById("sys-rx-val");
  const txVal = document.getElementById("sys-tx-val");
  const sparklineCanvas = document.getElementById("sidebar-sparkline");

  if (!cpuVal || !cpuBar || !ramVal || !ramBar || !sparklineCanvas) return;

  // Graphique Sparkline Temps Réel
  const maxDataPoints = 15;
  const cpuData = new Array(maxDataPoints).fill(0);
  const ramData = new Array(maxDataPoints).fill(0);
  const labels = new Array(maxDataPoints).fill("");

  const ctx = sparklineCanvas.getContext("2d");
  if (sparklineChartInstance) sparklineChartInstance.destroy();

  sparklineChartInstance = new Chart(ctx, {
    type: "line",
    data: {
      labels: labels,
      datasets: [
        {
          label: "CPU",
          data: cpuData,
          borderColor: "#00ff41",
          borderWidth: 1.5,
          pointRadius: 0,
          tension: 0.3,
          fill: false
        },
        {
          label: "RAM",
          data: ramData,
          borderColor: "#7ec8ff",
          borderWidth: 1.5,
          pointRadius: 0,
          tension: 0.3,
          fill: false
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 300 },
      scales: {
        x: { display: false },
        y: { display: false, min: 0, max: 100 }
      },
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false }
      }
    }
  });

  function formatSpeed(bytesPerSec) {
    if (bytesPerSec >= 1024 * 1024) {
      return (bytesPerSec / (1024 * 1024)).toFixed(1) + " MB/s";
    } else {
      return (bytesPerSec / 1024).toFixed(1) + " KB/s";
    }
  }

  async function updateStats() {
    try {
      const res = await fetch("/api/system-stats");
      if (!res.ok) return;
      const data = await res.json();

      // CPU
      cpuVal.textContent = `${data.cpu_percent}%`;
      cpuBar.style.width = `${data.cpu_percent}%`;
      cpuBar.style.background = data.cpu_percent > 85 ? "#ff4444" : (data.cpu_percent > 60 ? "#ffbb33" : "#00ff41");

      // RAM
      ramVal.textContent = `${data.ram_used_gb} / ${data.ram_total_gb} GB`;
      ramBar.style.width = `${data.ram_percent}%`;
      ramBar.style.background = data.ram_percent > 85 ? "#ff4444" : (data.ram_percent > 70 ? "#ffbb33" : "#00ff41");

      // Débit RX / TX
      if (rxVal) rxVal.textContent = formatSpeed(data.rx_bytes_sec);
      if (txVal) txVal.textContent = formatSpeed(data.tx_bytes_sec);

      // IP Publique a été déplacée dans le top-navbar et a son propre poller.

      // Mise à jour Sparkline
      cpuData.shift();
      cpuData.push(data.cpu_percent);

      ramData.shift();
      ramData.push(data.ram_percent);

      if (sparklineChartInstance) {
        sparklineChartInstance.update();
      }
    } catch (err) {
      console.warn("Mise à jour stats système échouée:", err);
    }
  }

  const copyIpBtn = document.getElementById("btn-copy-public-ip");
  if (copyIpBtn && !copyIpBtn.dataset.listenerAdded) {
    copyIpBtn.dataset.listenerAdded = "true";
    copyIpBtn.addEventListener("click", () => {
      const publicIpEl = document.getElementById("top-public-ip");
      if (!publicIpEl) return;
      const ipText = publicIpEl.textContent.trim();
      if (ipText && ipText !== "--.--.--.--" && ipText !== "Détection..." && ipText !== "Indisponible") {
        navigator.clipboard.writeText(ipText).then(() => {
          const icon = copyIpBtn.querySelector("i");
          if (icon) {
            icon.className = "fa-solid fa-check";
            copyIpBtn.style.color = "#00ff41";
            setTimeout(() => {
              icon.className = "fa-regular fa-copy";
              copyIpBtn.style.color = "#7ec8ff";
            }, 1500);
          }
        }).catch(err => {
          console.error("Erreur lors de la copie de l'IP:", err);
        });
      }
    });
  }

  // Poll toutes les 2 secondes avec intervalle unique
  updateStats();
  systemMonitorInterval = setInterval(updateStats, 2000);
}

/* ---------- HORLOGE TEMPS RÉEL (SIDEBAR HEADER) ---------- */
function initRealtimeClock() {
  const clockEl = document.getElementById("realtime-clock");
  if (!clockEl) return;

  function updateClock() {
    const now = new Date();
    const h = String(now.getHours()).padStart(2, '0');
    const m = String(now.getMinutes()).padStart(2, '0');
    const s = String(now.getSeconds()).padStart(2, '0');
    clockEl.textContent = `${h}:${m}:${s}`;
  }

  updateClock();
  setInterval(updateClock, 1000);
}

// Exposer globalement sur window
window.renderResults = renderResults;
window.renderLocalTopology = renderLocalTopology;


/* =====================================================================================
   SECTION RAPPORTS PERSONNALISÉS & ÉDITEUR WYSIWYG
   ===================================================================================== */

let currentActiveReportId = null;
let pendingAddToReportItem = null;
let reportAutoSaveTimer = null;

// Initialisation globale au chargement de la page
document.addEventListener("DOMContentLoaded", () => {
  initReportsPage();
  initAddToReportModal();
  initAddToReportButtons();
});

function initReportsPage() {
  const container = document.getElementById("reports-list-container");
  if (!container) return; // Pas sur la page /reports

  loadReportsList();

  // Bouton Nouveau rapport
  document.getElementById("btn-create-new-report")?.addEventListener("click", async () => {
    const title = prompt("Titre du nouveau rapport :", "Audit Cybersécurité " + new Date().toLocaleDateString());
    if (!title || !title.trim()) return;

    try {
      const res = await fetch("/api/reports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title: title.trim() })
      });
      const data = await res.json();
      if (data.success && data.id) {
        await loadReportsList();
        selectReportForEdit(data.id);
      }
    } catch (err) {
      alert("Erreur création rapport : " + err.message);
    }
  });

  // Boutons barre d'outils WYSIWYG
  document.querySelectorAll(".wysiwyg-toolbar button[data-command]").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      const command = btn.getAttribute("data-command");
      const value = btn.getAttribute("data-value") || null;
      if (command === "formatBlock" && value) {
        document.execCommand("formatBlock", false, value);
      } else {
        document.execCommand(command, false, null);
      }
    });
  });

  // Encarts d'alerte et tableaux
  document.getElementById("btn-wysiwyg-alert-note")?.addEventListener("click", () => insertWysiwygBlock("note"));
  document.getElementById("btn-wysiwyg-alert-warn")?.addEventListener("click", () => insertWysiwygBlock("warn"));
  document.getElementById("btn-wysiwyg-alert-crit")?.addEventListener("click", () => insertWysiwygBlock("crit"));
  document.getElementById("btn-wysiwyg-table")?.addEventListener("click", () => insertWysiwygTable());

  // Sauvegarde manuelle
  document.getElementById("btn-save-report")?.addEventListener("click", saveCurrentReport);

  // Supprimer le rapport actif
  document.getElementById("btn-delete-current-report")?.addEventListener("click", async () => {
    if (!currentActiveReportId) return;
    if (!confirm("Voulez-vous vraiment supprimer ce rapport ?")) return;

    try {
      const res = await fetch(`/api/reports/${currentActiveReportId}`, { method: "DELETE" });
      const data = await res.json();
      if (data.success) {
        currentActiveReportId = null;
        document.getElementById("active-report-editor")?.classList.add("hidden");
        document.getElementById("no-report-selected")?.classList.remove("hidden");
        loadReportsList();
      }
    } catch (err) {
      alert("Erreur suppression : " + err.message);
    }
  });

  // Export PDF
  document.getElementById("btn-export-pdf")?.addEventListener("click", () => {
    if (!currentActiveReportId) return;
    window.open(`/api/reports/${currentActiveReportId}/export/pdf`, "_blank");
  });

  // Export Word .docx
  document.getElementById("btn-export-docx")?.addEventListener("click", () => {
    if (!currentActiveReportId) return;
    window.open(`/api/reports/${currentActiveReportId}/export/docx`, "_blank");
  });

  // Auto-save on typing
  const editable = document.getElementById("editor-content-editable");
  if (editable) {
    editable.addEventListener("input", () => {
      if (reportAutoSaveTimer) clearTimeout(reportAutoSaveTimer);
      reportAutoSaveTimer = setTimeout(saveCurrentReport, 4000);
    });
  }
}

async function loadReportsList() {
  const container = document.getElementById("reports-list-container");
  if (!container) return;

  try {
    const res = await fetch("/api/reports");
    const reports = await res.json();

    if (!Array.isArray(reports) || reports.length === 0) {
      container.innerHTML = `<div style="text-align: center; color: #888; padding: 20px;">Aucun rapport créé.</div>`;
      return;
    }

    let html = "";
    reports.forEach(r => {
      const activeClass = r.id === currentActiveReportId ? "border-color: #00ff41; background: rgba(0,255,65,0.1);" : "";
      html += `
        <div class="report-item-card" onclick="selectReportForEdit(${r.id})" style="padding: 10px; border: 1px solid rgba(255,255,255,0.1); border-radius: 6px; cursor: pointer; transition: all 0.2s ease; ${activeClass}">
          <div style="font-weight: bold; color: #00ff41; font-size: 0.95rem;">${r.title}</div>
          <div style="font-size: 0.75rem; color: #aaa; margin-top: 4px;">Auditeur: ${r.author} | Modifié: ${r.updated_at}</div>
        </div>
      `;
    });

    container.innerHTML = html;
  } catch (err) {
    console.error("Erreur chargement liste rapports:", err);
  }
}

async function selectReportForEdit(reportId) {
  currentActiveReportId = reportId;
  await loadReportsList(); // Refresh active styles in list

  try {
    const res = await fetch(`/api/reports/${reportId}`);
    const report = await res.json();

    if (report.error) {
      alert("Erreur : " + report.error);
      return;
    }

    document.getElementById("no-report-selected")?.classList.add("hidden");
    document.getElementById("active-report-editor")?.classList.remove("hidden");

    document.getElementById("report-edit-title").value = report.title;
    document.getElementById("report-edit-author").value = report.author;
    document.getElementById("report-edit-date").textContent = "Créé le " + report.created_at;
    document.getElementById("editor-content-editable").innerHTML = report.content_html || "";

    const statusEl = document.getElementById("auto-save-status");
    if (statusEl) statusEl.textContent = "Dernière modification : " + report.updated_at;
  } catch (err) {
    alert("Erreur chargement rapport : " + err.message);
  }
}

async function saveCurrentReport() {
  if (!currentActiveReportId) return;

  const title = document.getElementById("report-edit-title")?.value.trim() || "Rapport Sans Titre";
  const author = document.getElementById("report-edit-author")?.value.trim() || "Auditeur";
  const contentHtml = document.getElementById("editor-content-editable")?.innerHTML || "";

  try {
    const res = await fetch(`/api/reports/${currentActiveReportId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title, author, content_html: contentHtml })
    });
    const data = await res.json();
    if (data.success) {
      const statusEl = document.getElementById("auto-save-status");
      if (statusEl) statusEl.textContent = "Dernière sauvegarde : " + new Date().toLocaleTimeString();
      loadReportsList();
    }
  } catch (err) {
    console.warn("Échec sauvegarde automatique :", err);
  }
}

function insertWysiwygBlock(type) {
  let blockHtml = "";
  if (type === "note") {
    blockHtml = `<div style="padding: 10px 14px; background: rgba(33, 150, 243, 0.1); border-left: 4px solid #2196F3; margin: 10px 0; border-radius: 4px;"><strong>ℹ️ Note d'audit :</strong> Saisissez vos observations ici...</div><p><br></p>`;
  } else if (type === "warn") {
    blockHtml = `<div style="padding: 10px 14px; background: rgba(255, 187, 51, 0.1); border-left: 4px solid #ffbb33; margin: 10px 0; border-radius: 4px;"><strong>⚠️ Avertissement :</strong> Risque modéré ou configuration à revoir...</div><p><br></p>`;
  } else if (type === "crit") {
    blockHtml = `<div style="padding: 10px 14px; background: rgba(255, 68, 68, 0.1); border-left: 4px solid #ff4444; margin: 10px 0; border-radius: 4px; color: #ff8888;"><strong>☣️ Vulnérabilité Critique :</strong> Action corrective urgente recommandée...</div><p><br></p>`;
  }
  document.execCommand("insertHTML", false, blockHtml);
}

function insertWysiwygTable() {
  const tableHtml = `
    <table style="width:100%; border-collapse: collapse; margin: 15px 0; border: 1px solid #00ff41;">
      <thead>
        <tr style="background: rgba(0,255,65,0.15); color: #00ff41;">
          <th style="padding: 8px; border: 1px solid #00ff41;">Composant</th>
          <th style="padding: 8px; border: 1px solid #00ff41;">Statut</th>
          <th style="padding: 8px; border: 1px solid #00ff41;">Recommandation</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="padding: 6px; border: 1px solid rgba(0,255,65,0.3);">Service Web</td>
          <td style="padding: 6px; border: 1px solid rgba(0,255,65,0.3);">En ligne</td>
          <td style="padding: 6px; border: 1px solid rgba(0,255,65,0.3);">Activer HSTS et CSP</td>
        </tr>
      </tbody>
    </table><p><br></p>
  `;
  document.execCommand("insertHTML", false, tableHtml);
}

/* ---------- BOUTONS "AJOUTER AU RAPPORT" ET MODALE ---------- */

function initAddToReportButtons() {
  document.addEventListener("click", (e) => {
    // Bouton Résultats de Scan
    const btnResults = e.target.closest("#btn-add-results-to-report");
    if (btnResults) {
      e.preventDefault();
      const summaryEl = document.getElementById("results-summary");
      const hostsEl = document.getElementById("hosts-detail");
      let html = (summaryEl ? summaryEl.innerHTML : "") + (hostsEl ? hostsEl.innerHTML : "");
      if (!html.trim()) {
        const card = document.getElementById("results-card");
        if (card) html = card.innerHTML;
      }
      if (!html || !html.trim()) {
        alert("Veuillez d'abord lancer un scan pour obtenir des résultats à ajouter.");
        return;
      }
      openAddToReportModal("Résultats du Pentest Réseau", html);
      return;
    }

    // Bouton Graphique des Ports (Chart)
    const btnChart = e.target.closest("#btn-add-chart-to-report");
    if (btnChart) {
      e.preventDefault();
      const canvas = document.getElementById("ports-chart");
      if (!canvas) {
        alert("Graphique des ports indisponible.");
        return;
      }
      try {
        const dataUrl = canvas.toDataURL("image/png");
        const chartHtml = `
          <div style="text-align: center; margin: 15px 0;">
            <img src="${dataUrl}" style="max-width: 100%; border: 1px solid #00ff41; border-radius: 6px; box-shadow: 0 0 10px rgba(0,255,65,0.2);">
            <p style="font-size: 0.8rem; color: #aaa; margin-top: 5px;">Graphique de répartition des ports scannés</p>
          </div>
        `;
        openAddToReportModal("Graphique Répartition des Ports", chartHtml);
      } catch (err) {
        alert("Erreur de capture du graphique : " + err.message);
      }
      return;
    }

    // Bouton Tous les Hôtes (1-clic)
    const btnAllHosts = e.target.closest("#btn-add-all-hosts-to-report");
    if (btnAllHosts) {
      e.preventDefault();
      const hostsEl = document.getElementById("hosts-detail");
      if (!hostsEl || !hostsEl.innerHTML.trim()) {
        alert("Aucun détail d'hôte disponible à ajouter.");
        return;
      }
      // Clone element and strip buttons
      const clone = hostsEl.cloneNode(true);
      clone.querySelectorAll(".btn-add-single-host-to-report").forEach(b => b.remove());
      openAddToReportModal("Détail Complet de Tous les Hôtes Scannés", clone.innerHTML);
      return;
    }

    // Bouton Hôte Individuel
    const btnSingleHost = e.target.closest(".btn-add-single-host-to-report");
    if (btnSingleHost) {
      e.preventDefault();
      const hostBlock = btnSingleHost.closest(".host-block");
      if (!hostBlock) return;
      const hostIp = btnSingleHost.getAttribute("data-host-ip") || "Inconnu";
      // Clone element and remove button before generating HTML
      const clone = hostBlock.cloneNode(true);
      clone.querySelectorAll(".btn-add-single-host-to-report").forEach(b => b.remove());
      openAddToReportModal(`Fiche Hôte : ${hostIp}`, clone.innerHTML);
      return;
    }

    // Bouton Netdiscover Table
    const btnNetdiscover = e.target.closest("#btn-add-netdiscover-to-report");
    if (btnNetdiscover) {
      e.preventDefault();
      const listEl = document.getElementById("netdiscover-results-list");
      let rawHtml = listEl ? listEl.innerHTML : "";
      if (!rawHtml.trim()) {
        const card = document.getElementById("netdiscover-card");
        if (card) rawHtml = card.innerHTML;
      }
      if (!rawHtml || !rawHtml.trim()) {
        alert("Veuillez d'abord lancer une découverte ARP Netdiscover pour obtenir des résultats.");
        return;
      }

      // Nettoyage complet pour le rapport d'audit
      const tempDiv = document.createElement("div");
      tempDiv.innerHTML = rawHtml;

      // 1. Supprimer tous les boutons (Lancer le scan, Tout sélectionner, Tout désélectionner, etc.)
      tempDiv.querySelectorAll("button").forEach(b => b.remove());

      // 2. Supprimer les textes d'instructions interactives
      tempDiv.querySelectorAll("span").forEach(s => {
        if (s.textContent.includes("Sélectionnez les hôtes")) s.remove();
      });

      // 3. Supprimer la colonne des cases à cocher (checkboxes) dans le tableau
      tempDiv.querySelectorAll("tr").forEach(tr => {
        const cells = Array.from(tr.children);
        cells.forEach(cell => {
          if (cell.querySelector("input[type='checkbox']") || (tr.parentElement.tagName === "THEAD" && cell === cells[0])) {
            cell.remove();
          }
        });
      });

      openAddToReportModal("Découverte ARP (Netdiscover LAN)", tempDiv.innerHTML);
      return;
    }

    // Bouton Topologie Image
    const btnTopo = e.target.closest("#btn-add-topo-to-report");
    if (btnTopo) {
      e.preventDefault();
      const container = document.getElementById("local-topology-container");
      if (!container) return;

      const canvas = container.querySelector("canvas");
      if (!canvas) {
        alert("Graphique de topologie indisponible. Veuillez d'abord lancer un scan local.");
        return;
      }

      try {
        const dataUrl = canvas.toDataURL("image/png");
        const imgHtml = `
          <div style="text-align: center; margin: 15px 0;">
            <img src="${dataUrl}" style="max-width: 100%; border: 1px solid #00ff41; border-radius: 6px; box-shadow: 0 0 10px rgba(0,255,65,0.2);">
            <p style="font-size: 0.8rem; color: #aaa; margin-top: 5px;">Schéma de topologie du réseau local (LAN)</p>
          </div>
        `;
        openAddToReportModal("Topologie Réseau Local (LAN)", imgHtml);
      } catch (err) {
        alert("Erreur de capture d'image de la topologie : " + err.message);
      }
      return;
    }

    // Bouton WHOIS
    const btnWhois = e.target.closest("#btn-add-whois-to-report");
    if (btnWhois) {
      e.preventDefault();
      const content = document.getElementById("whois-results-content");
      if (!content || !content.innerHTML.trim()) {
        alert("Aucune donnée WHOIS disponible à ajouter.");
        return;
      }
      openAddToReportModal("Informations de Domaine (WHOIS)", content.innerHTML);
      return;
    }

    // Bouton Sous-domaines
    const btnSubdomains = e.target.closest("#btn-add-subdomains-to-report");
    if (btnSubdomains) {
      e.preventDefault();
      const content = document.getElementById("subdomains-results-content");
      if (!content || !content.innerHTML.trim()) {
        alert("Aucun sous-domaine disponible à ajouter.");
        return;
      }
      openAddToReportModal("Sous-Domaines Découverts (Sublist3r)", content.innerHTML);
      return;
    }

    // Bouton WAF
    const btnWaf = e.target.closest("#btn-add-waf-to-report");
    if (btnWaf) {
      e.preventDefault();
      const content = document.getElementById("waf-results-content");
      if (!content || !content.innerHTML.trim()) {
        alert("Aucun résultat WAF disponible à ajouter.");
        return;
      }
      openAddToReportModal("Découverte Pare-Feu WAF (Wafw00f)", content.innerHTML);
      return;
    }

    // Bouton Screenshot Web
    const btnScreenshot = e.target.closest("#btn-add-screenshot-to-report");
    if (btnScreenshot) {
      e.preventDefault();
      const content = document.getElementById("screenshot-results-content");
      if (!content || !content.innerHTML.trim()) {
        alert("Aucune capture d'écran disponible à ajouter.");
        return;
      }
      openAddToReportModal("Capture d'Écran du Site Web (Gowitness)", content.innerHTML);
      return;
    }

    // Bouton Relancer la capture Gowitness
    const btnRetrySs = e.target.closest("#btn-retry-screenshot");
    if (btnRetrySs) {
      e.preventDefault();
      const targetInput = document.getElementById("target-input") || document.getElementById("target_input");
      const currentTarget = targetInput ? targetInput.value.trim() : "";
      if (currentTarget) {
        executeGowitnessScreenshot(currentTarget);
      } else {
        alert("Veuillez saisir l'URL de la cible web dans le champ de saisie.");
      }
      return;
    }

    // Bouton CMS & Empreinte Web
    const btnCms = e.target.closest("#btn-add-cms-to-report");
    if (btnCms) {
      e.preventDefault();
      const content = document.getElementById("cms-results-content");
      if (!content || !content.innerHTML.trim()) {
        alert("Aucune empreinte CMS disponible à ajouter.");
        return;
      }
      openAddToReportModal("Empreinte CMS & Technologies Web (WhatWeb)", content.innerHTML);
      return;
    }

    // Bouton CVE
    const btnCve = e.target.closest("#btn-add-cve-to-report");
    if (btnCve) {
      e.preventDefault();
      const cveEl = document.getElementById("cve-results");
      let html = cveEl ? cveEl.innerHTML : "";
      if (!html || !html.trim()) {
        alert("Veuillez effectuer une recherche CVE d'abord.");
        return;
      }
      openAddToReportModal("Vulnérabilités CVE Identifiées", html);
      return;
    }
  });
}

let isSubmittingReport = false;

function initAddToReportModal() {
  const modal = document.getElementById("modal-add-to-report");
  const closeBtn = document.getElementById("close-add-report-modal");
  const cancelBtn = document.getElementById("btn-cancel-add-report");
  const confirmBtn = document.getElementById("btn-confirm-add-report");

  const closeModal = () => {
    if (modal) {
      modal.classList.add("hidden");
      modal.style.display = "none";
    }
  };

  closeBtn?.addEventListener("click", () => {
    if (!isSubmittingReport) closeModal();
  });
  cancelBtn?.addEventListener("click", () => {
    if (!isSubmittingReport) closeModal();
  });

  confirmBtn?.addEventListener("click", async () => {
    if (isSubmittingReport || !pendingAddToReportItem) return;

    const selectEl = document.getElementById("select-dest-report");
    const newTitleInput = document.getElementById("input-new-report-title");
    let targetReportId = selectEl?.value;
    const newTitle = newTitleInput?.value.trim();

    // Verrouillage du bouton et feedback visuel instantané
    isSubmittingReport = true;
    if (confirmBtn) {
      confirmBtn.disabled = true;
      confirmBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Traitement en cours...`;
    }
    if (cancelBtn) cancelBtn.disabled = true;

    try {
      if (newTitle) {
        // Créer un nouveau rapport d'abord
        const createRes = await fetch("/api/reports", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ title: newTitle })
        });
        const createData = await createRes.json();
        if (createData.success && createData.id) {
          targetReportId = createData.id;
        } else {
          alert("Erreur création rapport : " + (createData.error || "Inconnue"));
          return;
        }
      }

      if (!targetReportId) {
        alert("Veuillez sélectionner un rapport existant ou indiquer un titre pour en créer un nouveau.");
        return;
      }

      // Appliquer l'ajout
      const appendRes = await fetch(`/api/reports/${targetReportId}/append`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: pendingAddToReportItem.title,
          html: pendingAddToReportItem.html
        })
      });

      const appendData = await appendRes.json();
      if (appendData.success) {
        closeModal();
        if (confirm("Élément ajouté au rapport avec succès ! Voulez-vous ouvrir le gestionnaire de rapports ?")) {
          window.location.href = "/reports";
        }
      } else {
        alert("Erreur ajout au rapport : " + (appendData.error || "Inconnue"));
      }
    } catch (err) {
      alert("Erreur réseau : " + err.message);
    } finally {
      // Déverrouillage systématique après exécution
      isSubmittingReport = false;
      if (confirmBtn) {
        confirmBtn.disabled = false;
        confirmBtn.innerHTML = `<i class="fa-solid fa-check"></i> Confirmer l'ajout`;
      }
      if (cancelBtn) cancelBtn.disabled = false;
    }
  });
}

async function openAddToReportModal(title, html) {
  pendingAddToReportItem = { title, html };

  let modal = document.getElementById("modal-add-to-report");
  if (!modal) {
    // Fallback: créer et injecter la modale si elle n'est pas encore dans le DOM
    const div = document.createElement("div");
    div.id = "modal-add-to-report";
    div.className = "modal";
    div.style.display = "flex";
    div.innerHTML = `
      <div class="modal-content card" style="max-width: 550px; background: #0c100c; border: 1px solid #00ff41;">
        <span class="close-btn" id="close-add-report-modal">&times;</span>
        <h3 style="color: #00ff41; margin-top: 0;"><i class="fa-solid fa-file-circle-plus"></i> Ajouter au rapport d'audit</h3>
        <p style="font-size: 0.9rem; color: #ccc;">Choisissez un rapport existant ou créez-en un nouveau à la volée :</p>
        <div style="margin-bottom: 15px;">
          <label style="display: block; font-size: 0.85rem; color: #888; margin-bottom: 5px;">Rapport de destination :</label>
          <select id="select-dest-report" style="width: 100%; padding: 8px; background: rgba(0,0,0,0.6); border: 1px solid rgba(0,255,65,0.4); color: #00ff41; border-radius: 4px; font-family: monospace;">
            <option value="">Chargement des rapports...</option>
          </select>
        </div>
        <div style="border-top: 1px dashed rgba(255,255,255,0.1); margin: 15px 0; padding-top: 15px;">
          <label style="display: block; font-size: 0.85rem; color: #888; margin-bottom: 5px;">Ou créer un nouveau rapport :</label>
          <input type="text" id="input-new-report-title" placeholder="ex: Audit Réseau LAN TP Cyber" style="width: 100%; padding: 8px; background: rgba(0,0,0,0.6); border: 1px solid rgba(255,255,255,0.2); color: #fff; border-radius: 4px;">
        </div>
        <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px;">
          <button id="btn-cancel-add-report" class="btn btn-small">Annuler</button>
          <button id="btn-confirm-add-report" class="btn btn-small btn-primary" style="font-weight: bold;">
            <i class="fa-solid fa-check"></i> Confirmer l'ajout
          </button>
        </div>
      </div>
    `;
    document.body.appendChild(div);
    initAddToReportModal();
    modal = div;
  }

  const selectEl = document.getElementById("select-dest-report");
  const newTitleInput = document.getElementById("input-new-report-title");

  if (newTitleInput) newTitleInput.value = "";
  if (selectEl) selectEl.innerHTML = `<option value="">Chargement des rapports...</option>`;

  modal.classList.remove("hidden");
  modal.style.display = "flex";

  try {
    const res = await fetch("/api/reports");
    const reports = await res.json();

    if (!Array.isArray(reports) || reports.length === 0) {
      if (selectEl) selectEl.innerHTML = `<option value="">(Aucun rapport existant - Saisissez un titre ci-dessous)</option>`;
    } else {
      let options = `<option value="">-- Sélectionner un rapport existant --</option>`;
      reports.forEach(r => {
        options += `<option value="${r.id}">${r.title} (${r.updated_at})</option>`;
      });
      if (selectEl) selectEl.innerHTML = options;
    }
  } catch (err) {
    if (selectEl) selectEl.innerHTML = `<option value="">Erreur chargement rapports</option>`;
  }
}


// =====================================================================================
// ONIONHOP — Lancement depuis la barre latérale
// =====================================================================================

async function startOnionHop() {
  try {
    const r = await fetch("/api/onionhop/start", { method: "POST" });
    const d = await r.json();
    if (d.status === "not_found") {
      alert("OnionHop introuvable sur ce système.\nInstallez-le depuis : https://github.com/center2055/OnionHop");
    }
    // Si started ou already_running : OnionHop s'ouvre visuellement, rien d'autre à faire
  } catch (e) {
    alert("Impossible de joindre le serveur. Vérifiez que M-SCAN est bien lancé.");
  }
}

// =====================================================================================
// RÉSEAU ET ROTATION IP
// =====================================================================================

async function fetchIPStatus() {
  const publicIpEl = document.getElementById("top-public-ip");
  const proxyBadge = document.getElementById("top-proxy-badge");
  
  if (!publicIpEl || !proxyBadge) return;
  
  try {
    const res = await fetch("/api/ip-status");
    const data = await res.json();
    
    publicIpEl.textContent = data.ip || "Inconnue";
    
    if (data.protected) {
      proxyBadge.textContent = "🟢 Protégé";
      proxyBadge.style.color = "#00ff41";
      proxyBadge.style.borderColor = "#00ff41";
      proxyBadge.style.background = "rgba(0, 255, 65, 0.2)";
    } else {
      proxyBadge.textContent = "🔴 Direct";
      proxyBadge.style.color = "#ff4444";
      proxyBadge.style.borderColor = "#ff4444";
      proxyBadge.style.background = "rgba(255, 0, 0, 0.2)";
    }
  } catch (err) {
    console.warn("Erreur fetch IP status:", err);
  }
}

async function rotateIP() {
  const btn = document.getElementById("btn-rotate-ip");
  const icon = btn ? btn.querySelector("i") : null;
  
  if (icon) icon.classList.add("fa-spin");
  if (btn) btn.disabled = true;
  
  try {
    const res = await fetch("/api/rotate-ip", { method: "POST" });
    const data = await res.json();
    
    if (data.status === "success") {
      // Attendre 2 secondes que le circuit se forme puis rafraîchir l'IP
      setTimeout(fetchIPStatus, 2000);
    } else {
      alert("Erreur lors de la rotation IP : " + data.message);
    }
  } catch (err) {
    alert("Impossible de joindre l'API de rotation Tor.");
  } finally {
    if (icon) icon.classList.remove("fa-spin");
    if (btn) btn.disabled = false;
  }
}

// Initial polling for IP
setInterval(fetchIPStatus, 10000);
fetchIPStatus();

