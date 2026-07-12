// =====================================================================================
// MATRIX SCANNER - script.js
// Gère : l'animation de fond "pluie de code", la vérification/installation des
// dépendances, le paramétrage et le lancement des scans, l'affichage des résultats
// (tableaux + Chart.js) et la recherche de CVE via l'API backend.
// =====================================================================================

/* -------------------------------------------------------------------------------
 * 1. ANIMATION DE FOND "MATRIX RAIN" (canvas 2D)
 * ------------------------------------------------------------------------------- */
(function initMatrixRain() {
  const canvas = document.getElementById("matrix-bg");
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
})();

/* -------------------------------------------------------------------------------
 * 2. VÉRIFICATION / INSTALLATION DES DÉPENDANCES
 * ------------------------------------------------------------------------------- */
async function checkDependencies() {
  const listEl = document.getElementById("deps-list");
  const missingAlert = document.getElementById("deps-missing-alert");

  try {
    const res = await fetch("/api/check-deps");
    const data = await res.json();

    listEl.innerHTML = "";
    Object.entries(data.tools).forEach(([name, info]) => {
      const span = document.createElement("span");
      span.className = "dep-item " + (info.installed ? "ok" : "missing");
      span.textContent = `${info.installed ? "✔" : "✘"} ${name} — ${info.description}`;
      listEl.appendChild(span);
    });

    if (!data.all_installed) {
      missingAlert.classList.remove("hidden");
      missingAlert.dataset.packages = JSON.stringify(data.missing_apt_packages);
    } else {
      missingAlert.classList.add("hidden");
    }
  } catch (err) {
    listEl.textContent = "Erreur lors de la vérification des dépendances : " + err.message;
  }
}

document.getElementById("install-btn").addEventListener("click", async () => {
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
    const startData = await startRes.json();
    if (startRes.status !== 200) {
      logEl.textContent = "Erreur : " + (startData.error || "inconnue");
      btn.disabled = false;
      btn.textContent = "⚡ Installer les dépendances";
      return;
    }

    // Polling du statut d'installation toutes les 1.5s
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

checkDependencies();

/* -------------------------------------------------------------------------------
 * 3. EXPLICATIONS DYNAMIQUES DES PARAMÈTRES
 * ------------------------------------------------------------------------------- */
const SCAN_TYPE_EXPLANATIONS = {
  sS: "Le SYN scan (-sS) envoie un paquet TCP SYN sans compléter la connexion : rapide et discret, nécessite les privilèges root.",
  sT: "Le Connect scan (-sT) complète la poignée de main TCP classique : plus lent, plus détectable, mais fonctionne sans privilèges root.",
  sU: "Le scan UDP (-sU) est nécessaire pour détecter des services comme DNS(53) ou SNMP(161) ; il est nettement plus lent que le TCP.",
  sA: "Le scan ACK (-sA) ne détermine pas si un port est ouvert mais s'il est filtré par un pare-feu stateful.",
  sn: "Le ping scan (-sn) détecte simplement les hôtes actifs sur le réseau, sans scanner leurs ports.",
};

const PORT_MODE_EXPLANATIONS = {
  fast: "Scan des 100 ports les plus courants (-F) : le plus rapide, adapté à une première reconnaissance.",
  top1000: "Scan des 1000 ports les plus courants (comportement par défaut de nmap) : bon compromis vitesse/exhaustivité.",
  all: "Scan des 65535 ports TCP (-p-) : le plus complet, mais aussi le plus long (peut prendre plusieurs minutes).",
  custom: "Scan restreint aux ports que vous spécifiez (ex: 22,80,443 ou 8000-8100).",
};

const TIMING_EXPLANATIONS = [
  "T0 (Paranoïaque) : extrêmement lent, pensé pour échapper à la détection IDS.",
  "T1 (Furtif) : très lent et discret.",
  "T2 (Poli) : ralentit le scan pour limiter la charge réseau.",
  "T3 (Normal) : vitesse par défaut de nmap, bon compromis.",
  "T4 (Agressif) : rapide, adapté à un réseau local fiable.",
  "T5 (Insane) : vitesse maximale, au risque de perdre des résultats.",
];

document.getElementById("scan_type").addEventListener("change", (e) => {
  document.getElementById("explain-scan-type").textContent = SCAN_TYPE_EXPLANATIONS[e.target.value];
});

document.getElementById("port_mode").addEventListener("change", (e) => {
  document.getElementById("explain-ports").textContent = PORT_MODE_EXPLANATIONS[e.target.value];
  document.getElementById("custom_ports").classList.toggle("hidden", e.target.value !== "custom");
});

document.getElementById("timing").addEventListener("input", (e) => {
  document.getElementById("explain-timing").textContent = TIMING_EXPLANATIONS[parseInt(e.target.value, 10)];
});

/* -------------------------------------------------------------------------------
 * 4. LANCEMENT DU SCAN
 * ------------------------------------------------------------------------------- */
let portsChartInstance = null;

function collectOptions() {
  return {
    scan_type: document.getElementById("scan_type").value,
    port_mode: document.getElementById("port_mode").value,
    custom_ports: document.getElementById("custom_ports").value,
    timing: document.getElementById("timing").value,
    service_version: document.getElementById("service_version").checked,
    os_detection: document.getElementById("os_detection").checked,
    default_scripts: document.getElementById("default_scripts").checked,
    vuln_scripts: document.getElementById("vuln_scripts").checked,
  };
}

document.getElementById("scan-btn").addEventListener("click", async () => {
  const target = document.getElementById("target").value;
  const errorBox = document.getElementById("scan-error");
  const progressBox = document.getElementById("scan-progress");
  const previewBox = document.getElementById("command-preview");
  const scanBtn = document.getElementById("scan-btn");
  const terminalBox = document.getElementById("scan-terminal");
  const terminalContent = document.getElementById("scan-terminal-content");

  errorBox.classList.add("hidden");
  document.getElementById("results-card").classList.add("hidden");
  document.getElementById("cve-card").classList.add("hidden");

  scanBtn.disabled = true;
  progressBox.classList.remove("hidden");
  document.getElementById("scan-progress-text").textContent = "Lancement du scan...";

  terminalBox.classList.remove("hidden");
  terminalContent.textContent = "";

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, options: collectOptions() }),
    });
    const data = await res.json();

    if (res.status !== 200) {
      errorBox.textContent = "Erreur : " + (data.error || "inconnue");
      errorBox.classList.remove("hidden");
      scanBtn.disabled = false;
      progressBox.classList.add("hidden");
      return;
    }

    previewBox.classList.remove("hidden");
    document.getElementById("command-preview-text").textContent = data.command_preview;

    pollScanStatus(data.job_id);
  } catch (err) {
    errorBox.textContent = "Erreur réseau : " + err.message;
    errorBox.classList.remove("hidden");
    scanBtn.disabled = false;
    progressBox.classList.add("hidden");
  }
});

function pollScanStatus(jobId) {
  const scanBtn = document.getElementById("scan-btn");
  const progressBox = document.getElementById("scan-progress");
  const progressText = document.getElementById("scan-progress-text");
  const errorBox = document.getElementById("scan-error");
  const terminalContent = document.getElementById("scan-terminal-content");

  // Rafraîchissement rapide (1s) pour un suivi fluide de la progression nmap.
  const poll = setInterval(async () => {
    const res = await fetch(`/api/scan-status/${jobId}`);
    const job = await res.json();

    progressText.textContent = `Scan en cours (statut: ${job.status})...`;
    updateTerminal(terminalContent, job.log || []);

    if (job.status === "done") {
      clearInterval(poll);
      scanBtn.disabled = false;
      progressBox.classList.add("hidden");
      renderResults(job.result);
    } else if (job.status === "error") {
      clearInterval(poll);
      scanBtn.disabled = false;
      progressBox.classList.add("hidden");
      errorBox.textContent = "Erreur pendant le scan : " + job.error;
      errorBox.classList.remove("hidden");
    }
  }, 1000);
}

// Met à jour le contenu du terminal live à partir du tableau de lignes de log.
// Ne réécrit le DOM que si le nombre de lignes a changé (évite un flicker
// inutile) et ne force l'auto-scroll que si l'utilisateur était déjà proche
// du bas (pour ne pas lui arracher la lecture s'il a remonté manuellement).
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
 * 5. AFFICHAGE DES RÉSULTATS (résumé, graphique, tableaux)
 * ------------------------------------------------------------------------------- */
function renderResults(hosts) {
  const resultsCard = document.getElementById("results-card");
  const summaryEl = document.getElementById("results-summary");
  const hostsDetailEl = document.getElementById("hosts-detail");

  resultsCard.classList.remove("hidden");
  summaryEl.innerHTML = "";
  hostsDetailEl.innerHTML = "";

  let totalOpen = 0, totalClosed = 0, totalFiltered = 0;
  const serviceCounts = {};

  hosts.forEach((host) => {
    const hostBlock = document.createElement("div");
    hostBlock.className = "host-block";

    const title = document.createElement("h4");
    title.textContent = `🖥 ${host.ip}` + (host.hostname ? ` (${host.hostname})` : "");
    hostBlock.appendChild(title);

    if (host.os_matches && host.os_matches.length > 0) {
      const osP = document.createElement("p");
      osP.style.fontSize = "0.8rem";
      osP.style.color = "#9fdcb0";
      osP.textContent = "OS probable : " + host.os_matches[0].name + ` (${host.os_matches[0].accuracy}% de confiance)`;
      hostBlock.appendChild(osP);
    }

    if (host.ports.length === 0) {
      const p = document.createElement("p");
      p.textContent = "Aucun port scanné / hôte down (mode ping scan ?).";
      hostBlock.appendChild(p);
    } else {
      const table = document.createElement("table");
      table.className = "ports-table";
      table.innerHTML = `
        <thead>
          <tr><th>Port</th><th>Protocole</th><th>État</th><th>Service</th><th>Produit / Version</th><th></th></tr>
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
        tr.innerHTML = `
          <td>${p.port}</td>
          <td>${p.protocol}</td>
          <td class="state-${p.state}">${p.state}</td>
          <td>${p.service || "-"}</td>
          <td>${productVersion || "-"}</td>
          <td>${p.state === "open" && p.product ? '<span class="cve-search-link">🔍 Chercher CVE</span>' : ""}</td>
        `;
        if (p.state === "open" && p.product) {
          tr.querySelector(".cve-search-link").addEventListener("click", () => {
            searchCve(p.product, p.version || "");
          });
        }
        tbody.appendChild(tr);
      });

      hostBlock.appendChild(table);
    }

    hostsDetailEl.appendChild(hostBlock);
  });

  // Résumé chiffré
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
  const ctx = document.getElementById("ports-chart").getContext("2d");
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

/* -------------------------------------------------------------------------------
 * 6. RECHERCHE DE CVE / EXPLOITS
 * ------------------------------------------------------------------------------- */
async function searchCve(product, version) {
  const cveCard = document.getElementById("cve-card");
  const resultsEl = document.getElementById("cve-results");

  cveCard.classList.remove("hidden");
  cveCard.scrollIntoView({ behavior: "smooth" });
  resultsEl.innerHTML = `<p>Recherche en cours pour "${product} ${version}"...</p>`;

  try {
    const res = await fetch("/api/cve-search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ product, version }),
    });
    const data = await res.json();

    if (res.status !== 200) {
      resultsEl.innerHTML = `<p class="alert-box error">${data.error || "Erreur inconnue"}</p>`;
      return;
    }

    if (!data.results || data.results.length === 0) {
      resultsEl.innerHTML = `<p>Aucun exploit connu trouvé dans Exploit-DB pour "${data.query}".</p>`;
      return;
    }

    resultsEl.innerHTML = "";
    data.results.forEach((r) => {
      const div = document.createElement("div");
      div.className = "cve-result-item";
      div.innerHTML = `
        <div class="title">${r.title}</div>
        <div class="meta">EDB-ID: ${r.edb_id} · Type: ${r.type} · Plateforme: ${r.platform} · Date: ${r.date}</div>
      `;
      resultsEl.appendChild(div);
    });
  } catch (err) {
    resultsEl.innerHTML = `<p class="alert-box error">Erreur réseau : ${err.message}</p>`;
  }
}
