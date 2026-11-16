// ==========================================================================
// REAL-TIME CYBER SOC DASHBOARD CONTROLLER
// ==========================================================================

let lastSeenId = 0;
let audioEnabled = false;

// Web Audio API Beep Generator for Breach Alerts
function playAlertSound() {
    if (!audioEnabled) return;
    try {
        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(880, audioCtx.currentTime); // A5
        osc.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.3);
        gain.gain.setValueAtTime(0.2, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.3);
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.3);
    } catch (e) {
        console.warn("Audio Context error:", e);
    }
}

function toggleAudioAlert() {
    audioEnabled = !audioEnabled;
    const btn = document.getElementById("audioToggleBtn");
    if (btn) {
        btn.innerHTML = audioEnabled ? '🔊 Sound Alert: ON' : '🔇 Sound Alert: OFF';
        btn.classList.toggle("btn-cyber-danger", audioEnabled);
    }
}

function updateClock() {
    const now = new Date();
    const clockEl = document.getElementById("dateTime");
    if (clockEl) {
        clockEl.innerHTML = `⏱ ${now.toLocaleTimeString()} | ${now.toLocaleDateString()}`;
    }
}

async function fetchLiveStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();

        // Update card numbers with animation if changed
        updateElementValue("totalAttacksVal", data.total_attacks);
        updateElementValue("todayAttacksVal", data.today_attacks);
        updateElementValue("uniqueIpsVal", data.unique_ips);
        updateElementValue("successfulBreachesVal", data.successful_breaches);

        // Sound alert if new breach recorded
        if (data.latest_id > lastSeenId && lastSeenId !== 0) {
            playAlertSound();
            fetchRecentLogs();
        }
        lastSeenId = data.latest_id;

        // Update Ticker
        const tickerEl = document.getElementById("liveTickerText");
        if (tickerEl) {
            tickerEl.innerHTML = `[${data.timestamp}] MONITORING ACTIVE ── TOTAL DETECTED: ${data.total_attacks} ── BREACHES: ${data.successful_breaches} ── UNIQUE ATTACKERS: ${data.unique_ips}`;
        }
    } catch (err) {
        console.error("Error fetching stats:", err);
    }
}

function updateElementValue(id, newValue) {
    const el = document.getElementById(id);
    if (el && el.innerText !== String(newValue)) {
        el.innerText = newValue;
    }
}

async function fetchRecentLogs() {
    try {
        const response = await fetch('/api/live_attacks');
        const data = await response.json();
        const terminalEl = document.getElementById("terminalWindow");

        if (terminalEl && data.attacks && data.attacks.length > 0) {
            terminalEl.innerHTML = "";
            data.attacks.slice(0, 12).forEach(attack => {
                const line = document.createElement("div");
                line.className = "terminal-line";
                const isSuccess = attack.status === "SUCCESS";
                const badgeColor = isSuccess ? "breach" : "cmd";
                const statusTag = isSuccess ? "[BREACH SUCCESS]" : "[LOGIN FAIL]";
                
                let detail = `User: ${attack.username} | Pass: ${attack.password}`;
                if (attack.command) {
                    detail = `CMD EXECUTED: ${attack.command}`;
                }

                line.innerHTML = `
                    <span class="terminal-timestamp">[${attack.time}]</span>
                    <span class="terminal-prompt">&gt;</span>
                    <span class="terminal-text ${badgeColor}">IP: ${attack.ip_address} (${attack.country}) ── ${statusTag} ── ${detail}</span>
                `;
                terminalEl.appendChild(line);
            });
        }
    } catch (err) {
        console.error("Error fetching recent logs:", err);
    }
}

// Initialize on page load
document.addEventListener("DOMContentLoaded", () => {
    updateClock();
    setInterval(updateClock, 1000);

    fetchLiveStats();
    fetchRecentLogs();
    
    // Auto-poll stats every 3 seconds
    setInterval(fetchLiveStats, 3000);
});
