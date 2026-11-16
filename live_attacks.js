// ==========================================
// REAL-TIME LIVE ATTACKS PAGE CONTROLLER
// ==========================================

let currentFilter = "ALL";

function searchTable() {
    fetchFilteredAttacks();
}

function setFilter(filterType) {
    currentFilter = filterType;
    document.querySelectorAll(".filter-btn").forEach(btn => {
        btn.classList.remove("active");
    });
    const activeBtn = document.getElementById(`btn-${filterType.toLowerCase()}`);
    if (activeBtn) activeBtn.classList.add("active");
    
    fetchFilteredAttacks();
}

async function fetchFilteredAttacks() {
    const searchVal = document.getElementById("searchInput") ? document.getElementById("searchInput").value : "";
    const url = `/api/live_attacks?status=${currentFilter}&search=${encodeURIComponent(searchVal)}`;

    try {
        const response = await fetch(url);
        const data = await response.json();
        renderAttackTable(data.attacks);
    } catch (err) {
        console.error("Error fetching live attacks:", err);
    }
}

function renderAttackTable(attacks) {
    const tbody = document.getElementById("attackTableBody");
    if (!tbody) return;

    if (!attacks || attacks.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color: var(--text-muted); padding:30px;">No attack logs found matching current filter.</td></tr>`;
        return;
    }

    tbody.innerHTML = attacks.map(attack => {
        const isSuccess = attack.status === "SUCCESS";
        const badgeClass = isSuccess ? "badge-success" : "badge-failed";
        const threatClass = attack.threat_level === "CRITICAL" ? "badge-critical" : (attack.threat_level === "HIGH" ? "badge-high" : "badge-medium");
        
        let cmdHtml = attack.command ? `<span class="code-pill">${escapeHtml(attack.command)}</span>` : `<span style="color:var(--text-muted)">-</span>`;

        return `
            <tr>
                <td><strong style="color:var(--cyan-neon)">${escapeHtml(attack.ip_address)}</strong></td>
                <td><span class="code-pill">${escapeHtml(attack.username)}</span></td>
                <td><span class="code-pill">${escapeHtml(attack.password)}</span></td>
                <td>${escapeHtml(attack.country)}</td>
                <td>${escapeHtml(attack.date)} ${escapeHtml(attack.time)}</td>
                <td><span class="badge ${badgeClass}">${escapeHtml(attack.status)}</span></td>
                <td><span class="badge ${threatClass}">${escapeHtml(attack.threat_level)}</span></td>
                <td>${cmdHtml}</td>
            </tr>
        `;
    }).join("");
}

function escapeHtml(text) {
    if (!text) return "";
    return text.toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Auto-poll live attack table every 4 seconds
document.addEventListener("DOMContentLoaded", () => {
    fetchFilteredAttacks();
    setInterval(fetchFilteredAttacks, 4000);
});