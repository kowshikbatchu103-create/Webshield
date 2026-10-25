document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("scan-form");
    const urlInput = document.getElementById("target-url");
    const scanButton = document.getElementById("scan-button");
    const buttonText = document.getElementById("button-text");
    const scanStatus = document.getElementById("scan-status");
    const findingsBody = document.getElementById("findings-body");

    const historyBody = document.getElementById("history-body");
    const historyCount = document.getElementById("history-count");

    if (!form) {
        console.error("WebShield: scan form not found.");
        return;
    }

    function displayHistory(history) {
        if (!historyBody || !historyCount) {
            return;
        }

        historyCount.textContent = `${history.length} SCANS`;

        if (history.length === 0) {
            historyBody.innerHTML = `
                <tr>
                    <td colspan="4" class="empty-state">
                        <div class="empty-icon">◷</div>
                        <strong>No scan history yet</strong>
                        <p>Completed scans will appear here.</p>
                    </td>
                </tr>
            `;
            return;
        }

        historyBody.innerHTML = "";

        history.slice().reverse().forEach((scan) => {
            const row = document.createElement("tr");

            const targetCell = document.createElement("td");
            targetCell.textContent = scan.target;

            const dateCell = document.createElement("td");
            dateCell.textContent =
                new Date(scan.scanned_at).toLocaleString();

            const statusCell = document.createElement("td");
            statusCell.textContent = `HTTP ${scan.status_code}`;

            const findingsCell = document.createElement("td");
            findingsCell.textContent =
                `${scan.summary.total} findings`;

            row.appendChild(targetCell);
            row.appendChild(dateCell);
            row.appendChild(statusCell);
            row.appendChild(findingsCell);

            historyBody.appendChild(row);
        });
    }

    async function loadHistory() {
        try {
            const response = await fetch("/api/history");

            if (!response.ok) {
                throw new Error("Could not load scan history.");
            }

            const history = await response.json();
            displayHistory(history);

        } catch (error) {
            console.error("WebShield history error:", error);
        }
    }

    form.addEventListener("submit", async (event) => {
        event.preventDefault();

        const url = urlInput.value.trim();

        if (!url) {
            scanStatus.textContent = "Please enter an HTTPS URL.";
            return;
        }

        scanButton.disabled = true;
        buttonText.textContent = "Scanning...";
        scanStatus.textContent = "Checking the target...";
        findingsBody.innerHTML = "";

        try {
            const response = await fetch("/api/scan", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ url })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || "Scan request failed.");
            }

            document.getElementById("total-count").textContent =
                data.summary.total;

            document.getElementById("high-count").textContent =
                data.summary.high;

            document.getElementById("medium-count").textContent =
                data.summary.medium;

            document.getElementById("low-count").textContent =
                data.summary.low;

            document.getElementById("target-summary").textContent =
                `${data.target} · HTTP ${data.status_code}`;

            document.getElementById("result-count").textContent =
                `${data.findings.length} findings`;

            if (data.findings.length === 0) {
                findingsBody.innerHTML =
                    '<tr><td colspan="4">No findings from these checks.</td></tr>';
            } else {
                data.findings.forEach((finding) => {
                    const row = document.createElement("tr");

                    [
                        finding.title,
                        finding.severity,
                        finding.category,
                        finding.status
                    ].forEach((value) => {
                        const cell = document.createElement("td");
                        cell.textContent = value ?? "";
                        row.appendChild(cell);
                    });

                    findingsBody.appendChild(row);
                });
            }

            scanStatus.textContent =
                data.note || "Scan completed. Review findings manually.";

            // Refresh scan history after a successful scan
            await loadHistory();

        } catch (error) {
            scanStatus.textContent = error.message;
            console.error("WebShield scan error:", error);

        } finally {
            scanButton.disabled = false;
            buttonText.textContent = "Run Scan";
        }
    });

    // Load previous scans when the dashboard opens
    loadHistory();
});