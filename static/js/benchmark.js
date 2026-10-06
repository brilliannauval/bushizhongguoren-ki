/* ==========================================================================
   benchmark.js - Multi-Download Benchmark Engine with Live Chart.js
   ========================================================================== */

let avgTimeChart = null;
let iterationLineChart = null;
let throughputChart = null;

document.addEventListener("DOMContentLoaded", () => {
    const runBtn = document.getElementById("runBenchmarkBtn");
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

    runBtn.addEventListener("click", async () => {
        const itemType = document.getElementById("benchmarkItemType").value;
        const fileSelect = document.getElementById("benchmarkFileSelect");
        const fileId = fileSelect.value;
        const iterations = parseInt(document.getElementById("benchmarkIterations").value, 10);

        if (itemType === "file" && !fileId) {
            alert("Please select a file to benchmark, or choose 'GDPR / UU PDP Profile Data'.");
            return;
        }

        runBtn.disabled = true;
        runBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Executing Benchmark Iterations...';
        document.getElementById("benchmarkLoadingIndicator").classList.remove("d-none");
        document.getElementById("benchmarkResultsCard").classList.add("d-none");

        try {
            const resp = await fetch("/api/benchmark/run", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": csrfToken
                },
                body: JSON.stringify({
                    item_type: itemType,
                    file_id: itemType === "file" ? fileId : null,
                    iterations: iterations
                })
            });

            const data = await resp.json();
            if (!resp.ok) {
                alert("Benchmark error: " + (data.error || "Unknown server error"));
                return;
            }

            renderBenchmarkResults(data);
        } catch (err) {
            console.error("Benchmark failed:", err);
            alert("Network or server failure during benchmark: " + err.message);
        } finally {
            runBtn.disabled = false;
            runBtn.innerHTML = '<i class="fa-solid fa-play me-1"></i> Run Multi-Download Benchmark';
            document.getElementById("benchmarkLoadingIndicator").classList.add("d-none");
        }
    });

    // Toggle file selector dropdown visibility based on item type
    document.getElementById("benchmarkItemType").addEventListener("change", (e) => {
        const fileGroup = document.getElementById("fileSelectGroup");
        if (e.target.value === "profile") {
            fileGroup.classList.add("d-none");
        } else {
            fileGroup.classList.remove("d-none");
        }
    });
});

function renderBenchmarkResults(data) {
    document.getElementById("benchmarkResultsCard").classList.remove("d-none");
    document.getElementById("resultsTargetLabel").innerText = data.item;
    document.getElementById("resultsIterationLabel").innerText = data.iterations + " iterations";

    const res = data.results;
    const tableBody = document.getElementById("benchmarkSummaryTableBody");
    tableBody.innerHTML = "";

    const ciphers = ["aes", "des", "rc4"];
    const labels = ["AES-128-CBC", "DES-CBC", "RC4 (ARC4)"];
    const colors = ["#06b6d4", "#f59e0b", "#8b5cf6"];

    const avgTimes = [];
    const throughputs = [];
    const lineDatasets = [];

    ciphers.forEach((c, idx) => {
        const info = res[c];
        if (!info) return;

        avgTimes.push(info.avg_ms);
        throughputs.push(info.throughput_mbps);

        // Populate table row
        const row = document.createElement("tr");
        row.innerHTML = `
            <td><strong class="text-white">${labels[idx]}</strong></td>
            <td><span class="badge bg-secondary font-monospace">${info.ciphertext_size.toLocaleString()} B</span></td>
            <td><span class="badge badge-entropy">${info.entropy}</span></td>
            <td class="text-info fw-bold">${info.avg_ms} ms</td>
            <td>${info.min_ms} ms / ${info.max_ms} ms</td>
            <td>± ${info.std_dev} ms</td>
            <td class="text-success fw-bold">${info.throughput_mbps} MB/s</td>
        `;
        tableBody.appendChild(row);

        // Dataset for Line Chart (Iteration-by-iteration latency)
        lineDatasets.push({
            label: labels[idx],
            data: info.durations,
            borderColor: colors[idx],
            backgroundColor: colors[idx] + "33",
            tension: 0.2,
            pointRadius: 4,
            fill: false
        });
    });

    // 1. Avg Time Bar Chart
    const ctxBar = document.getElementById("avgTimeChart").getContext("2d");
    if (avgTimeChart) avgTimeChart.destroy();
    avgTimeChart = new Chart(ctxBar, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Mean Running Time (ms)',
                data: avgTimes,
                backgroundColor: colors,
                borderWidth: 1,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    title: { display: true, text: 'Running Time (ms)' },
                    grid: { color: 'rgba(255, 255, 255, 0.08)' }
                },
                x: {
                    grid: { display: false }
                }
            }
        }
    });

    // 2. Iteration Latency Line Chart
    const ctxLine = document.getElementById("iterationLineChart").getContext("2d");
    if (iterationLineChart) iterationLineChart.destroy();
    const iterLabels = Array.from({ length: data.iterations }, (_, i) => `Run #${i + 1}`);
    iterationLineChart = new Chart(ctxLine, {
        type: 'line',
        data: {
            labels: iterLabels,
            datasets: lineDatasets
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    title: { display: true, text: 'Latency (ms)' },
                    grid: { color: 'rgba(255, 255, 255, 0.08)' }
                },
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.08)' }
                }
            }
        }
    });

    // 3. Throughput Bar Chart
    const ctxTp = document.getElementById("throughputChart").getContext("2d");
    if (throughputChart) throughputChart.destroy();
    throughputChart = new Chart(ctxTp, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Decryption Throughput (MB/s)',
                data: throughputs,
                backgroundColor: ['#10b981', '#14b8a6', '#06b6d4'],
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    title: { display: true, text: 'Throughput (MB/s)' },
                    grid: { color: 'rgba(255, 255, 255, 0.08)' }
                },
                x: {
                    grid: { display: false }
                }
            }
        }
    });
}
