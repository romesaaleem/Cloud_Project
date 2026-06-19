document.addEventListener("DOMContentLoaded", function () {
    fetch('/api/chart-data')
        .then(response => response.json())
        .then(data => {
            if (data.error) return;
            const pieCtx = document.getElementById('threatPieChart').getContext('2d');
            const pieLabels = Object.keys(data.threat_distribution);
            const pieValues = Object.values(data.threat_distribution);
            new Chart(pieCtx, {
                type: 'pie',
                data: {
                    labels: pieLabels.length ? pieLabels : ["No Incursions Found"],
                    datasets: [{ data: pieValues.length ? pieValues : [1], backgroundColor: ['#EF4444', '#F59E0B', '#3B82F6', '#10B981'] }]
                },
                options: { plugins: { legend: { labels: { color: '#9CA3AF' } } } }
            });

            const barCtx = document.getElementById('severityBarChart').getContext('2d');
            const sevLabels = ['Safe', 'Low', 'Medium', 'High', 'Critical'];
            const sevValues = sevLabels.map(label => data.severity_distribution[label] || 0);
            new Chart(barCtx, {
                type: 'bar',
                data: {
                    labels: sevLabels,
                    datasets: [{ data: sevValues, backgroundColor: ['#10B981', '#3B82F6', '#F59E0B', '#C2410C', '#EF4444'] }]
                },
                options: { scales: { x: { ticks: { color: '#9CA3AF' } }, y: { ticks: { color: '#9CA3AF' } } }, plugins: { legend: { display: false } } }
            });

            const lineCtx = document.getElementById('timelineLineChart').getContext('2d');
            const lineLabels = Object.keys(data.timeline_data).reverse();
            const lineValues = Object.values(data.timeline_data).reverse();
            new Chart(lineCtx, {
                type: 'line',
                data: {
                    labels: lineLabels.length ? lineLabels : ["Baseline"],
                    datasets: [{ label: 'Incursions', data: lineValues.length ? lineValues : [0], borderColor: '#3B82F6', fill: true, tension: 0.3 }]
                },
                options: { scales: { x: { ticks: { color: '#9CA3AF' } }, y: { ticks: { color: '#9CA3AF' } } }, plugins: { legend: { display: false } } }
            });
        });
});