class ChartsManager {
    constructor(repos) {
        this.repos = repos;
        this.charts = [];
        this.donutChartLarge = null;
        this.treemapSvg = null;
    }

    destroyAll() {
        this.charts.forEach(c => {
            try { c.destroy(); } catch (e) {}
        });
        this.charts = [];
        if (this.treemapSvg) {
            this.treemapSvg.selectAll('*').remove();
            this.treemapSvg = null;
        }
    }

    init(viewName) {
        switch (viewName) {
            case 'resumen':
                this.initDonutChart('chart-donut-severity', 280);
                this.initHBarChart('chart-hbar-types');
                break;
            case 'severidad':
                this.initDonutChartLarge('chart-donut-severity-large');
                break;
            case 'repositorios':
                this.initStackedBar('chart-stacked-bar');
                break;
            case 'sbom':
                break;
        }
    }

    getStats() {
        const repos = this.repos;
        let totalVulns = 0, critical = 0, high = 0, medium = 0, low = 0;
        const typeCount = {};

        repos.forEach(r => {
            r.vulnerabilities.forEach(v => {
                totalVulns++;
                if (v.severity === 'critical') critical++;
                else if (v.severity === 'high') high++;
                else if (v.severity === 'medium') medium++;
                else if (v.severity === 'low') low++;
                typeCount[v.type] = (typeCount[v.type] || 0) + 1;
            });
        });

        const sortedTypes = Object.entries(typeCount)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10);

        return { totalVulns, critical, high, medium, low, sortedTypes };
    }

    initDonutChart(canvasId, size) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        const stats = this.getStats();

        if (stats.totalVulns === 0) {
            ctx.font = '14px Inter';
            ctx.fillStyle = '#88AABF';
            ctx.textAlign = 'center';
            ctx.fillText('Sin datos', canvas.width / 2, canvas.height / 2);
            return;
        }

        const chart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Crítica', 'Alta', 'Media', 'Baja'],
                datasets: [{
                    data: [stats.critical, stats.high, stats.medium, stats.low],
                    backgroundColor: ['#DC2626', '#EA580C', '#F59E0B', '#22C55E'],
                    borderColor: '#FFFFFF',
                    borderWidth: 4,
                    hoverBorderWidth: 6,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                cutout: '65%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 12,
                            usePointStyle: true,
                            pointStyleWidth: 10,
                            font: { family: 'Inter', size: 11 },
                            color: '#023E73',
                        },
                    },
                    tooltip: {
                        backgroundColor: '#023E73',
                        titleFont: { family: 'Inter', weight: '600' },
                        bodyFont: { family: 'Inter' },
                        callbacks: {
                            label: function(ctx) {
                                const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                                const pct = total > 0 ? ((ctx.raw / total) * 100).toFixed(1) : 0;
                                return ` ${ctx.label}: ${ctx.raw} (${pct}%)`;
                            },
                        },
                    },
                },
            },
        });

        this.charts.push(chart);
    }

    initDonutChartLarge(canvasId) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        const stats = this.getStats();

        if (stats.totalVulns === 0) return;

        const self = this;
        const chart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Crítica', 'Alta', 'Media', 'Baja'],
                datasets: [{
                    data: [stats.critical, stats.high, stats.medium, stats.low],
                    backgroundColor: ['#DC2626', '#EA580C', '#F59E0B', '#22C55E'],
                    borderColor: '#FFFFFF',
                    borderWidth: 4,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                cutout: '60%',
                onClick: function(event, elements) {
                    if (elements.length > 0) {
                        const idx = elements[0].index;
                        const severities = ['critical', 'high', 'medium', 'low'];
                        if (AppState.viewSeverityFilter === severities[idx]) {
                            AppState.viewSeverityFilter = 'all';
                        } else {
                            AppState.viewSeverityFilter = severities[idx];
                        }
                        refreshView();
                    }
                },
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 16,
                            usePointStyle: true,
                            font: { family: 'Inter', size: 12 },
                            color: '#023E73',
                        },
                    },
                    tooltip: {
                        backgroundColor: '#023E73',
                        titleFont: { family: 'Inter', weight: '600' },
                        bodyFont: { family: 'Inter' },
                    },
                },
            },
        });

        this.charts.push(chart);
        this.donutChartLarge = chart;
    }

    initHBarChart(canvasId) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        const stats = this.getStats();

        if (stats.sortedTypes.length === 0) return;

        const chart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: stats.sortedTypes.map(t => t[0]),
                datasets: [{
                    label: 'Cantidad',
                    data: stats.sortedTypes.map(t => t[1]),
                    backgroundColor: stats.sortedTypes.map((_, i) => {
                        const colors = ['#03658C', '#024873', '#023E73', '#88AABF', '#03658C', '#024873', '#023E73', '#88AABF', '#03658C', '#024873'];
                        return colors[i] || '#03658C';
                    }),
                    borderRadius: 4,
                    borderSkipped: false,
                }],
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#023E73',
                        titleFont: { family: 'Inter', weight: '600' },
                        bodyFont: { family: 'Inter' },
                    },
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: { font: { family: 'Inter', size: 11 }, color: '#88AABF' },
                        grid: { color: '#E8ECF0' },
                    },
                    y: {
                        ticks: { font: { family: 'Inter', size: 11 }, color: '#023E73' },
                        grid: { display: false },
                    },
                },
            },
        });

        this.charts.push(chart);
    }

    initStackedBar(canvasId) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        const repos = this.repos;

        if (repos.length === 0) return;

        const labels = repos.map(r => r.name);
        const criticalData = repos.map(r => r.vulnerabilities.filter(v => v.severity === 'critical').length);
        const highData = repos.map(r => r.vulnerabilities.filter(v => v.severity === 'high').length);
        const mediumData = repos.map(r => r.vulnerabilities.filter(v => v.severity === 'medium').length);
        const lowData = repos.map(r => r.vulnerabilities.filter(v => v.severity === 'low').length);

        const chart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [
                    { label: 'Crítica', data: criticalData, backgroundColor: '#DC2626' },
                    { label: 'Alta', data: highData, backgroundColor: '#EA580C' },
                    { label: 'Media', data: mediumData, backgroundColor: '#F59E0B' },
                    { label: 'Baja', data: lowData, backgroundColor: '#22C55E' },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                        labels: { usePointStyle: true, font: { family: 'Inter', size: 11 }, color: '#023E73' },
                    },
                    tooltip: {
                        backgroundColor: '#023E73',
                        titleFont: { family: 'Inter', weight: '600' },
                        bodyFont: { family: 'Inter' },
                    },
                },
                scales: {
                    x: {
                        stacked: true,
                        ticks: { font: { family: 'Inter', size: 10 }, color: '#023E73' },
                        grid: { display: false },
                    },
                    y: {
                        stacked: true,
                        beginAtZero: true,
                        ticks: { font: { family: 'Inter', size: 11 }, color: '#88AABF' },
                        grid: { color: '#E8ECF0' },
                    },
                },
            },
        });

        this.charts.push(chart);
    }

    initTreeMap(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;

        container.innerHTML = '';

        const repos = this.repos;
        if (repos.length === 0) return;

        const data = {
            name: 'Repositorios',
            children: repos.map(r => ({
                name: r.name,
                value: r.sbomArtifactCount || r.dependencies.length || 1,
                vulns: r.vulnerabilityCount,
            })),
        };

        const width = container.clientWidth || 600;
        const height = 420;

        const color = d3.scaleOrdinal()
            .domain(repos.map(r => r.name))
            .range(['#023E73', '#024873', '#03658C', '#88AABF', '#5599BB']);

        const root = d3.treemap()
            .size([width, height])
            .padding(4)
            .round(true)(
            d3.hierarchy(data)
                .sum(d => d.value)
                .sort((a, b) => b.value - a.value)
        );

        const svg = d3.select(container)
            .append('svg')
            .attr('viewBox', `0 0 ${width} ${height}`)
            .attr('width', width)
            .attr('height', height)
            .style('max-width', '100%')
            .style('height', 'auto');

        const cell = svg.selectAll('g')
            .data(root.leaves())
            .join('g')
            .attr('transform', d => `translate(${d.x0},${d.y0})`);

        cell.append('rect')
            .attr('class', 'treemap-rect')
            .attr('width', d => d.x1 - d.x0)
            .attr('height', d => d.y1 - d.y0)
            .attr('fill', d => color(d.data.name))
            .append('title')
            .text(d => `${d.data.name}\nArtefactos: ${d.data.value}\nVulnerabilidades: ${d.data.vulns}`);

        cell.append('text')
            .attr('class', 'treemap-label')
            .attr('x', 6)
            .attr('y', 16)
            .text(d => {
                const w = d.x1 - d.x0;
                const maxChars = Math.floor(w / 7);
                const name = d.data.name;
                return name.length > maxChars ? name.substring(0, maxChars - 2) + '..' : name;
            });

        cell.append('text')
            .attr('class', 'treemap-label')
            .attr('x', 6)
            .attr('y', 32)
            .style('font-size', '0.6rem')
            .style('opacity', '0.8')
            .text(d => `${d.data.value} artefactos`);

        this.treemapSvg = svg;
    }
}
