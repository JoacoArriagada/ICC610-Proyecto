const DATA_BASE = '/data/results';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

const AppState = {
    currentView: 'resumen',
    dataset: null,
    filteredRepos: [],
    severityFilter: 'all',
    searchQuery: '',
    dateFilter: 'all',
    viewSeverityFilter: 'all',
    chartsManager: null,
};

const DatasetLoader = {
    async load() {
        await new Promise(resolve => setTimeout(resolve, 300));

        const ts = Date.now();
        const reposMeta = await fetch(`${DATA_BASE}/repos_activos.json?t=${ts}`).then(r => r.json());

        if (!Array.isArray(reposMeta) || reposMeta.length === 0) {
            throw new Error('No se encontraron repositorios en repos_activos.json');
        }

        const repoNames = reposMeta.map(r => r.name);

        const vulnData = {};
        const sastData = {};
        const sbomData = {};
        const cicdData = {};

        await Promise.all(repoNames.map(async repo => {
            try {
                const v = await fetch(`${DATA_BASE}/vulns/${repo}_vuln.json?t=${ts}`).then(r => r.json());
                vulnData[repo] = v;
            } catch (e) {
                vulnData[repo] = { matches: [] };
            }
            try {
                const s = await fetch(`${DATA_BASE}/sast/${repo}-codeql.json?t=${ts}`).then(r => {
                    if (!r.ok) throw new Error('Not found');
                    return r.json();
                });
                if (s.sarif_metadata && s.sarif_metadata.tool && s.sarif_metadata.tool.name === 'unknown') {
                    sastData[repo] = { error: true, total_issues: 0, issues: [] };
                } else {
                    sastData[repo] = s;
                }
            } catch (e) {
                sastData[repo] = { error: true, total_issues: 0, issues: [] };
            }
            try {
                const sb = await fetch(`${DATA_BASE}/sboms/${repo}_sbom.json?t=${ts}`).then(r => r.json());
                sbomData[repo] = sb;
            } catch (e) {
                sbomData[repo] = { artifacts: [] };
            }
            try {
                const ci = await fetch(`${DATA_BASE}/cicd/${repo}_cicd.json?t=${ts}`).then(r => r.json());
                cicdData[repo] = ci;
            } catch (e) {
                cicdData[repo] = { hallazgos: [] };
            }
        }));

        return this.transform(reposMeta, vulnData, sastData, sbomData, cicdData);
    },

    transform(reposMeta, vulnData, sastData, sbomData, cicdData) {
        const repositories = [];
        let totalVulns = 0;
        let totalDeps = 0;

        reposMeta.forEach(meta => {
            const repoName = meta.name;
            const vulns = vulnData[repoName] || { matches: [] };
            const sast = sastData[repoName] || { issues: [] };
            const sbom = sbomData[repoName] || { artifacts: [] };
            const cicd = cicdData[repoName] || { hallazgos: [] };

            const vulnerabilities = [];

            vulns.matches.forEach((match, idx) => {
                const v = match.vulnerability;
                const a = match.artifact;
                const severity = (v.severity || 'Low').toLowerCase();
                const cvssItem = (v.cvss && Array.isArray(v.cvss)) ? v.cvss.find(c => c && c.metrics && c.metrics.baseScore !== undefined) : null;
                const cvssScore = cvssItem ? cvssItem.metrics.baseScore : null;
                const location = a.locations && a.locations.length > 0 ? a.locations[0].path : '';
                const detectedAt = (v.fix && v.fix.available && v.fix.available.length > 0 && v.fix.available[0].date)
                    ? v.fix.available[0].date + 'T00:00:00Z'
                    : '2025-01-01T00:00:00Z';

                vulnerabilities.push({
                    id: v.id || `GRYPE-${idx}`,
                    severity: severity,
                    type: a.type || 'dependency',
                    source: 'Grype',
                    file: location,
                    lineStart: null,
                    lineEnd: null,
                    description: (v.description || '').substring(0, 200),
                    cve: (v.id && v.id.startsWith('CVE')) ? v.id : null,
                    cvss: cvssScore,
                    detectedAt: detectedAt,
                    artifactName: a.name,
                    artifactVersion: a.version,
                });
            });

            if (sast.issues && sast.issues.length > 0) {
                sast.issues.forEach((issue, idx) => {
                    const sevMap = { error: 'critical', warning: 'high', note: 'medium' };
                    const sev = sevMap[issue.level] || sevMap[issue.severity] || 'low';
                    const loc = issue.file || (issue.locations && issue.locations[0] && issue.locations[0].physicalLocation ? issue.locations[0].physicalLocation.artifactLocation.uri || '' : '');
                    const region = issue.region || (issue.locations && issue.locations[0] && issue.locations[0].physicalLocation ? issue.locations[0].physicalLocation.region : null);

                    vulnerabilities.push({
                        id: issue.rule_id || issue.ruleId || `SAST-${idx}`,
                        severity: sev,
                        type: 'SAST',
                        source: 'CodeQL',
                        file: loc,
                        lineStart: region ? region.startLine : null,
                        lineEnd: region ? region.endLine : null,
                        description: typeof issue.message === 'string'
                            ? issue.message.substring(0, 200)
                            : (issue.message && issue.message.text || '').substring(0, 200),
                        cve: null,
                        cvss: null,
                        detectedAt: '2025-01-01T00:00:00Z',
                        artifactName: null,
                        artifactVersion: null,
                    });
                });
            }

            const cicdIssues = [];
            if (cicd.hallazgos) {
                cicd.hallazgos.forEach(h => {
                    if (h.issues) {
                        h.issues.forEach(issueText => {
                            cicdIssues.push({
                                workflow: h.workflow,
                                issue: issueText,
                            });
                        });
                    }
                });
            }

            const dependencies = this.transformDependencies(sbom.artifacts || []);

            repositories.push({
                id: `REPO-${meta.name}`,
                name: meta.name,
                url: meta.clone_url,
                language: meta.language,
                vulnerabilityCount: vulnerabilities.length,
                lastAnalysis: '2025-01-15T00:00:00Z',
                vulnerabilities: vulnerabilities,
                dependencies: dependencies,
                cicdIssues: cicdIssues,
                stargazers: meta.stargazers_count,
                sbomArtifactCount: (sbom.artifacts || []).length,
                sastError: sast.error === true,
            });

            totalVulns += vulnerabilities.length;
            totalDeps += dependencies.length;
        });

        let orgName = 'Organización';
        if (reposMeta.length > 0 && reposMeta[0].clone_url) {
            const match = reposMeta[0].clone_url.match(/github\.com\/([^\/]+)\//);
            if (match && match[1]) {
                orgName = match[1];
            } else {
                orgName = reposMeta[0].name.split('/')[0];
            }
        }

        const timeline = this.buildTimeline(repositories);

        return {
            organization: {
                name: orgName,
                id: 'ORG-ANALYZED',
                analyzedAt: new Date().toISOString(),
                totalRepositories: repositories.length,
                totalVulnerabilities: totalVulns,
                totalDependencies: totalDeps,
                repositories: repositories,
            },
            timeline: timeline,
        };
    },

    buildTimeline(repositories) {
        const yearCount = {};
        const vulnsByDate = [];
        const now = new Date();

        repositories.forEach(r => {
            r.vulnerabilities.forEach(v => {
                let year = null;
                let dateLabel = 'Desconocido';

                if (v.detectedAt && v.detectedAt.startsWith('20')) {
                    const d = new Date(v.detectedAt);
                    if (!isNaN(d.getTime())) {
                        year = d.getFullYear();
                        dateLabel = d.toISOString().split('T')[0];
                    }
                }

                if (v.cve) {
                    const cveYearMatch = v.cve.match(/^CVE-(\d{4})-/);
                    if (cveYearMatch && cveYearMatch[1]) {
                        const cveYear = parseInt(cveYearMatch[1], 10);
                        if (year === null) {
                            year = cveYear;
                            dateLabel = `${cveYear}-01-01`;
                        }
                        if (!yearCount[cveYear]) {
                            yearCount[cveYear] = { year: cveYear, count: 0 };
                        }
                        yearCount[cveYear].count++;
                    }
                } else if (year !== null) {
                    if (!yearCount[year]) {
                        yearCount[year] = { year: year, count: 0 };
                    }
                    yearCount[year].count++;
                }

                vulnsByDate.push({
                    id: v.id,
                    severity: v.severity,
                    repoName: r.name,
                    date: dateLabel,
                    cve: v.cve,
                    artifactName: v.artifactName || v.type,
                    source: v.source,
                    cvss: v.cvss,
                });
            });
        });

        const years = Object.values(yearCount).sort((a, b) => a.year - b.year);
        let cumulative = 0;
        const yearlyData = years.map(y => {
            cumulative += y.count;
            return { year: y.year, count: y.count, cumulative: cumulative };
        });

        vulnsByDate.sort((a, b) => b.date.localeCompare(a.date));

        const minYear = yearlyData.length > 0 ? yearlyData[0].year : now.getFullYear() - 3;
        const maxYear = yearlyData.length > 0 ? yearlyData[yearlyData.length - 1].year : now.getFullYear();

        return {
            yearlyData: yearlyData,
            vulnsByDate: vulnsByDate,
            minYear: minYear,
            maxYear: maxYear,
            totalTimelineVulns: vulnsByDate.length,
            oldestVulnYear: minYear,
            newestVulnYear: maxYear,
        };
    },

    transformDependencies(artifacts) {
        if (!artifacts || artifacts.length === 0) return [];

        const depMap = new Map();
        const transitiveNames = new Set();

        artifacts.forEach(a => {
            const name = a.name || 'unknown';
            const key = `${name}@${a.version || 'unknown'}`;
            if (!depMap.has(key)) {
                depMap.set(key, {
                    name: name,
                    version: a.version || 'unknown',
                    source: 'Syft',
                    vulnerabilities: 0,
                    type: a.type || 'unknown',
                    licenses: (a.licenses && a.licenses.length > 0) ? a.licenses : [],
                    children: [],
                });
            }
            const meta = a.metadata || {};
            const rawDeps = meta.dependencies || [];
            if (Array.isArray(rawDeps) && rawDeps.length > 0) {
                depMap.get(key).children = rawDeps.map(d => ({
                    name: typeof d === 'string' ? d : d.name,
                }));
                rawDeps.forEach(d => {
                    transitiveNames.add(typeof d === 'string' ? d : d.name);
                });
            }
        });

        return Array.from(depMap.values()).map(d => ({
            ...d,
            dependencyType: transitiveNames.has(d.name) ? 'Transitiva' : 'Directa',
        }));
    },
};

const GlobalFilters = {
    apply(dataset, filters) {
        let repos = [...dataset.organization.repositories];

        if (filters.searchQuery) {
            const q = filters.searchQuery.toLowerCase();
            repos = repos.filter(r =>
                r.name.toLowerCase().includes(q) ||
                r.language.toLowerCase().includes(q)
            );
        }

        if (filters.severityFilter && filters.severityFilter !== 'all') {
            const minIdx = SEVERITY_ORDER.indexOf(filters.severityFilter);
            repos = repos.map(r => {
                const filteredVulns = r.vulnerabilities.filter(v => {
                    const vIdx = SEVERITY_ORDER.indexOf(v.severity);
                    return vIdx >= 0 && vIdx <= minIdx;
                });
                return { ...r, vulnerabilities: filteredVulns, vulnerabilityCount: filteredVulns.length };
            });
        }

        if (filters.dateFilter && filters.dateFilter !== 'all') {
            const daysMap = { '7d': 7, '30d': 30, '90d': 90 };
            const days = daysMap[filters.dateFilter];
            const cutoff = new Date();
            cutoff.setDate(cutoff.getDate() - days);
            repos = repos.filter(r => new Date(r.lastAnalysis) >= cutoff);
        }

        return repos;
    },

    getSummaryStats(repos) {
        let totalVulns = 0;
        let critical = 0, high = 0, medium = 0, low = 0;
        const typeCount = {};
        const sourceCount = { Grype: 0, CodeQL: 0 };
        let totalCvss = 0, cvssCount = 0;

        repos.forEach(r => {
            r.vulnerabilities.forEach(v => {
                totalVulns++;
                if (v.severity === 'critical') critical++;
                else if (v.severity === 'high') high++;
                else if (v.severity === 'medium') medium++;
                else if (v.severity === 'low') low++;
                typeCount[v.type] = (typeCount[v.type] || 0) + 1;
                sourceCount[v.source] = (sourceCount[v.source] || 0) + 1;
                if (v.cvss !== null && v.cvss !== undefined) {
                    totalCvss += v.cvss;
                    cvssCount++;
                }
            });
        });

        const sortedTypes = Object.entries(typeCount)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10);

        return {
            totalVulns,
            totalRepos: repos.length,
            critical, high, medium, low,
            typeCount: sortedTypes,
            sourceCount,
            cleanRepos: repos.filter(r => r.vulnerabilities.length === 0).length,
            avgCvss: cvssCount > 0 ? (totalCvss / cvssCount).toFixed(1) : 'N/A',
        };
    },
};

const ViewRenderer = {
    render(viewName) {
        const container = document.getElementById('view-container');
        AppState.currentView = viewName;

        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.view === viewName);
        });

        container.innerHTML = '';

        switch (viewName) {
            case 'resumen': this.renderResumen(container); break;
            case 'severidad': this.renderSeveridad(container); break;
            case 'repositorios': this.renderRepositorios(container); break;
            case 'evolucion': this.renderEvolucion(container); break;
            case 'sbom': this.renderSBOM(container); break;
            default: this.renderResumen(container);
        }

        if (AppState.chartsManager) {
            AppState.chartsManager.destroyAll();
        }
        AppState.chartsManager = new ChartsManager(AppState.filteredRepos);
        AppState.chartsManager.init(viewName);

        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    },

    renderResumen(container) {
        const stats = GlobalFilters.getSummaryStats(AppState.filteredRepos);
        const severityPercent = stats.totalVulns > 0
            ? {
                critical: ((stats.critical / stats.totalVulns) * 100).toFixed(1),
                high: ((stats.high / stats.totalVulns) * 100).toFixed(1),
                medium: ((stats.medium / stats.totalVulns) * 100).toFixed(1),
                low: ((stats.low / stats.totalVulns) * 100).toFixed(1),
            }
            : { critical: 0, high: 0, medium: 0, low: 0 };

        container.innerHTML = `
            <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                <div class="stat-card animate-slide-up" style="animation-delay: 0ms;">
                    <div class="stat-card__icon bg-red-100">
                        <i data-lucide="shield-alert" class="w-5 h-5 text-red-600"></i>
                    </div>
                    <div>
                        <div class="stat-card__value">${stats.critical}</div>
                        <div class="stat-card__label">Críticas</div>
                    </div>
                </div>
                <div class="stat-card animate-slide-up" style="animation-delay: 80ms;">
                    <div class="stat-card__icon bg-orange-100">
                        <i data-lucide="alert-triangle" class="w-5 h-5 text-orange-600"></i>
                    </div>
                    <div>
                        <div class="stat-card__value">${stats.high}</div>
                        <div class="stat-card__label">Altas</div>
                    </div>
                </div>
                <div class="stat-card animate-slide-up" style="animation-delay: 160ms;">
                    <div class="stat-card__icon bg-yellow-100">
                        <i data-lucide="alert-circle" class="w-5 h-5 text-yellow-600"></i>
                    </div>
                    <div>
                        <div class="stat-card__value">${stats.medium}</div>
                        <div class="stat-card__label">Medias</div>
                    </div>
                </div>
                <div class="stat-card animate-slide-up" style="animation-delay: 240ms;">
                    <div class="stat-card__icon bg-green-100">
                        <i data-lucide="check-circle" class="w-5 h-5 text-green-600"></i>
                    </div>
                    <div>
                        <div class="stat-card__value">${stats.low}</div>
                        <div class="stat-card__label">Bajas</div>
                    </div>
                </div>
            </div>

            <div class="dashboard-grid mb-6">
                <div class="card animate-slide-up" style="animation-delay: 300ms;">
                    <div class="card__header">
                        <h3 class="card__title">Distribución por Severidad</h3>
                        <span class="card__subtitle">Donut Chart</span>
                    </div>
                    <div class="card__body">
                        <div class="relative" style="max-width: 320px; margin: 0 auto;">
                            <canvas id="chart-donut-severity"></canvas>
                        </div>
                        <div class="flex justify-center gap-4 mt-3 flex-wrap text-xs">
                            <span class="flex items-center gap-1"><span class="w-3 h-3 rounded-full bg-red-500 inline-block"></span> Crítica ${severityPercent.critical}%</span>
                            <span class="flex items-center gap-1"><span class="w-3 h-3 rounded-full bg-orange-500 inline-block"></span> Alta ${severityPercent.high}%</span>
                            <span class="flex items-center gap-1"><span class="w-3 h-3 rounded-full bg-yellow-500 inline-block"></span> Media ${severityPercent.medium}%</span>
                            <span class="flex items-center gap-1"><span class="w-3 h-3 rounded-full bg-green-500 inline-block"></span> Baja ${severityPercent.low}%</span>
                        </div>
                    </div>
                </div>

                <div class="card animate-slide-up" style="animation-delay: 380ms;">
                    <div class="card__header">
                        <h3 class="card__title">Top Tipos de Vulnerabilidad</h3>
                        <span class="card__subtitle">Análisis de Pareto</span>
                    </div>
                    <div class="card__body">
                        <canvas id="chart-hbar-types"></canvas>
                    </div>
                </div>
            </div>

            <div class="card animate-slide-up" style="animation-delay: 460ms;">
                <div class="card__header">
                    <h3 class="card__title">Últimas Vulnerabilidades Detectadas</h3>
                    <span class="card__subtitle">${stats.totalVulns} hallazgos en ${stats.totalRepos} repositorios</span>
                </div>
                <div class="card__body card__body--no-padding overflow-x-auto">
                    ${this.buildSeverityFilterBar(stats)}
                    ${this.buildVulnerabilityTable(AppState.filteredRepos, 5)}
                </div>
            </div>
        `;
    },

    renderSeveridad(container) {
        const stats = GlobalFilters.getSummaryStats(AppState.filteredRepos);
        container.innerHTML = `
            <div class="dashboard-grid--3col mb-6">
                <div class="card col-span-full lg:col-span-2 animate-slide-up">
                    <div class="card__header">
                        <h3 class="card__title">Donut de Severidad - Impacto Global</h3>
                        <span class="card__subtitle">Click en segmento para filtrar</span>
                    </div>
                    <div class="card__body flex items-center justify-center">
                        <div class="relative" style="max-width: 380px; width: 100%;">
                            <canvas id="chart-donut-severity-large"></canvas>
                        </div>
                    </div>
                </div>
                <div class="card animate-slide-up" style="animation-delay: 100ms;">
                    <div class="card__header">
                        <h3 class="card__title">Resumen Rápido</h3>
                    </div>
                    <div class="card__body space-y-3">
                        <div class="flex justify-between py-2 border-b border-[#E8ECF0]"><span class="text-sm text-[#88AABF]">Total Vulnerabilidades</span><span class="font-bold text-[#023E73]">${stats.totalVulns}</span></div>
                        <div class="flex justify-between py-2 border-b border-[#E8ECF0]"><span class="text-sm text-[#88AABF]">Repositorios afectados</span><span class="font-bold text-[#023E73]">${stats.totalRepos - stats.cleanRepos}</span></div>
                        <div class="flex justify-between py-2 border-b border-[#E8ECF0]"><span class="text-sm text-[#88AABF]">Repositorios limpios</span><span class="font-bold text-green-600">${stats.cleanRepos}</span></div>
                        <div class="flex justify-between py-2 border-b border-[#E8ECF0]"><span class="text-sm text-[#88AABF]">Grype</span><span class="font-bold text-[#023E73]">${stats.sourceCount.Grype || 0}</span></div>
                        <div class="flex justify-between py-2"><span class="text-sm text-[#88AABF]">CodeQL</span><span class="font-bold text-[#023E73]">${stats.sourceCount.CodeQL || 0}</span></div>
                    </div>
                </div>
            </div>
            <div class="card animate-slide-up" style="animation-delay: 200ms;">
                <div class="card__header">
                    <h3 class="card__title">Detalle de Vulnerabilidades por Severidad</h3>
                </div>
                <div class="card__body card__body--no-padding overflow-x-auto">
                    ${this.buildSeverityFilterBar(stats)}
                    ${this.buildVulnerabilityTable(AppState.filteredRepos, 50)}
                </div>
            </div>
        `;
    },

    renderRepositorios(container) {
        container.innerHTML = `
            <div class="card animate-slide-up mb-6">
                <div class="card__header">
                    <h3 class="card__title">Comparativa por Repositorio (Stacked Bar)</h3>
                    <span class="card__subtitle">Volumen apilado por severidad</span>
                </div>
                <div class="card__body">
                    <div style="max-height: 450px; overflow-y: auto;">
                        <canvas id="chart-stacked-bar" style="min-height: 400px;"></canvas>
                    </div>
                </div>
            </div>
            <div class="card animate-slide-up" style="animation-delay: 150ms;">
                <div class="card__header">
                    <h3 class="card__title">Listado de Repositorios</h3>
                </div>
                <div class="card__body card__body--no-padding overflow-x-auto">
                    ${this.buildRepoTable(AppState.filteredRepos)}
                </div>
            </div>
        `;
    },

    renderEvolucion(container) {
        const timeline = AppState.dataset.timeline || { yearlyData: [], vulnsByDate: [], minYear: 2020, maxYear: 2026, totalTimelineVulns: 0, oldestVulnYear: null, newestVulnYear: null };
        const yearlyData = timeline.yearlyData || [];
        const vulnsByDate = timeline.vulnsByDate || [];
        const totalVulns = timeline.totalTimelineVulns || 0;
        const minYear = timeline.oldestVulnYear || timeline.minYear || 2020;
        const maxYear = timeline.newestVulnYear || timeline.maxYear || 2026;
        const yearSpan = (maxYear - minYear) || 1;

        const stats = GlobalFilters.getSummaryStats(AppState.filteredRepos);
        const avgAge = totalVulns > 0 ? yearSpan > 0 ? (new Date().getFullYear() - (minYear + Math.floor(yearSpan / 2))) : 'N/A' : 'N/A';

        const criticalOverTime = [];
        const highOverTime = [];
        let critCumul = 0; let highCumul = 0;
        yearlyData.forEach(y => {
            const yearVulns = vulnsByDate.filter(v => v.date.startsWith(String(y.year)));
            critCumul += yearVulns.filter(v => v.severity === 'critical').length;
            highCumul += yearVulns.filter(v => v.severity === 'high').length;
            criticalOverTime.push({ year: y.year, count: critCumul });
            highOverTime.push({ year: y.year, count: highCumul });
        });

        const latestVulns = vulnsByDate.slice(0, 10);

        container.innerHTML = `
            <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                <div class="stat-card animate-slide-up" style="animation-delay: 0ms;">
                    <div class="stat-card__icon bg-blue-100">
                        <i data-lucide="database" class="w-5 h-5 text-blue-600"></i>
                    </div>
                    <div>
                        <div class="stat-card__value">${totalVulns}</div>
                        <div class="stat-card__label">Vulns con fecha</div>
                    </div>
                </div>
                <div class="stat-card animate-slide-up" style="animation-delay: 80ms;">
                    <div class="stat-card__icon bg-indigo-100">
                        <i data-lucide="calendar-off" class="w-5 h-5 text-indigo-600"></i>
                    </div>
                    <div>
                        <div class="stat-card__value">${minYear || 'N/A'}</div>
                        <div class="stat-card__label">Año más antiguo</div>
                    </div>
                </div>
                <div class="stat-card animate-slide-up" style="animation-delay: 160ms;">
                    <div class="stat-card__icon bg-teal-100">
                        <i data-lucide="calendar-plus" class="w-5 h-5 text-teal-600"></i>
                    </div>
                    <div>
                        <div class="stat-card__value">${maxYear || 'N/A'}</div>
                        <div class="stat-card__label">Año más reciente</div>
                    </div>
                </div>
                <div class="stat-card animate-slide-up" style="animation-delay: 240ms;">
                    <div class="stat-card__icon bg-purple-100">
                        <i data-lucide="clock" class="w-5 h-5 text-purple-600"></i>
                    </div>
                    <div>
                        <div class="stat-card__value">${yearSpan}</div>
                        <div class="stat-card__label">Ventana (años)</div>
                    </div>
                </div>
            </div>

            <div class="dashboard-grid mb-6">
                <div class="card animate-slide-up col-span-full">
                    <div class="card__header">
                        <h3 class="card__title">Evolución de Vulnerabilidades por Año (CVE)</h3>
                        <span class="card__subtitle">Línea = Acumulado · Barra = Nuevas por año</span>
                    </div>
                    <div class="card__body">
                        <canvas id="chart-evolucion-timeline" style="max-height: 350px;"></canvas>
                    </div>
                </div>
            </div>

            <div class="dashboard-grid mb-6">
                <div class="card animate-slide-up" style="animation-delay: 100ms;">
                    <div class="card__header">
                        <h3 class="card__title">Vulnerabilidades por Año (Detalle)</h3>
                    </div>
                    <div class="card__body card__body--no-padding overflow-x-auto">
                        ${yearlyData.length > 0 ? `
                        <table class="table-zebra w-full">
                            <thead>
                                <tr>
                                    <th>Año</th>
                                    <th>Nuevas Vulns</th>
                                    <th>Acumulado</th>
                                    <th>% del Total</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${yearlyData.map(y => `
                                    <tr>
                                        <td class="font-bold text-[#023E73]">${y.year}</td>
                                        <td><span class="text-sm font-semibold">${y.count}</span></td>
                                        <td><span class="text-sm font-semibold text-[#03658C]">${y.cumulative}</span></td>
                                        <td>
                                            <div class="flex items-center gap-2">
                                                <div class="flex-1 h-2 bg-[#E8ECF0] rounded-full max-w-[100px]">
                                                    <div class="h-2 bg-[#03658C] rounded-full" style="width: ${totalVulns > 0 ? ((y.count / totalVulns) * 100).toFixed(0) : 0}%"></div>
                                                </div>
                                                <span class="text-xs text-[#88AABF]">${totalVulns > 0 ? ((y.count / totalVulns) * 100).toFixed(1) : 0}%</span>
                                            </div>
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                        ` : `<div class="empty-state"><p class="empty-state__text">Sin datos de evolución disponibles</p></div>`}
                    </div>
                </div>
                <div class="card animate-slide-up" style="animation-delay: 200ms;">
                    <div class="card__header">
                        <h3 class="card__title">Distribución Anual Acumulada</h3>
                    </div>
                    <div class="card__body">
                        <canvas id="chart-evolucion-area" style="max-height: 320px;"></canvas>
                    </div>
                </div>
            </div>

            <div class="card animate-slide-up" style="animation-delay: 300ms;">
                <div class="card__header">
                    <h3 class="card__title">Cronología de Vulnerabilidades</h3>
                    <span class="card__subtitle">${vulnsByDate.length} hallazgos con fecha registrada</span>
                </div>
                <div class="card__body card__body--no-padding overflow-x-auto">
                    ${latestVulns.length > 0 ? `
                    <table class="table-zebra w-full">
                        <thead>
                            <tr>
                                <th>Fecha</th>
                                <th>Vulnerabilidad</th>
                                <th>Severidad</th>
                                <th>Repositorio</th>
                                <th>Fuente</th>
                                <th>CVSS</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${latestVulns.map(v => `
                                <tr class="row-${v.severity}">
                                    <td class="text-xs font-mono text-[#88AABF] whitespace-nowrap">${v.date}</td>
                                    <td class="font-medium text-sm max-w-[250px] truncate" title="${this.escape((v.artifactName || '') + ' ' + v.id)}">${this.escape(v.id)}</td>
                                    <td><span class="severity-badge severity-badge--${v.severity}">${v.severity}</span></td>
                                    <td class="text-xs text-[#03658C]">${v.repoName}</td>
                                    <td><span class="text-xs px-2 py-0.5 rounded-full ${v.source === 'CodeQL' ? 'bg-purple-100 text-purple-700' : 'bg-teal-100 text-teal-700'}">${v.source}</span></td>
                                    <td><span class="font-bold text-sm ${v.cvss >= 9 ? 'text-red-600' : v.cvss >= 7 ? 'text-orange-600' : 'text-yellow-600'}">${v.cvss !== null ? v.cvss : '-'}</span></td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                    ` : `<div class="empty-state"><div class="empty-state__icon"><i data-lucide="clock" class="w-10 h-10 text-[#88AABF]"></i></div><p class="empty-state__title">Sin cronología</p><p class="empty-state__text">No se encontraron vulnerabilidades con fechas registradas.</p></div>`}
                </div>
            </div>
        `;
    },

    renderSBOM(container) {
        const allDeps = [];
        let totalDirectas = 0;
        let totalTransitivas = 0;
        AppState.filteredRepos.forEach(r => {
            if (r.dependencies) {
                r.dependencies.forEach(d => {
                    allDeps.push({ ...d, repoName: r.name, repoVulns: r.vulnerabilityCount, sbomCount: r.sbomArtifactCount });
                    if (d.dependencyType === 'Directa') totalDirectas++;
                    else totalTransitivas++;
                });
            }
        });

        container.innerHTML = `
            <div class="flex items-center gap-4 mb-4 flex-wrap">
                <label class="text-sm font-medium text-[#023E73]">Filtrar por fuente:</label>
                <select id="sbom-source-filter" class="text-sm border border-[#E0E6EB] rounded-lg bg-white px-3 py-2 focus:outline-none focus:ring-2 focus:ring-[#03658C]/30 cursor-pointer">
                    <option value="all">Todas (Syft SBOM)</option>
                    <option value="Syft">Syft (SBOM)</option>
                </select>
                <span class="text-xs text-[#88AABF]">${allDeps.length} dependencias (${totalDirectas} directas · ${totalTransitivas} transitivas)</span>
            </div>

            <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                <div class="stat-card animate-slide-up" style="animation-delay: 0ms;">
                    <div class="stat-card__icon bg-blue-100">
                        <i data-lucide="package" class="w-5 h-5 text-blue-600"></i>
                    </div>
                    <div>
                        <div class="stat-card__value">${allDeps.length}</div>
                        <div class="stat-card__label">Total Dependencias</div>
                    </div>
                </div>
                <div class="stat-card animate-slide-up" style="animation-delay: 80ms;">
                    <div class="stat-card__icon bg-green-100">
                        <i data-lucide="arrow-right-circle" class="w-5 h-5 text-green-600"></i>
                    </div>
                    <div>
                        <div class="stat-card__value">${totalDirectas}</div>
                        <div class="stat-card__label">Directas</div>
                    </div>
                </div>
                <div class="stat-card animate-slide-up" style="animation-delay: 160ms;">
                    <div class="stat-card__icon bg-orange-100">
                        <i data-lucide="git-branch" class="w-5 h-5 text-orange-600"></i>
                    </div>
                    <div>
                        <div class="stat-card__value">${totalTransitivas}</div>
                        <div class="stat-card__label">Transitivas</div>
                    </div>
                </div>
                <div class="stat-card animate-slide-up" style="animation-delay: 240ms;">
                    <div class="stat-card__icon bg-purple-100">
                        <i data-lucide="file-text" class="w-5 h-5 text-purple-600"></i>
                    </div>
                    <div>
                        <div class="stat-card__value">${totalDirectas > 0 ? (totalTransitivas / Math.max(totalDirectas, 1)).toFixed(1) : 0}x</div>
                        <div class="stat-card__label">Ratio Trans/Drct</div>
                    </div>
                </div>
            </div>

            <div class="dashboard-grid mb-6">
                <div class="card animate-slide-up col-span-full lg:col-span-2">
                    <div class="card__header">
                        <h3 class="card__title">Distribución de Artefactos por Repositorio</h3>
                        <span class="card__subtitle">SBOM Artifacts</span>
                    </div>
                    <div class="card__body">
                        <div id="treemap-container" style="min-height: 420px;"></div>
                    </div>
                </div>
                <div class="card animate-slide-up" style="animation-delay: 100ms;">
                    <div class="card__header">
                        <h3 class="card__title">Resumen SBOM</h3>
                    </div>
                    <div class="card__body card__body--no-padding overflow-x-auto">
                        ${this.buildSBOMSummaryTable(AppState.filteredRepos)}
                    </div>
                </div>
            </div>

            <div class="card animate-slide-up mb-6" style="animation-delay: 200ms;">
                <div class="card__header">
                    <h3 class="card__title">Dependencias por Tipo y Licencia</h3>
                    <span class="card__subtitle">Directas vs Transitivas con detalle de licencias</span>
                </div>
                <div class="card__body card__body--no-padding overflow-x-auto">
                    ${this.buildDependencyDetailTable(AppState.filteredRepos)}
                </div>
            </div>
        `;

        setTimeout(() => {
            if (AppState.chartsManager) {
                AppState.chartsManager.initTreeMap('treemap-container');
            }
        }, 100);
    },

    buildSeverityFilterBar(stats) {
        return `
            <div class="flex items-center gap-2 p-3 flex-wrap border-b border-[#E8ECF0]">
                <button class="severity-filter-btn ${AppState.viewSeverityFilter === 'all' ? 'active' : ''}" data-sev="all">
                    Todas <span class="count">${stats.totalVulns}</span>
                </button>
                <button class="severity-filter-btn ${AppState.viewSeverityFilter === 'critical' ? 'active' : ''}" data-sev="critical">
                    Críticas <span class="count">${stats.critical}</span>
                </button>
                <button class="severity-filter-btn ${AppState.viewSeverityFilter === 'high' ? 'active' : ''}" data-sev="high">
                    Altas <span class="count">${stats.high}</span>
                </button>
                <button class="severity-filter-btn ${AppState.viewSeverityFilter === 'medium' ? 'active' : ''}" data-sev="medium">
                    Medias <span class="count">${stats.medium}</span>
                </button>
                <button class="severity-filter-btn ${AppState.viewSeverityFilter === 'low' ? 'active' : ''}" data-sev="low">
                    Bajas <span class="count">${stats.low}</span>
                </button>
            </div>
        `;
    },

    buildVulnerabilityTable(repos, limit) {
        let allVulns = [];
        repos.forEach(r => {
            r.vulnerabilities.forEach(v => {
                if (AppState.viewSeverityFilter !== 'all' && v.severity !== AppState.viewSeverityFilter) return;
                allVulns.push({ ...v, repoName: r.name });
            });
        });

        allVulns.sort((a, b) => {
            return new Date(b.detectedAt) - new Date(a.detectedAt);
        });

        const displayed = allVulns.slice(0, limit);

        if (displayed.length === 0) {
            return `
                <div class="empty-state">
                    <div class="empty-state__icon">
                        <i data-lucide="shield-check" class="w-10 h-10 text-[#88AABF]"></i>
                    </div>
                    <p class="empty-state__title">Sin vulnerabilidades</p>
                    <p class="empty-state__text">No se encontraron vulnerabilidades con los filtros actuales.</p>
                </div>
            `;
        }

        return `
            <table class="table-zebra w-full">
                <thead>
                    <tr>
                        <th>Severidad</th>
                        <th>Artefacto</th>
                        <th>Repositorio</th>
                        <th>Archivo</th>
                        <th>Fuente</th>
                        <th>CVE</th>
                        <th>CVSS</th>
                    </tr>
                </thead>
                <tbody>
                    ${displayed.map(v => `
                        <tr class="row-${v.severity}">
                            <td><span class="severity-badge severity-badge--${v.severity}">${v.severity}</span></td>
                            <td class="font-medium text-sm max-w-[200px] truncate" title="${this.escape(v.artifactName || v.type)}">${this.escape(v.artifactName || v.type)}</td>
                            <td class="text-xs text-[#03658C]">${v.repoName}</td>
                            <td class="text-xs font-mono max-w-[150px] truncate" title="${this.escape(v.file)}">${this.escape(v.file)}</td>
                            <td><span class="text-xs px-2 py-0.5 rounded-full ${v.source === 'CodeQL' ? 'bg-purple-100 text-purple-700' : 'bg-teal-100 text-teal-700'}">${v.source}</span></td>
                            <td class="text-xs font-mono text-[#88AABF]">${v.cve || 'N/A'}</td>
                            <td><span class="font-bold text-sm ${v.cvss >= 9 ? 'text-red-600' : v.cvss >= 7 ? 'text-orange-600' : 'text-yellow-600'}">${v.cvss !== null ? v.cvss : '-'}</span></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    },

    buildRepoTable(repos) {
        if (repos.length === 0) {
            return `
                <div class="empty-state">
                    <div class="empty-state__icon">
                        <i data-lucide="folder-open" class="w-10 h-10 text-[#88AABF]"></i>
                    </div>
                    <p class="empty-state__title">Sin repositorios</p>
                    <p class="empty-state__text">No hay repositorios que coincidan con los filtros actuales.</p>
                </div>
            `;
        }

        return `
            <table class="table-zebra w-full">
                <thead>
                    <tr>
                        <th>Repositorio</th>
                        <th>Lenguaje</th>
                        <th>Vulnerabilidades</th>
                        <th>Stars</th>
                        <th>Artefactos SBOM</th>
                        <th>Estado</th>
                    </tr>
                </thead>
                <tbody>
                    ${repos.map(r => {
                        const critCount = r.vulnerabilities.filter(v => v.severity === 'critical').length;
                        const highCount = r.vulnerabilities.filter(v => v.severity === 'high').length;
                        let statusClass = '';
                        let statusText = '';
                        
                        if (r.sastError && r.vulnerabilityCount === 0) {
                            statusClass = 'bg-gray-100 text-gray-700';
                            statusText = 'Error SAST';
                        } else if (critCount > 0) {
                            statusClass = 'bg-red-100 text-red-700';
                            statusText = 'Crítico';
                        } else if (highCount > 0) {
                            statusClass = 'bg-orange-100 text-orange-700';
                            statusText = 'Alto';
                        } else if (r.vulnerabilityCount === 0) {
                            statusClass = 'bg-green-100 text-green-700';
                            statusText = 'Limpio';
                        } else {
                            statusClass = 'bg-yellow-100 text-yellow-700';
                            statusText = 'Medio';
                        }
                        return `
                            <tr>
                                <td class="font-medium text-[#023E73]">
                                    <a href="${r.url}" target="_blank" class="hover:text-[#03658C]">${r.name}</a>
                                </td>
                                <td><span class="text-xs px-2 py-1 bg-[#F0F7FB] rounded-full text-[#03658C]">${r.language}</span></td>
                                <td class="font-bold">${r.vulnerabilityCount}</td>
                                <td class="text-xs text-[#88AABF]">${r.stargazers ? r.stargazers.toLocaleString() : '-'}</td>
                                <td class="text-xs text-[#88AABF]">${r.sbomArtifactCount || 0}</td>
                                <td><span class="text-xs px-2 py-0.5 rounded-full font-medium ${statusClass}">${statusText}</span></td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
        `;
    },

    buildSBOMSummaryTable(repos) {
        if (repos.length === 0) {
            return `<div class="empty-state"><p class="empty-state__text text-sm">Sin datos SBOM</p></div>`;
        }

        let totalArtifacts = 0;
        let totalDeps = 0;
        let totalVulns = 0;
        repos.forEach(r => {
            totalArtifacts += r.sbomArtifactCount || 0;
            totalDeps += r.dependencies ? r.dependencies.length : 0;
            totalVulns += r.vulnerabilityCount || 0;
        });

        return `
            <table class="table-zebra w-full">
                <thead>
                    <tr>
                        <th>Repositorio</th>
                        <th>Artefactos</th>
                        <th>Dependencias</th>
                        <th>Vulns</th>
                    </tr>
                </thead>
                <tbody>
                    ${repos.map(r => `
                        <tr>
                            <td class="font-medium text-sm text-[#023E73]">${r.name}</td>
                            <td><span class="font-bold text-[#03658C]">${r.sbomArtifactCount || 0}</span></td>
                            <td><span class="font-bold text-[#03658C]">${r.dependencies ? r.dependencies.length : 0}</span></td>
                            <td><span class="font-bold ${r.vulnerabilityCount > 50 ? 'text-red-600' : r.vulnerabilityCount > 10 ? 'text-orange-600' : 'text-green-600'}">${r.vulnerabilityCount}</span></td>
                        </tr>
                    `).join('')}
                    ${(totalArtifacts > 0 || totalDeps > 0) ? `
                    <tr class="bg-[#F0F7FB] font-semibold">
                        <td class="text-[#023E73]">TOTAL</td>
                        <td class="text-[#03658C]">${totalArtifacts}</td>
                        <td class="text-[#03658C]">${totalDeps}</td>
                        <td class="text-[#03658C]">${totalVulns}</td>
                    </tr>
                    ` : ''}
                </tbody>
            </table>
        `;
    },

    buildDependencyDetailTable(repos) {
        const allDeps = [];
        const seen = new Set();

        repos.forEach(r => {
            if (r.dependencies) {
                r.dependencies.forEach(d => {
                    const key = `${d.name}@${d.version}`;
                    if (seen.has(key)) return;
                    seen.add(key);
                    allDeps.push({ ...d, repoName: r.name });
                });
            }
        });

        const sorted = allDeps.sort((a, b) => a.name.localeCompare(b.name));
        const displayed = sorted.slice(0, 50);
        const truncated = allDeps.length > 50;

        if (displayed.length === 0) {
            return `<div class="empty-state"><div class="empty-state__icon"><i data-lucide="package-open" class="w-10 h-10 text-[#88AABF]"></i></div><p class="empty-state__title">Sin dependencias</p><p class="empty-state__text">No se encontraron dependencias en los SBOMs.</p></div>`;
        }

        return `
            ${truncated ? `<div class="p-3 text-xs text-[#88AABF] bg-[#F9FAFB] border-b border-[#E8ECF0]">Mostrando ${displayed.length} de ${allDeps.length} dependencias. Usa el buscador global para filtrar por repositorio.</div>` : ''}
            <table class="table-zebra w-full">
                <thead>
                    <tr>
                        <th>Paquete</th>
                        <th>Versión</th>
                        <th>Tipo</th>
                        <th>Dependencia</th>
                        <th>Licencias</th>
                        <th>Repositorio</th>
                        <th>Sub-deps</th>
                    </tr>
                </thead>
                <tbody>
                    ${displayed.map(d => {
                        const licenseDisplay = (d.licenses && d.licenses.length > 0)
                            ? d.licenses.map(l => typeof l === 'string' ? l : (l.name || l.license || l.spdx || JSON.stringify(l))).join(', ')
                            : '<span class="text-[#88AABF] italic text-xs">N/D</span>';
                        const depTypeClass = d.dependencyType === 'Directa' ? 'bg-green-100 text-green-700' : 'bg-orange-100 text-orange-700';
                        return `
                        <tr>
                            <td class="font-medium text-sm text-[#023E73] max-w-[180px] truncate" title="${this.escape(d.name)}">${this.escape(d.name)}</td>
                            <td class="text-xs font-mono text-[#88AABF]">${this.escape(d.version)}</td>
                            <td><span class="text-xs px-2 py-0.5 rounded-full bg-[#F0F7FB] text-[#03658C]">${this.escape(d.type)}</span></td>
                            <td><span class="text-xs px-2 py-0.5 rounded-full font-medium ${depTypeClass}">${d.dependencyType}</span></td>
                            <td class="text-xs max-w-[140px] truncate" title="${licenseDisplay}">${licenseDisplay}</td>
                            <td class="text-xs text-[#03658C]">${d.repoName}</td>
                            <td class="text-center"><span class="text-xs font-semibold ${(d.children && d.children.length > 0) ? 'text-[#023E73]' : 'text-[#88AABF]'}">${d.children ? d.children.length : 0}</span></td>
                        </tr>
                    `}).join('')}
                </tbody>
            </table>
        `;
    },

    escape(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    },
};

function refreshView() {
    const dataset = AppState.dataset;
    if (!dataset) return;
    AppState.filteredRepos = GlobalFilters.apply(dataset, {
        searchQuery: AppState.searchQuery,
        severityFilter: AppState.severityFilter,
        dateFilter: AppState.dateFilter,
    });
    ViewRenderer.render(AppState.currentView);
    updateTopBarStats();
    bindSeverityFilterButtons();
}

function updateTopBarStats() {
    const stats = GlobalFilters.getSummaryStats(AppState.filteredRepos);
    document.getElementById('repo-count-display').textContent =
        `${stats.totalRepos} repositorios · ${stats.totalVulns} vulns`;
    document.getElementById('dataset-info').textContent =
        `Total: ${stats.totalVulns} vulnerabilidades · Grype: ${stats.sourceCount.Grype || 0} · CodeQL: ${stats.sourceCount.CodeQL || 0}`;

    const statusIndicator = document.getElementById('status-indicator');
    const statusText = document.getElementById('status-text');
    if (stats.critical > 0) {
        statusIndicator.className = 'w-2 h-2 rounded-full bg-red-400 animate-pulse-soft';
        statusText.textContent = 'Crítico';
    } else if (stats.high > 5) {
        statusIndicator.className = 'w-2 h-2 rounded-full bg-orange-400';
        statusText.textContent = 'Atención';
    } else {
        statusIndicator.className = 'w-2 h-2 rounded-full bg-green-400 animate-pulse-soft';
        statusText.textContent = 'Sistema Operativo';
    }
}

function bindSeverityFilterButtons() {
    document.querySelectorAll('.severity-filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            AppState.viewSeverityFilter = btn.dataset.sev;
            refreshView();
        });
    });
}

async function initApp() {
    console.log('Inicializando Miner-Visualizer...');

    document.getElementById('loading-placeholder').style.display = 'flex';

    try {
        AppState.dataset = await DatasetLoader.load();

        document.getElementById('org-name-sidebar').textContent = AppState.dataset.organization.name;

        AppState.filteredRepos = GlobalFilters.apply(AppState.dataset, {
            searchQuery: '',
            severityFilter: 'all',
            dateFilter: 'all',
            viewSeverityFilter: 'all',
        });

        document.getElementById('loading-placeholder').style.display = 'none';

        ViewRenderer.render('resumen');
        updateTopBarStats();
        bindSeverityFilterButtons();

        console.log('Miner-Visualizer inicializado correctamente');
    } catch (error) {
        console.error('Error al inicializar:', error);
        document.getElementById('loading-placeholder').innerHTML = `
            <div class="empty-state">
                <p class="empty-state__title text-red-600">Error al cargar datos</p>
                <p class="empty-state__text">${error.message}. Asegúrate de servir los archivos desde un servidor HTTP local.</p>
            </div>
        `;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    initApp();

    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            AppState.currentView = btn.dataset.view;
            AppState.viewSeverityFilter = 'all';
            refreshView();
        });
    });

    const sidebarToggle = document.getElementById('sidebar-toggle');
    const sidebar = document.getElementById('sidebar');
    let overlay = null;

    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', () => {
            sidebar.classList.toggle('open');
            if (!overlay) {
                overlay = document.createElement('div');
                overlay.className = 'sidebar-overlay';
                document.body.appendChild(overlay);
                overlay.addEventListener('click', () => {
                    sidebar.classList.remove('open');
                    overlay.classList.remove('active');
                });
            }
            overlay.classList.toggle('active');
        });
    }

    let searchDebounce;
    document.getElementById('global-search').addEventListener('input', e => {
        clearTimeout(searchDebounce);
        searchDebounce = setTimeout(() => {
            AppState.searchQuery = e.target.value;
            refreshView();
        }, 300);
    });

    document.getElementById('severity-filter').addEventListener('change', e => {
        AppState.severityFilter = e.target.value;
        AppState.viewSeverityFilter = 'all';
        refreshView();
    });

    document.getElementById('date-filter').addEventListener('change', e => {
        AppState.dateFilter = e.target.value;
        refreshView();
    });

    console.log('Event listeners registrados');
});
