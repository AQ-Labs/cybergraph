    (function () {
      const data = window.CYBERGRAPH || { nodes: [], edges: [], attack_paths: [] };
      const GROUP_COLORS = {
        entrypoint: '#2563eb', function: '#64748b', guard: '#16a34a', validator: '#0d9488',
        sink: '#dc2626', secret: '#d97706', dataflow: '#0891b2', dependency: '#7c3aed',
        vulnerability: '#991b1b', infrastructure: '#475569', call: '#cbd5e1', file: '#94a3b8'
      };
      const EDGE_COLORS = {
        EXPOSES_ENTRYPOINT: '#2563eb', CALLS: '#cbd5e1', GUARDS: '#16a34a', SANITIZES: '#0d9488',
        REACHES_SINK: '#dc2626', USES_SECRET: '#d97706', EXPOSES_SECRET: '#dc2626',
        USES_RESOURCE: '#475569', AFFECTS_DEPENDENCY: '#7c3aed', PATH: '#f59e0b', MODULE_LINK: '#94a3b8'
      };
      const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0, '': -1 };

      if (typeof cytoscape === 'undefined' || !document.getElementById('cy')) return;

      const rawNodes = data.nodes || [];
      const rawEdges = data.edges || [];
      const attackPaths = (data.attack_paths || []).slice().sort(function (a, b) {
        return ((b.risk && b.risk.score) || 0) - ((a.risk && a.risk.score) || 0);
      });
      const nodeById = new Map(rawNodes.map(function (n) { return [n.id, n]; }));

      function tail(id) {
        return String(id || '?').split('::').pop().split('/').pop();
      }

      function moduleName(file) {
        if (!file) return 'synthetic';
        const parts = String(file).split('/').filter(Boolean);
        if (parts.length <= 2) return parts.join('/') || file;
        return parts.slice(0, 3).join('/');
      }

      function cloneNode(id, overrides) {
        const base = nodeById.get(id) || {
          id: id,
          label: tail(id),
          group: 'call',
          kind: 'Synthetic',
          file: '',
          line: 0,
          severity: '',
          findings: [],
          properties: {},
          synthetic: true
        };
        return Object.assign({}, base, overrides || {});
      }

      function makeEdge(source, target, kind, id, extra) {
        return {
          data: Object.assign({
            id: id,
            source: source,
            target: target,
            kind: kind || 'PATH',
            label: kind || 'PATH'
          }, extra || {})
        };
      }

      function rawEdgeBetween(source, target) {
        return rawEdges.find(function (e) { return e.source === source && e.target === target; });
      }

      function buildRawElements() {
        const elements = [];
        rawNodes.forEach(function (n) { elements.push({ data: Object.assign({}, n) }); });
        rawEdges.forEach(function (e) {
          elements.push({
            data: {
              id: e.id,
              source: e.source,
              target: e.target,
              kind: e.kind,
              label: e.kind
            }
          });
        });
        return {
          elements: elements,
          layout: { name: 'breadthfirst', directed: true, padding: 24, spacingFactor: 1.25 },
          title: 'Raw Security Graph',
          subtitle: 'Advanced view of the capped graph export. Use filters to reduce noise.'
        };
      }

      function buildAttackPathElements() {
        const elements = [];
        const seenNodes = new Set();
        const paths = attackPaths.slice(0, 12);
        paths.forEach(function (path, pathIndex) {
          const ids = path.nodes || [];
          ids.forEach(function (id, nodeIndex) {
            if (!seenNodes.has(id)) {
              seenNodes.add(id);
              const isFirst = nodeIndex === 0;
              const isLast = nodeIndex === ids.length - 1;
              const group = isFirst ? 'entrypoint' : (isLast ? 'sink' : undefined);
              const risk = path.risk || {};
              elements.push({
                data: cloneNode(id, {
                  group: group || (nodeById.get(id) || {}).group || 'function',
                  severity: risk.label || (nodeById.get(id) || {}).severity || '',
                  risk_score: risk.score || ''
                }),
                position: { x: 90 + nodeIndex * 230, y: 70 + pathIndex * 105 }
              });
            }
          });
          for (let i = 0; i < ids.length - 1; i++) {
            const raw = rawEdgeBetween(ids[i], ids[i + 1]);
            elements.push(makeEdge(
              ids[i],
              ids[i + 1],
              raw ? raw.kind : 'PATH',
              'path-' + pathIndex + '-' + i,
              { risk_score: (path.risk && path.risk.score) || '' }
            ));
          }
        });
        return {
          elements: elements,
          layout: { name: 'preset', fit: true, padding: 44 },
          title: 'Attack Path Explorer',
          subtitle: 'Default view: the highest-risk entrypoint-to-sink paths, arranged left to right.'
        };
      }

      function buildRiskNeighborhoodElements() {
        const pathIds = new Set();
        attackPaths.slice(0, 8).forEach(function (path) {
          (path.nodes || []).forEach(function (id) { pathIds.add(id); });
        });
        const neighborhoodEdges = rawEdges.filter(function (e) {
          return pathIds.has(e.source) || pathIds.has(e.target);
        }).slice(0, 220);
        neighborhoodEdges.forEach(function (e) {
          pathIds.add(e.source);
          pathIds.add(e.target);
        });
        const elements = [];
        Array.from(pathIds).forEach(function (id) {
          elements.push({ data: cloneNode(id) });
        });
        neighborhoodEdges.forEach(function (e) {
          elements.push(makeEdge(e.source, e.target, e.kind, e.id));
        });
        return {
          elements: elements,
          layout: { name: 'cose', animate: false, padding: 30, idealEdgeLength: 90, nodeRepulsion: 6500 },
          title: 'Top-Risk Neighborhoods',
          subtitle: 'The highest-risk path nodes plus their immediate graph context.'
        };
      }

      function buildModuleElements() {
        const modules = new Map();
        rawNodes.forEach(function (node) {
          const module = moduleName(node.file);
          const current = modules.get(module) || { findings: 0, nodes: 0, severity: '' };
          current.nodes += 1;
          current.findings += (node.findings || []).length;
          if (SEV_RANK[node.severity || ''] > SEV_RANK[current.severity || '']) current.severity = node.severity;
          modules.set(module, current);
        });
        const ids = Array.from(modules.keys()).sort();
        const edgeCounts = new Map();
        rawEdges.forEach(function (edge) {
          const source = nodeById.get(edge.source);
          const target = nodeById.get(edge.target);
          const sourceModule = moduleName(source && source.file);
          const targetModule = moduleName(target && target.file);
          if (!sourceModule || !targetModule || sourceModule === targetModule) return;
          const key = sourceModule + ' -> ' + targetModule;
          edgeCounts.set(key, (edgeCounts.get(key) || 0) + 1);
        });
        const radius = Math.max(180, ids.length * 28);
        const elements = ids.map(function (id, index) {
          const meta = modules.get(id);
          const angle = (Math.PI * 2 * index) / Math.max(ids.length, 1);
          return {
            data: {
              id: 'module:' + id,
              label: id,
              group: meta.findings ? 'sink' : 'infrastructure',
              kind: 'Module',
              file: id,
              line: 0,
              severity: meta.severity,
              findings: [],
              synthetic: true,
              properties: { nodes: meta.nodes, findings: meta.findings }
            },
            position: { x: 420 + Math.cos(angle) * radius, y: 330 + Math.sin(angle) * radius }
          };
        });
        edgeCounts.forEach(function (count, key) {
          const parts = key.split(' -> ');
          elements.push(makeEdge('module:' + parts[0], 'module:' + parts[1], 'MODULE_LINK', 'module-edge:' + key, { weight: count }));
        });
        return {
          elements: elements,
          layout: { name: 'preset', fit: true, padding: 44 },
          title: 'Module Map',
          subtitle: 'A clustered overview by folder/module, useful for understanding architecture before drilling down.'
        };
      }

      const cy = cytoscape({
        container: document.getElementById('cy'),
        elements: [],
        wheelSensitivity: 0.2,
        style: [
          { selector: 'node', style: {
            'background-color': function (ele) { return GROUP_COLORS[ele.data('group')] || '#94a3b8'; },
            'label': 'data(label)', 'font-size': 10, 'font-weight': 600,
            'color': '#0b1220', 'text-outline-width': 2, 'text-outline-color': '#f8fafc',
            'text-wrap': 'ellipsis', 'text-max-width': 110, 'width': 24, 'height': 24,
            'border-width': 1, 'border-color': '#ffffff'
          } },
          { selector: 'node[group = "entrypoint"]', style: { 'width': 34, 'height': 26, 'shape': 'round-rectangle' } },
          { selector: 'node[group = "sink"]', style: { 'shape': 'triangle', 'width': 30, 'height': 30 } },
          { selector: 'node[group = "dataflow"]', style: { 'shape': 'hexagon' } },
          { selector: 'node[group = "vulnerability"]', style: { 'shape': 'diamond', 'width': 30, 'height': 30 } },
          { selector: 'node[kind = "Module"]', style: { 'width': 44, 'height': 44, 'font-size': 11, 'text-max-width': 140 } },
          { selector: 'node[severity = "critical"], node[severity = "high"]', style: { 'border-width': 3, 'border-color': '#dc2626' } },
          { selector: 'node[severity = "medium"]', style: { 'border-width': 2, 'border-color': '#d97706' } },
          { selector: 'edge', style: {
            'width': 1.4, 'curve-style': 'bezier', 'target-arrow-shape': 'triangle',
            'line-color': function (ele) { return EDGE_COLORS[ele.data('kind')] || '#cbd5e1'; },
            'target-arrow-color': function (ele) { return EDGE_COLORS[ele.data('kind')] || '#cbd5e1'; },
            'arrow-scale': 0.8
          } },
          { selector: 'edge[kind = "REACHES_SINK"], edge[kind = "PATH"]', style: { 'width': 3.2 } },
          { selector: 'edge[kind = "MODULE_LINK"]', style: { 'line-style': 'dashed', 'width': 2 } },
          { selector: '.cg-dim', style: { 'opacity': 0.12 } },
          { selector: '.cg-hl', style: { 'opacity': 1, 'border-width': 4, 'border-color': '#f59e0b', 'line-color': '#f59e0b', 'target-arrow-color': '#f59e0b', 'z-index': 99 } }
        ],
        layout: { name: 'preset' }
      });

      function updateViewText(view, built) {
        document.getElementById('cg-view-title').textContent = built.title;
        document.getElementById('cg-view-subtitle').textContent = built.subtitle;
        document.getElementById('cg-view-counts').textContent =
          cy.nodes().length + ' nodes / ' + cy.edges().length + ' edges';
      }

      function renderMode(mode) {
        const builders = {
          paths: buildAttackPathElements,
          risks: buildRiskNeighborhoodElements,
          modules: buildModuleElements,
          raw: buildRawElements
        };
        const built = (builders[mode] || buildAttackPathElements)();
        cy.elements().remove();
        cy.add(built.elements);
        cy.layout(built.layout).run();
        updateViewText(mode, built);
        applyFilters();
        document.getElementById('cg-details').innerHTML =
          '<p class="muted">Click a node to inspect its security evidence.</p>';
      }

      // Populate the layer filter from the groups actually present.
      const layerSelect = document.getElementById('cg-layer');
      const present = Array.from(new Set(rawNodes.map(function (n) { return n.group; }).concat(['module']))).sort();
      present.forEach(function (g) {
        const opt = document.createElement('option');
        opt.value = g; opt.textContent = g.charAt(0).toUpperCase() + g.slice(1);
        layerSelect.appendChild(opt);
      });

      // Populate the attack-path selector.
      const pathSelect = document.getElementById('cg-path');
      attackPaths.forEach(function (p, i) {
        const opt = document.createElement('option');
        opt.value = String(i);
        opt.textContent = (p.entrypoint || '?') + ' → ' + (p.sink || '?');
        pathSelect.appendChild(opt);
      });

      const riskStrip = document.getElementById('cg-risk-strip');
      attackPaths.slice(0, 6).forEach(function (p, i) {
        const card = document.createElement('button');
        card.type = 'button';
        card.className = 'risk-card';
        const score = (p.risk && p.risk.score) || '?';
        card.innerHTML = '<strong><span class="risk-score">' + esc(score) + '</span>' +
          esc(tail(p.entrypoint)) + ' → ' + esc(tail(p.sink)) + '</strong><span>' +
          esc((p.risk && p.risk.label) || 'risk') + ' · ' +
          esc(p.data_reachable ? 'data-reachable' : 'structural') + '</span>';
        card.addEventListener('click', function () {
          document.getElementById('cg-mode').value = 'paths';
          renderMode('paths');
          document.getElementById('cg-path').value = String(i);
          highlightPath(String(i));
        });
        riskStrip.appendChild(card);
      });

      function applyFilters() {
        const q = (document.getElementById('cg-search').value || '').toLowerCase();
        const layer = document.getElementById('cg-layer').value;
        const minSev = SEV_RANK[document.getElementById('cg-severity').value] ?? -1;
        cy.batch(function () {
          cy.nodes().forEach(function (n) {
            const hay = (n.data('label') + ' ' + (n.data('file') || '') + ' ' + n.data('group')).toLowerCase();
            const matchText = !q || hay.indexOf(q) !== -1;
            const matchLayer = !layer || n.data('group') === layer;
            const matchSev = (SEV_RANK[n.data('severity')] ?? -1) >= minSev;
            n.style('display', (matchText && matchLayer && matchSev) ? 'element' : 'none');
          });
          cy.edges().forEach(function (e) {
            const vis = e.source().style('display') !== 'none' && e.target().style('display') !== 'none';
            e.style('display', vis ? 'element' : 'none');
          });
        });
      }

      function highlightPath(idx) {
        if (document.getElementById('cg-mode').value !== 'paths') {
          document.getElementById('cg-mode').value = 'paths';
          renderMode('paths');
        }
        cy.elements().removeClass('cg-hl cg-dim');
        if (idx === '' || idx === null) return;
        const p = attackPaths[Number(idx)];
        if (!p) return;
        const ids = p.nodes || [];
        const inPath = cy.collection();
        ids.forEach(function (id) { inPath.merge(cy.getElementById(id)); });
        for (let i = 0; i < ids.length - 1; i++) {
          inPath.merge(cy.edges().filter(function (edge) {
            return edge.source().id() === ids[i] && edge.target().id() === ids[i + 1];
          }));
        }
        cy.elements().addClass('cg-dim');
        inPath.removeClass('cg-dim').addClass('cg-hl');
        if (inPath.length) cy.animate({ fit: { eles: inPath, padding: 60 }, duration: 350 });
      }

      function esc(s) { return String(s == null ? '' : s).replace(/[&<>]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]; }); }

      function showDetails(node) {
        const d = node.data();
        const color = GROUP_COLORS[d.group] || '#94a3b8';
        let html = '<h3>' + esc(d.label) + '</h3>';
        html += '<div class="kv"><span class="tag" style="background:' + color + '">' + esc(d.group) + '</span></div>';
        if (d.file) html += '<div class="kv"><strong>Location:</strong> <code>' + esc(d.file) + ':' + esc(d.line) + '</code></div>';
        html += '<div class="kv"><strong>Kind:</strong> ' + esc(d.kind) + '</div>';
        if (d.severity) html += '<div class="kv"><strong>Severity:</strong> ' + esc(d.severity) + '</div>';
        const findings = d.findings || [];
        if (findings.length) {
          html += '<div class="kv"><strong>Findings:</strong><ul>';
          findings.forEach(function (f) { html += '<li>' + esc(f.severity) + ' ' + esc(f.rule_id) + ': ' + esc(f.message) + '</li>'; });
          html += '</ul></div>';
        }
        const props = d.properties || {};
        const keys = Object.keys(props).filter(function (k) { return props[k] && k !== 'decorators'; });
        if (keys.length) {
          html += '<div class="kv"><strong>Properties:</strong><ul>';
          keys.forEach(function (k) { html += '<li>' + esc(k) + ': ' + esc(JSON.stringify(props[k])) + '</li>'; });
          html += '</ul></div>';
        }
        const neighbors = node.neighborhood('node').map(function (n) { return n.data('label'); });
        if (neighbors.length) html += '<div class="kv"><strong>Connected:</strong> ' + esc(neighbors.slice(0, 12).join(', ')) + '</div>';
        const snip = d.snippet;
        if (snip && snip.lines && snip.lines.length) {
          html += '<div class="kv"><strong>Source:</strong> <code>' + esc(snip.file) + '</code></div>';
          html += '<div class="cg-snippet">';
          snip.lines.forEach(function (ln) {
            html += '<div class="ln' + (ln.highlight ? ' hl' : '') + '"><span class="num">' + esc(ln.n) + '</span><span>' + ln.text + '</span></div>';
          });
          html += '</div>';
        }
        document.getElementById('cg-details').innerHTML = html;
      }

      cy.on('tap', 'node', function (evt) {
        cy.elements().removeClass('cg-hl cg-dim');
        const node = evt.target;
        const hood = node.closedNeighborhood();
        cy.elements().addClass('cg-dim');
        hood.removeClass('cg-dim');
        node.removeClass('cg-dim').addClass('cg-hl');
        showDetails(node);
      });
      cy.on('tap', function (evt) { if (evt.target === cy) cy.elements().removeClass('cg-hl cg-dim'); });

      document.getElementById('cg-mode').addEventListener('change', function (e) {
        document.getElementById('cg-path').value = '';
        renderMode(e.target.value);
      });
      document.getElementById('cg-search').addEventListener('input', applyFilters);
      document.getElementById('cg-layer').addEventListener('change', applyFilters);
      document.getElementById('cg-severity').addEventListener('change', applyFilters);
      document.getElementById('cg-path').addEventListener('change', function (e) { highlightPath(e.target.value); });
      document.getElementById('cg-layout').addEventListener('change', function (e) {
        cy.layout({ name: e.target.value, directed: true, padding: 12, spacingFactor: 1.1, animate: false }).run();
      });
      document.getElementById('cg-zoom-in').addEventListener('click', function () { cy.zoom(cy.zoom() * 1.2); });
      document.getElementById('cg-zoom-out').addEventListener('click', function () { cy.zoom(cy.zoom() / 1.2); });
      document.getElementById('cg-reset').addEventListener('click', function () {
        document.getElementById('cg-mode').value = 'paths';
        document.getElementById('cg-search').value = '';
        document.getElementById('cg-layer').value = '';
        document.getElementById('cg-severity').value = '';
        document.getElementById('cg-path').value = '';
        renderMode('paths');
      });
      renderMode('paths');
    })();
    const findingSearch = document.getElementById('cg-search');
    const findingSeverity = document.querySelector('[data-filter="findings-severity"]');
    function filterFindings() {
      const query = (findingSearch?.value || '').toLowerCase();
      const severity = findingSeverity?.value || '';
      document.querySelectorAll('[data-finding-row]').forEach((row) => {
        const matchesText = row.dataset.search.includes(query);
        const matchesSeverity = !severity || row.dataset.severity === severity;
        row.hidden = !(matchesText && matchesSeverity);
      });
    }
    findingSearch?.addEventListener('input', filterFindings);
    findingSeverity?.addEventListener('change', filterFindings);
    document.getElementById('cg-theme-toggle')?.addEventListener('click', function () {
      var cur = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', cur);
      try { localStorage.setItem('cybergraph-theme', cur); } catch (e) {}
    });
