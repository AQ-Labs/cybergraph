const id=location.hash.slice(1)||'welcome';
const logo='../../../../src/cybergraph/assets/brand-mark.svg';
const identity=(closing=false)=>`<div class="identity"><img src="${logo}" alt="CyberGraph logo"><h1>CyberGraph</h1><p>${closing?'Thank you for watching.':'Trace code. Inspect evidence.'}</p>${closing?'<div class="address">github.com/AQ-Labs/cybergraph</div>':''}</div>`;
const content=document.getElementById('content');
const tech=document.getElementById('tech');
if(id==='welcome'){
 content.innerHTML='<h1>Inspect. Question. Repair. Recheck.</h1><iframe id="report" src="report.html" title="Actual offline PyGoat report"></iframe>';
 document.body.insertAdjacentHTML('beforeend',identity());
 tech.textContent='Python static analysis | SQLite knowledge graph | Cytoscape.js explorer';
 document.getElementById('mode').textContent='Public PyGoat source: 19d17cc | No application execution';
}
if(id==='thanks'){
 document.querySelector('header').hidden=true;document.querySelector('footer').hidden=true;
 document.body.insertAdjacentHTML('beforeend',identity(true));
}
if(id==='install'){
 const cmds=['git clone https://github.com/AQ-Labs/cybergraph.git','python -m venv .venv','.venv\\Scripts\\activate','python -m pip install .\\cybergraph','git clone https://github.com/adeyosemanputra/pygoat.git','cd pygoat','git checkout 19d17cc','cybergraph doctor .'];
 content.innerHTML='<h1>Install once. Scan your repository.</h1><div class="two"><div class="terminal"><div class="label">WINDOWS COMMAND PROMPT / IDE TERMINAL | VERIFIED WORKFLOW REPLAY</div><pre>'+cmds.map((c,i)=>`<div class="cmd" data-at="${[0,4,7,9,14,18,20,23][i]}">${c}</div>`).join('')+'</pre></div><aside><h2>Git + Python 3.10 or newer</h2><p class="muted">One isolated virtual environment.</p><div class="rule"><h2>Target: public PyGoat</h2><p class="muted">Intentionally vulnerable Django training code. Pinned for reproducibility.</p></div><div class="rule"><h2>The dot means this folder</h2><p class="muted">Run CyberGraph from the repository root. No target application installation or execution.</p></div></aside></div>';
 tech.textContent='Git | Python venv | pip | CyberGraph doctor';
 document.getElementById('mode').textContent='macOS / Linux activation: source .venv/bin/activate';
}
if(id==='compare'){
 content.innerHTML='<span class="badge">REPRODUCIBLE EVIDENCE ABLATION</span><h1>What does path evidence add?</h1><p class="muted">Nine existing positive fixtures. One template-generated question per entrypoint.</p><table><thead><tr><th>Evidence pool</th><th>Both endpoint labels present</th><th>Connected path citation</th><th>Mean characters</th></tr></thead><tbody id="results"></tbody></table><p class="note">Same ranking. At most 2 complete records and 2,000 characters per question.<br>Labels present does not mean a relationship is correct. Path records use more context.</p>';
 tech.textContent='Saved protocol + per-question evidence + deterministic Python runner';
 document.getElementById('mode').textContent='Not an LLM evaluation or real-world detection benchmark';
 window.setComparison=summary=>{
  document.getElementById('results').innerHTML=Object.entries(summary).map(([k,v])=>`<tr class="${k==='with_path_records'?'highlight':''}"><td>${{findings_only:'Findings only',without_path_records:'Records without paths',with_path_records:'Records with paths'}[k]}</td><td class="num">${v.endpoint_pairs} / ${v.questions}</td><td>${v.path_citations} / ${v.questions}</td><td>${v.mean_characters}</td></tr>`).join('');
 };
 window.setComparison({
  findings_only:{questions:9,endpoint_pairs:0,path_citations:0,mean_characters:136.3},
  without_path_records:{questions:9,endpoint_pairs:8,path_citations:0,mean_characters:243.2},
  with_path_records:{questions:9,endpoint_pairs:9,path_citations:9,mean_characters:543.7}
 });
}
if(id==='optional'){
 content.innerHTML='<span class="badge">OPTIONAL / NOT EXERCISED IN THIS RECORDING</span><h1>Keep the evidence. Choose the explanation.</h1><div class="flow"><section><h2>Local graph retrieval</h2><p>Typed records, paths,<br>source citations</p></section><div class="arrow">&#8594;</div><section><h2>Optional LLM phrasing</h2><p>Anthropic / OpenAI / Kimi<br>Explicit provider setup</p></section><div class="arrow">&#8594;</div><section><h2>Developer verification</h2><p>Inspect the cited code.<br>Challenge unsupported claims.</p></section></div><div class="rule"><h2>Offline by default</h2><p class="muted">External providers receive selected context when enabled.<br>Citation instructions are not a guarantee of faithful generation.</p></div>';
 tech.textContent='Optional model clients | FastMCP for IDE integration | SARIF for review pipelines';
 document.getElementById('mode').textContent='All answers shown in this video are deterministic';
}
window.demoTick=t=>{
 if(id==='welcome')document.querySelector('.identity').classList.toggle('gone',t>=5);
 if(id==='install')document.querySelectorAll('.cmd').forEach(el=>el.classList.toggle('active',t>=Number(el.dataset.at)));
};
