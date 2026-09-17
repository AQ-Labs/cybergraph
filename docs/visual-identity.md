# CyberGraph Visual Identity

The original connected-shield mark combines a security boundary with a small
directed-code graph. It is not a certification or a guarantee that code is safe.
The wordmark and report share graphite, teal, blue, amber and rose accents.
Mirofy's clear logo-first README and semantic graph colors inspired the
presentation hierarchy; no Mirofy artwork, code or footage is reused.

## Graph Semantics

- Blue: route or other entrypoint.
- Neutral: application function or code structure.
- Green: detected guard; teal: validator.
- Red: sensitive sink, not automatically a confirmed vulnerability.
- Amber trail: selected path, not a severity classification.

Focus path changes presentation only. It does not change the stored graph,
findings, scores, citations or analysis. Search and severity/layer filters still
apply. The count reports visible nodes versus the current view's total, not the
entire database. Animate path is optional, stops while the page is hidden and
is disabled when the operating system requests reduced motion. Motion illustrates
edge direction, not captured execution.

## Screenshot Provenance

`report-focus.png` is generated from the public, intentionally vulnerable
[PyGoat](https://github.com/adeyosemanputra/pygoat) repository at commit
`19d17cc8874861142b330636d068bbde54e86b85`.
The baseline has 806 stored nodes, 2,634 edges and 14 findings. The HTML report
displays at most 25 ranked paths; this is a display limit, not the total number
of possible paths. Analysis does not run the target application or exploit it.

The other report screenshots are earlier captures and may show different counts.
The demo uses real commands and this same public target. Static reachability is
evidence for human review, not a claim of a successful exploit. The SVG brand
assets are original project assets distributed under the project license.
