# CyberGraph AAAI-27 Demonstration Draft

**Draft for author review, not a submitted or accepted paper.**

- [Paper PDF](CyberGraph-AAAI27-Draft.pdf)
- [Editable manuscript](main.tex) and [bibliography](references.bib)
- [Reproducible evidence ablation](../../benchmark/retrieval/README.md)
- [Demo narration, captions, and checks](demo/README.md)

The paper describes the inspect-question-repair-recheck workflow on pinned
public PyGoat code. It includes an actual offline explorer screenshot, the
existing 11-case reachability regression result, and a nine-question
evidence-availability ablation. None is a real-world accuracy estimate or user
study. Optional LLM clients are described, not evaluated; the recorded answers
are deterministic.

## Build

Use Python 3.10+ and a TeX installation providing PDFLaTeX and BibTeX:

```sh
python docs/aaai27/build_paper.py
```

For a portable TeX installation, pass `--tex-bin /path/to/tex/bin`.
Output goes to the ignored `docs/aaai27/build/` directory; the script does not
replace the reviewed PDF automatically. Alternatively import this directory
into a LaTeX editor and select PDFLaTeX as the compiler.

`aaai2027.sty` and `aaai2027.bst` are the unchanged official files from the
[AAAI-27 author kit](https://aaai.org/authorkit27/), retained under their original
notices. They are not CyberGraph-authored code. The screenshot is from the real
report with typography scaled for print; its data was not changed.

## Provenance and Review

- Analysis base: `18329a63971cd9f6564d59195293de3493903c6c`.
- Presentation revision: `b3b47b1c18db1bfa5692cd1b20270aff3ef1ba3f`.
- Target: `adeyosemanputra/pygoat` at
  `19d17cc8874861142b330636d068bbde54e86b85`.
- Baseline: 806 stored nodes, 2,634 edges, 14 findings. A predefined two-line
  parameterization patch removes one finding; REVIEW remains. The patch was
  syntax-checked, not tested against a running database.
- [Verification record](verification.json): three US Letter pages, two content
  pages plus references, embedded fonts, no overfull boxes or unresolved
  references. All final pages were visually inspected.

The author order, affiliations, and emails were supplied by the authors. A
corresponding author has not been designated. Confirm every author's approval,
the current submission rules, and the final review mode before submitting.
This draft uses the official `draft` option to keep the author block visible
without an acceptance notice. Its author block, repository link, and video
identify the project; it is not anonymized.

Do not modify template margins or font sizes to force pagination. Recheck
layout and claims after any edits. No conference submission is performed by
this repository or its build script.
