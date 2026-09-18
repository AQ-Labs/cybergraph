# CyberGraph Demonstration V6

The verified recording is **296.981 seconds (4:57), 1920x1080 H.264/AAC**, with
English synthetic narration, timed captions, and original soft music ducked
under speech. This is a system-demonstration draft, not evidence of conference
acceptance.

## Review Materials

- [Narration and chapter script](Narration-and-Chapters.md)
- [English captions](CyberGraph-AAAI27-English.srt)
- [Chapter timings](chapters.json)
- [Opening poster](CyberGraph-demo-poster.png)
- [Playback verification](video-QA.json) and [chapter provenance](edit-provenance.json)
- [Music provenance](Music-provenance.md)
- [Demonstrated PyGoat parameterization patch](pygoat-parameterization.patch)

The MP4 is intentionally not committed to Git. Its filename is
`CyberGraph-AAAI27-Walkthrough-v6-1080p.mp4`; the verified SHA-256 is
`b515f3d7888f9dbd0c2319c71cd2988780ab87339b63f38cdbb4da54a3da0732`.
The presenter has copies in Downloads and the local CyberGraph folder. No
public video URL or release upload has been created.

## Walkthrough

1. Minimal centered CyberGraph logo, then the actual offline explorer.
2. Install into a virtual environment and select pinned public PyGoat code.
3. Build the graph and identify database, HTML, configuration, and export files.
4. Decode node/edge roles, select a focused attack path, and inspect source.
5. Ask a local question and follow its citations.
6. Compare record pools using the reproducible seeded evidence ablation.
7. Apply a predefined patch, rescan, and explain why REVIEW remains.
8. Distinguish optional model phrasing from demonstrated deterministic answers.
9. Close with the uncluttered logo and thank-you frame.

Seven substantive chapters retain the earlier verified interaction footage;
five chapters are new. Terminal sequences are labeled workflow/output replays,
not live installations. Graph footage uses real browser interactions with the
offline report. PyGoat is neither started nor exploited. The repair was
syntax-checked but not database-tested. No LLM call, MCP client interaction,
or CI upload is represented as exercised in the video.

## Editable New Frames

The five new 1920x1080 editorial frames are in `frames/`. Open `index.html`
with `#welcome`, `#install`, `#compare`, `#optional`, or `#thanks`.
The capture controller advances animation by calling `window.demoTick(seconds)`;
these are fixed-format production frames, not a new product interface.

The welcome scene expects a real generated `report.html` beside the frame.
Generate one from the pinned target with `cybergraph visualize . --with-source
--max-nodes 2000` and copy it there locally. That report is ignored. The static
comparison frame contains the committed [ablation results](../../../benchmark/retrieval/results.json)
and must be updated if those results change. These frame sources, the script,
and captions support editing; they are not a standalone one-command movie
renderer. The full capture, speech, mixing, and encoding environment remains in
the local production workspace.

Keep the final video under five minutes. Before replacing it, check every
chapter, caption timing, audio level, full decode, and the final held frame.
