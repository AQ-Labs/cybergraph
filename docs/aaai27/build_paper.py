"""Compile the manuscript without overwriting the reviewed PDF."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tex-bin", type=Path, help="Directory containing pdflatex and bibtex")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    build = root / "build"
    programs = {}
    for name in ("pdflatex", "bibtex"):
        located = shutil.which(name, path=str(args.tex_bin) if args.tex_bin else None)
        if not located:
            parser.error(f"{name} not found; install TeX or supply --tex-bin")
        programs[name] = located
    build.mkdir(exist_ok=True)
    command = [
        programs["pdflatex"],
        "-interaction=nonstopmode",
        "-halt-on-error",
        "-output-directory=build",
        "main.tex",
    ]
    subprocess.run(command, cwd=root, check=True)
    env = dict(os.environ)
    for variable in ("BIBINPUTS", "BSTINPUTS"):
        env[variable] = str(root) + os.pathsep + env.get(variable, "")
    subprocess.run([programs["bibtex"], "main"], cwd=build, env=env, check=True)
    for _ in range(2):
        subprocess.run(command, cwd=root, check=True)
    print(f"Built {build / 'main.pdf'}; reviewed PDF unchanged.")


if __name__ == "__main__":
    main()
