"""
Ask the knowledge base one question, straight from the command line.

Useful for checking the RAG half works before any detection exists:

    python ask.py "How is T1059 used by threat actors?"
    python ask.py "What is the capital of Egypt?"      # should abstain
"""
from __future__ import annotations

import sys
from pathlib import Path

from report import RAG_DIR, load_chain


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit('usage: python ask.py "your question"')
    question = " ".join(sys.argv[1:])

    print("loading the RAG chain (the first call is slow) ...\n")
    r = load_chain(Path(RAG_DIR)).invoke(question)

    print(r.answer, "\n")
    print(f"confidence : {r.confidence.overall}/100")
    print(f"abstained  : {bool(r.hard_abstained)}")
    for s in (r.citations.sources or []):
        print(f"  {s.source_id}  {s.url}")


if __name__ == "__main__":
    main()
