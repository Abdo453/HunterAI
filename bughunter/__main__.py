"""Console-script entrypoints.

`bughunter`        -> engine.main   (the recon/hunt/chat/mcp dispatcher; the
                                     legacy install.sh symlinked engine.py here)
`bughunter-agent`  -> agent.main    (the autonomous session runner)

Both insert this package dir on sys.path first so the package's flat internal
imports (`from brain import ...`, `from tools.scope_checker import ...`) resolve.
"""
import os
import sys

_PKG = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_PKG)
for _p in (_PARENT, _PKG):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def main():
    from bughunter import engine
    engine.main()


def agent_main():
    from bughunter import agent
    agent.main()


if __name__ == "__main__":
    main()
