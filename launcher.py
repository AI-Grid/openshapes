"""Launcher for starting multiple agents defined in launcher.ini."""

from __future__ import annotations

import time
from pathlib import Path

from server.proc import launch_agents_from_file


def main() -> None:
    path = Path("config/launcher.ini")
    if not path.exists():
        raise SystemExit("launcher.ini not found in config directory")
    manager = launch_agents_from_file(path)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        manager.stop_all()


if __name__ == "__main__":
    main()
