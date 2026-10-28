"""Registers the http-net origin in a fresh HTTP Garden checkout.

    python register.py add GARDEN_DIR
        Adds the services in compose.yml to GARDEN_DIR/docker-compose.yml,
        adds the fallback http_net entry from quirks.yml to
        GARDEN_DIR/quirks.yml, and copies http_net_grid.py into
        GARDEN_DIR/tools/.

    python register.py set-quirks GARDEN_DIR PROBE_OUTPUT
        Replaces the http_net entry in GARDEN_DIR/quirks.yml with the one in
        PROBE_OUTPUT (what tools/probe_quirks.py --servers http_net prints).

The image's build context (GARDEN_DIR/images/http_net) is staged by the
workflow, not here. Needs PyYAML, which the Garden's own environment has.
"""

import shutil
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
NAME = "http_net"


def load(path: Path) -> dict:
    with open(path, encoding="latin1") as f:
        return yaml.safe_load(f) or {}


def dump(path: Path, data: dict) -> None:
    # Same style as the Garden's tools/update.py output.
    with open(path, "w", encoding="latin1") as f:
        yaml.dump(data, f)


def add(garden: Path) -> None:
    compose_path = garden / "docker-compose.yml"
    compose = load(compose_path)
    services = compose.setdefault("services", {})
    for name, service in load(HERE / "compose.yml").items():
        if name in services:
            sys.exit(f"{name} is already a service in {compose_path}")
        services[name] = service
    dump(compose_path, compose)

    quirks_path = garden / "quirks.yml"
    quirks = load(quirks_path)
    quirks.update(load(HERE / "quirks.yml"))
    dump(quirks_path, quirks)

    shutil.copy(HERE / "http_net_grid.py", garden / "tools" / "http_net_grid.py")
    print(f"registered {', '.join(load(HERE / 'compose.yml'))} in {garden}")


def set_quirks(garden: Path, probe_output: Path) -> None:
    probed = load(probe_output)
    if NAME not in probed:
        sys.exit(f"{probe_output} has no {NAME} entry")
    quirks_path = garden / "quirks.yml"
    quirks = load(quirks_path)
    quirks[NAME] = probed[NAME]
    dump(quirks_path, quirks)
    print(f"{NAME} quirks: {probed[NAME]!r}")


def main() -> None:
    match sys.argv[1:]:
        case ["add", garden]:
            add(Path(garden))
        case ["set-quirks", garden, probe_output]:
            set_quirks(Path(garden), Path(probe_output))
        case _:
            sys.exit(__doc__)


if __name__ == "__main__":
    main()
