"""Build the browser-hosted Coconut workshop demo."""

import argparse
import json
from pathlib import Path
from shutil import copyfile

DEMO = Path(__file__).resolve().parent
PROJECT = DEMO.parent


def build(output):
    output.mkdir(parents=True, exist_ok=True)
    for name in ("styles.css", "app.js"):
        copyfile(DEMO / "static" / name, output / name)
    for name in ("browser.js", "browser-worker.js"):
        copyfile(DEMO / "browser" / name, output / name)

    sources = {
        "pairing.py": DEMO / "browser" / "pairing.py",
        **{
            name: PROJECT / name
            for name in (
                "ashoka_demo/__init__.py", "ashoka_demo/protocol.py",
                "coconut/__init__.py", "coconut/scheme.py", "coconut/proofs.py", "coconut/utils.py",
            )
        },
    }
    for name, source in sources.items():
        target = output / "python" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        copyfile(source, target)
    (output / "python-files.json").write_text(json.dumps(list(sources)), encoding="utf-8")

    html = (DEMO / "static" / "index.html").read_text(encoding="utf-8")
    html = html.replace('href="/static/', 'href="./').replace('src="/static/', 'src="./')
    html = html.replace('href="/"', 'href="./"')
    html = html.replace('id="protocol-form"', 'id="protocol-form" data-runtime="browser"')
    html = html.replace("Local study environment", 'Browser demo · <a href="../">LRSW99 demo</a>')
    html = html.replace(
        "functions unchanged.",
        "functions unchanged. This browser edition uses BLS12-381 for group operations. "
        "The local complaint list resets on reload.",
    )
    (output / "index.html").write_text(html, encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    build(parser.parse_args().output)
