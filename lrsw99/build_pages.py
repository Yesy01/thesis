"""Build a static copy of the Streamlit demo for GitHub Pages."""

import argparse
import json
from pathlib import Path
from shutil import copyfile

STLITE = "https://cdn.jsdelivr.net/npm/@stlite/browser@1.12.2/build"
ROOT = Path(__file__).resolve().parent


def build(output: Path) -> None:
    files = [ROOT / "app.py", *sorted((ROOT / "src").glob("*.py"))]
    mounts = {}
    for source in files:
        name = source.relative_to(ROOT).as_posix()
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        copyfile(source, target)
        mounts[name] = {"url": f"./{name}"}
    (output / ".nojekyll").touch()
    (output / "index.html").write_text(
        f"""<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LRSW99 Pseudonym System</title>
<link rel="stylesheet" href="{STLITE}/stlite.css">
<main id="demo"><p>Loading the LRSW99 demo…</p></main>
<noscript>Enable JavaScript to run this Python demo in your browser.</noscript>
<script type="module">
  const root = document.getElementById("demo");
  try {{
    const {{ mount }} = await import("{STLITE}/stlite.js");
    const files = {json.dumps(mounts)};
    for (const file of Object.values(files)) {{
      file.url = new URL(file.url, document.baseURI).href;
    }}
    await mount({{ entrypoint: "app.py", files }}, root);
  }} catch (error) {{
    root.textContent = "The demo could not load. Refresh to try again.";
    console.error(error);
  }}
</script>
</html>
""",
        encoding="utf-8",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="Directory for the static site")
    build(parser.parse_args().output)
