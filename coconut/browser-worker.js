const pyodideBase = "https://cdn.jsdelivr.net/pyodide/v0.27.7/full/";
const curvesUrl = "https://cdn.jsdelivr.net/npm/@noble/curves@2.0.1/bls12-381.js/+esm";

let runtime;
let activeRequestId;


function send(type, payload = {}) {
  self.postMessage({ type, request_id: activeRequestId, ...payload });
}


async function startRuntime() {
  const [{ loadPyodide }, { bls12_381: bls }, manifest] = await Promise.all([
    import(`${pyodideBase}pyodide.mjs`),
    import(curvesUrl),
    fetch("./python-files.json").then((response) => {
      if (!response.ok) throw new Error("Could not load the demo’s Python file list.");
      return response.json();
    }),
  ]);
  const pyodide = await loadPyodide({ indexURL: pyodideBase });
  const g1 = bls.G1.Point;
  const g2 = bls.G2.Point;
  const target = bls.fields.Fp12;

  pyodide.registerJsModule("pairing_browser", {
    order: g1.Fn.ORDER.toString(),
    generator1: g1.BASE,
    generator2: g2.BASE,
    zero1: g1.ZERO,
    zero2: g2.ZERO,
    scale: (point, scalar) => point.multiply(BigInt(scalar)),
    hash_to_g1: (hex) => bls.G1.hashToCurve(
      Uint8Array.from(hex.match(/../g), (byte) => Number.parseInt(byte, 16)),
    ),
    pair: (a, b) => a.equals(g1.ZERO) || b.equals(g2.ZERO)
      ? target.ONE
      : bls.pairing(a, b),
    equal_pairings: (a, b) => target.eql(a, b),
  });
  pyodide.registerJsModule("progress_bridge", {
    emit: (serialized) => send("protocol_event", {
      event: JSON.parse(serialized),
    }),
  });

  await Promise.all(manifest.map(async (file) => {
    const response = await fetch(`./python/${file}`);
    if (!response.ok) throw new Error(`Could not load ${file}.`);
    const path = `/coconut-demo/${file}`;
    pyodide.FS.mkdirTree(path.slice(0, path.lastIndexOf("/")));
    pyodide.FS.writeFile(path, new Uint8Array(await response.arrayBuffer()));
  }));

  pyodide.runPython(`
import json
import sys
sys.path.insert(0, "/coconut-demo")
import pairing
pairing.install()
from progress_bridge import emit
from ashoka_demo.protocol import InMemoryUsedList, execute_flow

used_list = InMemoryUsedList()

def emit_protocol_event(event):
    emit(json.dumps(event))

def run_request(payload):
    args = json.loads(payload)
    result = execute_flow(
        **args,
        used_list=used_list,
        event_callback=emit_protocol_event,
    )
    return json.dumps(result)
  `);
  return pyodide.globals.get("run_request");
}


self.addEventListener("message", async ({ data }) => {
  if (data.type !== "run") return;
  activeRequestId = data.request_id;
  try {
    runtime ??= startRuntime().catch((error) => {
      runtime = undefined;
      throw error;
    });
    const run = await runtime;
    const result = JSON.parse(run(JSON.stringify(data.payload)));
    send("result", { result });
  } catch (error) {
    send("error", { error: error.message || String(error) });
  }
});
