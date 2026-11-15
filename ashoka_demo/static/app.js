const form = document.querySelector("#protocol-form");
const runButton = document.querySelector("#run-button");
const formMessage = document.querySelector("#form-message");
const stageList = document.querySelector("#stage-list");
const runSummary = document.querySelector("#run-summary");
const resultPanel = document.querySelector("#result-panel");
const stageBlueprints = [
  ["Setup", "Pairing group and attribute generators"],
  ["TTPKeyGen + AggKey", "Authority shares and consolidated verification key"],
  ["PrepareBlindSign", "Commitment, ElGamal encryption, issuance proof"],
  ["BlindSign", "Two blinded partial credentials"],
  ["Unblind", "Remove ElGamal blinding"],
  ["AggCred", "Lagrange interpolation over two shares"],
  ["ProveCred", "Credential randomization and showing proof"],
  ["VerifyCred", "Proof verification and pairing equation"],
  ["Application record", "Process-local UsedList update"],
];
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const wait = (milliseconds) => new Promise((resolve) => {
  window.setTimeout(resolve, reducedMotion ? 20 : milliseconds);
});

function resetStages() {
  stageList.replaceChildren();
  stageBlueprints.forEach(([algorithm, detail], index) => {
    const item = document.createElement("li");
    item.className = `stage pending ${index === 8 ? "application-stage" : ""}`;
    const number = document.createElement("span");
    number.className = "stage-number";
    number.textContent = index + 1;
    const content = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = algorithm;
    const description = document.createElement("small");
    description.textContent = detail;
    content.append(title, description);
    item.append(number, content);
    stageList.append(item);
  });
}

function setRunning(running) {
  runButton.disabled = running;
  runButton.querySelector("span").textContent = running
    ? "Executing real Coconut flow…"
    : "Run complete protocol";
  runSummary.className = `run-summary ${running ? "running" : "idle"}`;
  runSummary.textContent = running ? "Protocol running" : "Ready to run";
  if (running) {
    resultPanel.hidden = true;
    formMessage.textContent = "";
    resetStages();
  }
}

function renderStage(stage, status) {
  const item = stageList.children[stage.number - 1];
  item.className = `stage ${status} ${stage.number === 9 ? "application-stage" : ""}`;

  const number = document.createElement("span");
  number.className = "stage-number";
  number.textContent = status === "complete" ? "✓" : "•••";

  const content = document.createElement("div");
  const title = document.createElement("strong");
  title.textContent = stage.algorithm;
  const actor = document.createElement("span");
  actor.className = "stage-actor";
  actor.textContent = stage.actor;
  const detail = document.createElement("small");
  detail.textContent = status === "complete" ? stage.detail : stage.activity;
  const mapping = document.createElement("code");
  mapping.textContent = `${stage.function} · ${stage.file}`;
  content.append(title, actor, detail, mapping);

  const duration = document.createElement("span");
  duration.className = "stage-time";
  duration.textContent = status === "complete"
    ? `${stage.duration_ms.toFixed(2)} ms`
    : "running";

  item.replaceChildren(number, content, duration);
  if (status === "running") item.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function displayProtocolEvent(event) {
  if (event.type === "stage_start") {
    const { stage } = event;
    runSummary.textContent = `Stage ${stage.number} of ${stageBlueprints.length}`;
    runButton.querySelector("span").textContent = `${stage.actor}: ${stage.algorithm}…`;
    renderStage(stage, "running");
    await wait(420);
  } else if (event.type === "stage_complete") {
    renderStage(event.stage, "complete");
    await wait(260);
  } else if (event.type === "error") {
    throw new Error(event.error || "Protocol run failed");
  }
}

function renderResult(result) {
  runSummary.className = "run-summary complete";
  runSummary.textContent = `${result.stages.length} stages complete`;

  const title = document.querySelector("#result-title");
  const copy = document.querySelector("#result-copy");
  title.textContent = result.recorded
    ? "Credential accepted · complaint recorded"
    : "Credential accepted · duplicate record blocked";
  copy.textContent = result.recorded
    ? "The randomized showing verified. The complaint was then added to the process-local UsedList."
    : "The randomized showing verified, but this IssueID and complaint ID already exist in the local UsedList.";
  document.querySelector("#total-duration").textContent = `${result.total_duration_ms.toFixed(2)} ms`;
  document.querySelector("#used-count").textContent = result.used_list_size;
  resultPanel.hidden = false;
  resultPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function runProtocol(payload) {
  if (form.dataset.runtime === "browser") {
    const { runFlow } = await import("./browser.js");
    return runFlow(payload, displayProtocolEvent);
  }
  const response = await fetch("/api/run/stream", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok || !response.body) throw new Error("Could not start the protocol stream");

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let result;

  async function consumeLine(line) {
    if (!line.trim()) return;
    const event = JSON.parse(line);
    if (event.type === "result") result = event.result;
    else await displayProtocolEvent(event);
  }

  while (true) {
    const { value, done } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
    const lines = buffer.split("\n");
    buffer = lines.pop();
    for (const line of lines) await consumeLine(line);
    if (done) break;
  }
  await consumeLine(buffer);
  if (!result) throw new Error("The protocol stream ended without a result");
  return result;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setRunning(true);

  const payload = {
    issue_id: Number(document.querySelector("#issue-id").value),
    complaint_id: document.querySelector("#complaint-id").value,
    complaint_text: document.querySelector("#complaint-text").value,
  };

  try {
    if (!Number.isSafeInteger(payload.issue_id) || payload.issue_id <= 0) {
      throw new Error("IssueID must be a positive safe integer");
    }
    renderResult(await runProtocol(payload));
  } catch (error) {
    runSummary.className = "run-summary idle";
    runSummary.textContent = "Run failed";
    formMessage.textContent = error.message;
  } finally {
    runButton.disabled = false;
    runButton.querySelector("span").textContent = "Run complete protocol";
    document.querySelectorAll(".stage.running").forEach((item) => item.classList.remove("running"));
  }
});
