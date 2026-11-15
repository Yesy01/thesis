const form = document.querySelector("#protocol-form");
const runButton = document.querySelector("#run-button");
const formMessage = document.querySelector("#form-message");
const stageList = document.querySelector("#stage-list");
const runSummary = document.querySelector("#run-summary");
const resultPanel = document.querySelector("#result-panel");

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
    document.querySelectorAll(".stage").forEach((item) => {
      item.classList.remove("complete");
      item.classList.add("pending");
    });
    document.querySelector(".stage").classList.add("running");
  }
}

function renderStages(stages) {
  stageList.replaceChildren();
  stages.forEach((stage) => {
    const item = document.createElement("li");
    item.className = `stage complete ${stage.number === 9 ? "application-stage" : ""}`;

    const number = document.createElement("span");
    number.className = "stage-number";
    number.textContent = "✓";

    const content = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = stage.algorithm;
    const detail = document.createElement("small");
    detail.textContent = stage.detail;
    const mapping = document.createElement("code");
    mapping.textContent = `${stage.function} · ${stage.file}`;
    content.append(title, detail, mapping);

    const duration = document.createElement("span");
    duration.className = "stage-time";
    duration.textContent = `${stage.duration_ms.toFixed(2)} ms`;

    item.append(number, content, duration);
    stageList.append(item);
  });
}

function renderResult(result) {
  renderStages(result.stages);
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
    const response = await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Protocol run failed");
    renderResult(data);
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
