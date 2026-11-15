const form = document.querySelector("#protocol-form");
const runButton = document.querySelector("#run-button");
const formMessage = document.querySelector("#form-message");
const stageList = document.querySelector("#stage-list");
const runSummary = document.querySelector("#run-summary");
const resultPanel = document.querySelector("#result-panel");

const stages = [
  {
    number: 1,
    algorithm: "Setup",
    actor: "System",
    description: "Initialize the pairing group and derive two attribute generators.",
    input: "Maximum attribute count q = 2",
    output: "Public parameters (G1, G2, GT, order, generators)",
    function: "setup(2)",
    file: "coconut/scheme.py",
    equation: "params ← Setup(1^λ, q)",
  },
  {
    number: 2,
    algorithm: "TTPKeyGen + AggKey",
    actor: "Authority setup",
    description: "Generate three authority key shares and combine the two selected verification shares.",
    input: "params, threshold t = 2, authorities n = 3",
    output: "Three secret-key shares and one aggregate verification key",
    function: "ttp_keygen(); agg_key()",
    file: "coconut/scheme.py",
    equation: "vk ← AggKey(vk₁, vk₂, ⊥)",
  },
  {
    number: 3,
    algorithm: "PrepareBlindSign",
    actor: "User",
    description: "Commit to private k and public IssueID, encrypt k, and construct the issuance proof.",
    input: "private k, public IssueID, user ElGamal public key γ",
    output: "Commitment cm, ciphertext c, issuance proof πs",
    function: "elgamal_keygen(); prepare_blind_sign()",
    file: "coconut/utils.py + coconut/scheme.py",
    equation: "h = H(cm), Λ = (cm, c, πs)",
  },
  {
    number: 4,
    algorithm: "BlindSign",
    actor: "Authorities A1 + A2",
    description: "Each selected authority checks πs and returns a blinded credential share.",
    input: "Authority key share, γ, Λ, public IssueID",
    output: "Two blinded partial credentials",
    function: "blind_sign() × 2",
    file: "coconut/scheme.py",
    equation: "σ̃ᵢ ← BlindSign(skᵢ, γ, Λ)",
  },
  {
    number: 5,
    algorithm: "Unblind",
    actor: "User",
    description: "Remove ElGamal blinding from both partial credentials.",
    input: "Two blinded shares and user ElGamal secret d",
    output: "Two Coconut credential shares σ₁, σ₂",
    function: "unblind() × 2",
    file: "coconut/scheme.py",
    equation: "σᵢ ← Unblind(σ̃ᵢ, d)",
  },
  {
    number: 6,
    algorithm: "AggCred",
    actor: "User",
    description: "Interpolate the ordered shares into one threshold credential.",
    input: "σ₁, σ₂, missing authority marker ⊥",
    output: "Aggregate credential σ",
    function: "agg_cred()",
    file: "coconut/scheme.py",
    equation: "σ ← Σᵢ lᵢ · σᵢ",
  },
  {
    number: 7,
    algorithm: "ProveCred",
    actor: "Credential holder",
    description: "Randomize the credential and construct a proof of the private attribute.",
    input: "Aggregate credential σ, aggregate vk, private k",
    output: "Randomized credential σ′ and showing proof πv",
    function: "prove_cred()",
    file: "coconut/scheme.py",
    equation: "Θ = (κ, ν, σ′, πv)",
  },
  {
    number: 8,
    algorithm: "VerifyCred",
    actor: "Verifier",
    description: "Check πv and the final pairing equation using public IssueID.",
    input: "Aggregate vk, Θ, public IssueID",
    output: "Accepted or rejected",
    function: "verify_cred()",
    file: "coconut/scheme.py",
    equation: "e(h′, κ + public terms) = e(s′ + ν, g₂)",
  },
  {
    number: 9,
    algorithm: "Application record",
    actor: "Application",
    description: "Check the process-local UsedList and record the complaint after verification.",
    input: "IssueID and complaint ID",
    output: "Recorded or duplicate",
    function: "InMemoryUsedList.record()",
    file: "ashoka_demo/protocol.py",
    equation: "UsedList ← UsedList ∪ {(IssueID, complaint ID)}",
  },
];

const attackDefinitions = [
  ["changed_attribute", "Change the private attribute", "Tests attribute binding."],
  ["insufficient_shares", "Use one authority share", "Tests the 2-of-3 threshold requirement."],
  ["corrupted_share", "Corrupt a credential share", "Tests integrity after aggregation."],
  ["malformed_proof", "Alter the showing proof", "Tests Fiat-Shamir proof integrity."],
  ["wrong_verification_key", "Use a different issuer key", "Tests issuer-key binding."],
  ["altered_randomized_credential", "Alter the randomized credential", "Tests showing and credential binding."],
];

const stageRecords = new Map();
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const wait = (milliseconds) => new Promise((resolve) => {
  window.setTimeout(resolve, reducedMotion ? 20 : milliseconds);
});

function stageButton(number) {
  return stageList.querySelector(`[data-stage="${number}"]`);
}

function selectStage(number) {
  stageList.querySelectorAll(".process-button").forEach((button) => {
    button.classList.toggle("selected", Number(button.dataset.stage) === number);
  });
  const base = stages[number - 1];
  const record = stageRecords.get(number);
  const data = record ? { ...base, ...record.stage } : base;
  const status = record?.status || "pending";

  document.querySelector("#process-number").textContent = `Process ${String(number).padStart(2, "0")}`;
  document.querySelector("#process-title").textContent = data.algorithm;
  document.querySelector("#process-actor").textContent = data.actor;
  document.querySelector("#process-description").textContent = data.description || data.activity;
  document.querySelector("#process-input").textContent = base.input;
  document.querySelector("#process-output").textContent = base.output;
  document.querySelector("#process-code").textContent = `${data.function} · ${data.file}`;
  document.querySelector("#process-equation").textContent = base.equation;

  const statusElement = document.querySelector("#process-status");
  statusElement.className = `process-status ${status}`;
  statusElement.textContent = status === "pending" ? "Pending" : status;
  const result = document.querySelector("#process-result");
  result.className = `process-result ${status}`;
  if (status === "running") {
    result.textContent = data.activity;
  } else if (status === "complete") {
    result.textContent = `${data.detail} Measured runtime: ${data.duration_ms.toFixed(2)} ms.`;
  } else {
    result.textContent = "Run the protocol to execute this process.";
  }
}

function resetProtocolView() {
  stageRecords.clear();
  stageList.querySelectorAll(".process-button").forEach((button) => {
    button.classList.remove("running", "complete", "failed", "selected");
  });
  resultPanel.hidden = true;
  runSummary.textContent = "Running";
  selectStage(1);
}

async function displayProtocolEvent(event) {
  if (event.type === "error") throw new Error(event.error || "Protocol run failed");
  const { stage } = event;
  const status = event.type === "stage_start" ? "running" : "complete";
  stageRecords.set(stage.number, { stage, status });
  const button = stageButton(stage.number);
  button.classList.remove("running", "complete");
  button.classList.add(status);
  selectStage(stage.number);
  runSummary.textContent = `${stage.number} / ${stages.length}`;
  runButton.textContent = status === "running" ? stage.algorithm : "Running…";
  await wait(status === "running" ? 480 : 300);
}

function renderResult(result) {
  runSummary.textContent = "Complete";
  document.querySelector("#result-title").textContent = result.recorded
    ? "Credential accepted; complaint recorded"
    : "Credential accepted; duplicate record blocked";
  document.querySelector("#result-copy").textContent = result.recorded
    ? "Verification completed before the application updated its local UsedList."
    : "Verification completed, but the same IssueID and complaint ID were already present.";
  document.querySelector("#total-duration").textContent = `${result.total_duration_ms.toFixed(2)} ms`;
  document.querySelector("#used-count").textContent = result.used_list_size;
  resultPanel.hidden = false;
}

async function browserApi() {
  return import("./browser.js");
}

async function runProtocol(payload) {
  if (form.dataset.runtime === "browser") {
    const { runFlow } = await browserApi();
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
  const payload = {
    issue_id: Number(document.querySelector("#issue-id").value),
    complaint_id: document.querySelector("#complaint-id").value,
    complaint_text: document.querySelector("#complaint-text").value,
  };
  runButton.disabled = true;
  formMessage.textContent = "";
  resetProtocolView();
  try {
    if (!Number.isSafeInteger(payload.issue_id) || payload.issue_id <= 0) {
      throw new Error("IssueID must be a positive safe integer");
    }
    renderResult(await runProtocol(payload));
  } catch (error) {
    runSummary.textContent = "Failed";
    formMessage.textContent = error.message;
  } finally {
    runButton.disabled = false;
    runButton.textContent = "Run protocol";
  }
});

stageList.addEventListener("click", (event) => {
  const button = event.target.closest(".process-button");
  if (button) selectStage(Number(button.dataset.stage));
});

let parametersLoaded = false;

function addParameter(container, label, value, mono = false) {
  const item = document.createElement("dl");
  item.className = "parameter-item";
  const term = document.createElement("dt");
  term.textContent = label;
  const description = document.createElement("dd");
  description.className = mono ? "mono" : "";
  description.textContent = value;
  item.append(term, description);
  container.append(item);
}

async function fetchParameters() {
  if (form.dataset.runtime === "browser") {
    const { getParameters } = await browserApi();
    return getParameters();
  }
  const response = await fetch("/api/parameters");
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Could not load parameters");
  return data;
}

async function loadParameters() {
  if (parametersLoaded) return;
  const status = document.querySelector("#parameter-status");
  status.textContent = "Loading the public parameters…";
  try {
    const data = await fetchParameters();
    const grid = document.querySelector("#parameter-grid");
    grid.replaceChildren();
    addParameter(grid, "Runtime", data.runtime);
    addParameter(grid, "Group implementation", data.group_implementation, true);
    addParameter(grid, "Group order", data.group_order, true);
    addParameter(grid, "Order size", `${data.group_order_bits} bits`);
    addParameter(grid, "Pairing groups", data.pairing_groups.join(", "));
    addParameter(grid, "Attribute capacity", `q = ${data.maximum_attributes}`);
    addParameter(grid, "Threshold", `t = ${data.threshold} of n = ${data.authority_count}`);
    addParameter(grid, "Selected authorities", data.selected_authorities.join(", "));
    addParameter(grid, "Private attribute", data.private_attributes.join(", "));
    addParameter(grid, "Public attribute", data.public_attributes.join(", "));
    addParameter(grid, "G1 generator", `${data.g1.bytes} bytes · sha256 ${data.g1.sha256}`, true);
    addParameter(grid, "G2 generator", `${data.g2.bytes} bytes · sha256 ${data.g2.sha256}`, true);
    addParameter(
      grid,
      "Attribute generators",
      data.attribute_generators.map((item, index) => `h${index}: ${item.bytes} bytes · ${item.sha256}`).join(" | "),
      true,
    );
    addParameter(grid, "Hash to group", data.hash_to_group);
    addParameter(grid, "Issuance proof", data.issuance_proof);
    addParameter(grid, "Showing proof", data.showing_proof);
    addParameter(grid, "Verification equation", data.verification_equation, true);
    status.textContent = "Public parameters loaded from the active runtime.";
    parametersLoaded = true;
  } catch (error) {
    status.textContent = error.message;
  }
}

function renderAttackButtons() {
  const list = document.querySelector("#attack-list");
  list.replaceChildren();
  attackDefinitions.forEach(([id, title, description]) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "attack-button";
    button.dataset.attack = id;
    const heading = document.createElement("strong");
    heading.textContent = title;
    const summary = document.createElement("small");
    summary.textContent = description;
    button.append(heading, summary);
    list.append(button);
  });
}

async function executeAttack(attackId) {
  if (form.dataset.runtime === "browser") {
    const { runAttack } = await browserApi();
    return runAttack(attackId);
  }
  const response = await fetch("/api/attack", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ attack_id: attackId }),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Experiment failed");
  return data;
}

function fact(list, label, value) {
  const row = document.createElement("div");
  const term = document.createElement("dt");
  term.textContent = label;
  const description = document.createElement("dd");
  description.textContent = value;
  row.append(term, description);
  list.append(row);
}

function renderAttackResult(result) {
  const panel = document.querySelector("#attack-result");
  panel.replaceChildren();
  const index = document.createElement("p");
  index.className = "section-index";
  index.textContent = "Experiment result";
  const title = document.createElement("h3");
  title.textContent = result.title;
  const facts = document.createElement("dl");
  facts.className = "attack-facts";
  fact(facts, "Assumption under test", result.assumption);
  fact(facts, "Mutation", result.mutation);
  fact(facts, "Expected", result.expected);
  fact(facts, "Observed", result.observed);
  fact(facts, "Implementation behavior", result.implementation_behavior);
  if (result.note) fact(facts, "Implementation note", result.note);
  fact(facts, "Scope", result.scope);
  const outcome = document.createElement("span");
  outcome.className = `attack-outcome ${result.passed ? "pass" : "fail"}`;
  outcome.textContent = result.passed ? "EXPECTED REJECTION OBSERVED" : "UNEXPECTED RESULT";
  panel.append(index, title, facts, outcome);
}

function renderAttackMessage(titleText, message) {
  const panel = document.querySelector("#attack-result");
  panel.replaceChildren();
  const index = document.createElement("p");
  index.className = "section-index";
  index.textContent = "Experiment result";
  const title = document.createElement("h3");
  title.textContent = titleText;
  const copy = document.createElement("p");
  copy.textContent = message;
  panel.append(index, title, copy);
}

document.querySelector("#attack-list").addEventListener("click", async (event) => {
  const button = event.target.closest(".attack-button");
  if (!button) return;
  document.querySelectorAll(".attack-button").forEach((item) => {
    item.disabled = true;
    item.classList.toggle("selected", item === button);
  });
  renderAttackMessage(
    "Running experiment…",
    "Creating a fresh valid credential, applying one mutation, and invoking the original verifier.",
  );
  try {
    renderAttackResult(await executeAttack(button.dataset.attack));
  } catch (error) {
    renderAttackMessage("Experiment failed to run", error.message);
  } finally {
    document.querySelectorAll(".attack-button").forEach((item) => { item.disabled = false; });
  }
});

document.querySelectorAll(".view-tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".view-tab").forEach((item) => item.classList.toggle("active", item === tab));
    document.querySelectorAll(".view").forEach((view) => {
      const selected = view.id === `view-${tab.dataset.view}`;
      view.hidden = !selected;
      view.classList.toggle("active", selected);
    });
    if (tab.dataset.view === "parameters") loadParameters();
  });
});

renderAttackButtons();
selectStage(1);
