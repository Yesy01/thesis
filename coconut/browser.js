let worker;
let requestSequence = 0;
const pending = new Map();


function rejectPending(error) {
  for (const request of pending.values()) request.reject(error);
  pending.clear();
}


function getWorker() {
  if (worker) return worker;

  worker = new Worker(new URL("./browser-worker.js", import.meta.url), {
    type: "module",
  });
  worker.addEventListener("message", ({ data }) => {
    const request = pending.get(data.request_id);
    if (!request) return;

    if (data.type === "protocol_event") {
      request.displayQueue = request.displayQueue.then(() => request.onEvent(data.event));
      return;
    }

    pending.delete(data.request_id);
    if (data.type === "result") {
      request.displayQueue.then(() => request.resolve(data.result), request.reject);
    } else {
      request.reject(new Error(data.error || "The browser protocol worker failed"));
    }
  });
  worker.addEventListener("error", (event) => {
    rejectPending(new Error(event.message || "The browser protocol worker stopped"));
    worker = undefined;
  });
  return worker;
}


export function runFlow(payload, onEvent = async () => {}) {
  const requestId = ++requestSequence;
  return new Promise((resolve, reject) => {
    pending.set(requestId, {
      resolve,
      reject,
      onEvent,
      displayQueue: Promise.resolve(),
    });
    getWorker().postMessage({
      type: "run",
      request_id: requestId,
      payload,
    });
  });
}
