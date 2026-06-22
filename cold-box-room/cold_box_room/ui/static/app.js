const state = { caseId: null, snapshot: null, technical: false, timer: null, selectedRoom: null, sideView: "stream", roomJustActivated: null };
const $ = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;",
}[char]));

async function api(path, options) {
  const response = await fetch(path, options);
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || "Request failed");
  return payload;
}

function formatTime(value) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function renderRooms(snapshot) {
  const unlockedSet = new Set(snapshot.unlocked_rooms || []);
  $("roomTower").innerHTML = [...snapshot.rooms].reverse().map((room) => {
    const index = snapshot.rooms.findIndex((item) => item.id === room.id);
    const nextRoom = index + 1 < snapshot.rooms.length ? snapshot.rooms[index + 1] : null;
    const active = room.id === snapshot.room;
    // complete = the room above was ever entered (stable even during return_to_room)
    const complete = snapshot.complete || (nextRoom ? unlockedSet.has(nextRoom.id) : false);
    const justActivated = room.id === state.roomJustActivated;
    const selected = room.id === state.selectedRoom;
    const hasGateAbove = index < snapshot.rooms.length - 1;
    // Gate 1A (above Room 1): sealed forever. All others: open once target room was unlocked.
    const isSealedGate = room.id === "1";
    const gateOpen = hasGateAbove && !isSealedGate && nextRoom && unlockedSet.has(nextRoom.id);
    const gateClass = isSealedGate ? "locked sealed" : (gateOpen ? "open" : "locked");
    const gateLabel = isSealedGate ? "SEALED" : (gateOpen ? "OPEN" : "LOCKED");
    const agent = active ? `<div class="tower-agent" title="Cold Box analyst">
      <span class="tower-agent-head"></span><span class="tower-agent-body"></span>
      <span class="tower-agent-eye left"></span><span class="tower-agent-eye right"></span>
    </div>` : "";
    const gate = hasGateAbove ? `<div class="gate ${gateClass}">
      <span class="gate-left"></span><span class="gate-right"></span><i>${gateLabel}</i>
    </div>` : "";
    const classes = ["room", active ? "active" : "", complete ? "complete" : "", selected ? "selected" : "", justActivated ? "just-activated" : ""].filter(Boolean).join(" ");
    return `<div class="tower-floor-wrap">
      ${gate}<button class="${classes}" data-room="${room.id}">
        <span class="room-status"></span><span class="room-number">${room.id}</span>
        <span class="room-copy"><strong>${escapeHtml(room.label)}</strong><small>${escapeHtml(room.description)}</small></span>${agent}
      </button>
    </div>`;
  }).join("");
  document.querySelectorAll("[data-room]").forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedRoom = button.dataset.room;
      renderRooms(snapshot);
      renderRoomOutput(snapshot);
    });
  });
}

function renderRoomOutput(snapshot) {
  const roomId = state.selectedRoom || snapshot.room;
  const output = snapshot.room_outputs?.[roomId];
  if (!output) return;
  $("roomOutputTitle").textContent = output.title;
  $("roomOutputBadge").textContent = `Room ${roomId}`;
  $("roomOutputSummary").textContent = output.summary;
  $("roomArtifacts").innerHTML = output.artifacts.map(
    (item) => `<button data-artifact="${escapeHtml(item)}">${escapeHtml(item)}</button>`
  ).join("");
  $("roomArtifacts").querySelectorAll("[data-artifact]").forEach((button) => {
    button.addEventListener("click", () => openArtifact(button.dataset.artifact));
  });
  $("roomOutputContent").innerHTML = linkAuditIds(marked.parse(output.content || ""));
  $("roomOutputContent").querySelectorAll("[data-audit]").forEach((button) => {
    button.addEventListener("click", () => openEvidence(button.dataset.audit));
  });
}

function renderEvents(snapshot) {
  const events = [...snapshot.events].reverse();
  $("eventFeed").classList.toggle("show-technical", state.technical);
  $("eventFeed").classList.toggle("technical-mode", state.technical);
  $("eventFeed").innerHTML = events.length ? events.map((event) => `
    <article class="event ${escapeHtml(event.level)}">
      <span class="event-dot"></span>
      <div><strong>${escapeHtml(event.title)}</strong><p>${escapeHtml(event.detail)}</p>
      <time>${escapeHtml(formatTime(event.ts))}${event.id ? ` \u00b7 ${escapeHtml(event.id)}` : ""}</time>
      <div class="technical">${escapeHtml(JSON.stringify(event.technical, null, 2))}</div></div>
    </article>`).join("") : `<p class="empty">The first investigation actions will stream here.</p>`;
}

function renderSidePanel(snapshot) {
  const finalAvailable = Boolean(snapshot.report?.available);
  if (finalAvailable && state.sideView === "final") {
    $("sideEyebrow").textContent = "FINAL REPORT";
    $("sideTitle").textContent = "Investigation findings";
    $("eventFeed").style.display = "none";
    $("sideReport").style.display = "block";
    $("sideReport").innerHTML = linkAuditIds(marked.parse(snapshot.report.content || ""));
    $("sideReport").querySelectorAll("[data-audit]").forEach((button) => {
      button.addEventListener("click", () => openEvidence(button.dataset.audit));
    });
    $("plainToggle").style.display = "none";
    $("technicalToggle").style.display = "none";
    $("streamToggle").style.display = "";
    $("finalToggle").style.display = "none";
  } else {
    $("sideEyebrow").textContent = "LIVE INVESTIGATION STREAM";
    $("sideTitle").textContent = "What Cold Box is doing";
    $("eventFeed").style.display = "block";
    $("sideReport").style.display = "none";
    $("plainToggle").style.display = "";
    $("technicalToggle").style.display = "";
    $("streamToggle").style.display = "none";
    $("finalToggle").style.display = finalAvailable ? "" : "none";
    renderEvents(snapshot);
  }
}

function renderEvidence(snapshot) {
  $("evidenceList").innerHTML = snapshot.evidence.length
    ? snapshot.evidence.map((item) => `<div class="evidence-item">${escapeHtml(item)}</div>`).join("")
    : `<p class="empty">Files will appear after intake.</p>`;
}

function reportPreview(report) {
  return (report.findings || report.content || "").replace(/[#*`|]/g, " ").replace(/\s+/g, " ").trim().slice(0, 190);
}

function linkAuditIds(text) {
  return (text || "").replace(
    /\b(CB-[A-Za-z0-9-]+)\b/g,
    (match) => `<button class="audit-link" data-audit="${match}">${match}</button>`
  );
}

function render(snapshot) {
  const reportBecameAvailable = snapshot.report.available && !state.snapshot?.report?.available;
  const prevRoom = state.snapshot?.room;
  if (prevRoom && prevRoom !== snapshot.room) {
    state.roomJustActivated = snapshot.room;
    clearTimeout(state._roomFlashTimer);
    state._roomFlashTimer = setTimeout(() => { state.roomJustActivated = null; }, 900);
  }
  state.snapshot = snapshot;
  // follow the agent automatically unless user has manually selected a room
  if (!state.selectedRoom || (prevRoom && prevRoom !== snapshot.room && state.selectedRoom === prevRoom)) {
    state.selectedRoom = snapshot.room;
  }
  $("caseTitle").textContent = snapshot.case_id;
  const auditCount = snapshot.audit_count || 0;
  const evtCount = snapshot.event_count || 0;
  $("caseSubtitle").textContent = snapshot.complete
    ? `Investigation complete · ${auditCount} tool run${auditCount !== 1 ? "s" : ""}`
    : `Room ${snapshot.room} · ${auditCount} tool run${auditCount !== 1 ? "s" : ""} · ${evtCount} event${evtCount !== 1 ? "s" : ""}`;
  $("phaseLabel").textContent = snapshot.complete ? "Complete" : `${snapshot.progress}%`;
  $("activityTitle").textContent = snapshot.complete
    ? "Final report ready"
    : (snapshot.activity?.title || "Investigating files");
  $("activityDetail").textContent = snapshot.activity?.detail || "";
  renderRooms(snapshot);
  renderRoomOutput(snapshot);
  if (reportBecameAvailable) state.sideView = "final";
  renderSidePanel(snapshot);
  renderEvidence(snapshot);
}

async function loadCase(caseId) {
  if (!caseId) return;
  state.caseId = caseId;
  try {
    render(await api(`/api/cases/${encodeURIComponent(caseId)}`));
  } catch (error) {
    $("activityTitle").textContent = "Unable to read case";
    $("activityDetail").textContent = error.message;
  }
}

async function loadCases() {
  const payload = await api("/api/cases");
  $("caseSelect").innerHTML = payload.cases.length
    ? payload.cases.map((item) => `<option value="${escapeHtml(item.case_id)}">${escapeHtml(item.case_id)}${item.complete ? " \u00b7 complete" : ""}</option>`).join("")
    : `<option value="">No cases yet</option>`;
  const requested = new URLSearchParams(location.search).get("case");
  const initial = payload.cases.find((item) => item.case_id === requested)?.case_id || payload.cases[0]?.case_id;
  if (initial) {
    $("caseSelect").value = initial;
    await loadCase(initial);
  } else {
    $("caseTitle").textContent = "Start your first investigation";
    $("caseSubtitle").textContent = "";
  }
}

function showEvidenceDialog(title, html) {
  $("evidenceDialogTitle").textContent = title;
  $("evidenceContent").innerHTML = html;
  $("evidenceDialog").showModal();
}

async function openArtifact(name) {
  showEvidenceDialog(name, `<p class="empty">Opening case artifactâ€¦</p>`);
  try {
    const payload = await api(`/api/cases/${encodeURIComponent(state.caseId)}/artifacts/${encodeURIComponent(name)}`);
    $("evidenceContent").innerHTML = `<pre class="artifact-content">${escapeHtml(payload.content || "This artifact is empty.")}</pre>`;
  } catch (error) {
    $("evidenceContent").innerHTML = `<p class="evidence-missing">${escapeHtml(error.message)}</p>`;
  }
}

async function openEvidence(auditId) {
  const evidence = state.snapshot?.audit_evidence?.[auditId];
  if (!evidence) {
    showEvidenceDialog(auditId, `<p class=”evidence-missing”>Evidence reference not found in this case bundle. Run the full investigation to generate traceable audit records.</p>`);
    return;
  }
  const rows = [
    [“Forensic tool”, `${evidence.tool_name || “Unknown”}${evidence.tool_id ? ` (${evidence.tool_id})` : “”}`],
    [“Purpose”, evidence.purpose], [“Why selected”, evidence.why], [“Evidence input”, evidence.input],
    [“Input fingerprint”, evidence.input_sha256], [“Exit code”, evidence.exit_code], [“Timestamp”, evidence.timestamp],
  ];
  const scratchFiles = evidence.scratch_files || [];
  const fileButtons = scratchFiles.length
    ? `<h3>Artifact files</h3><div class=”artifact-chips”>${scratchFiles.map((f, i) =>
        `<button class=”ghost compact evidence-file-btn” data-idx=”${i}”>${escapeHtml(f.split(“/”).at(-1) || f)}</button>`
      ).join(“”)}</div><div id=”evidenceFileContent”></div>`
    : “”;
  showEvidenceDialog(auditId, `
    <div class=”evidence-grid”>${rows.map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value ?? “—“)}</strong></div>`).join(“”)}</div>
    <h3>Recorded output</h3><pre id=”evidencePreview”>${escapeHtml(evidence.stdout_preview || evidence.error || “No output preview recorded.”)}</pre>
    ${fileButtons}`);
  $(“evidenceContent”).querySelectorAll(“.evidence-file-btn”).forEach((btn) => {
    btn.addEventListener(“click”, async () => {
      const f = scratchFiles[parseInt(btn.dataset.idx, 10)];
      $(“evidenceFileContent”).innerHTML = `<p class=”empty”>Loading…</p>`;
      try {
        const payload = await api(`/api/cases/${encodeURIComponent(state.caseId)}/artifacts/${encodeURIComponent(f)}`);
        $(“evidenceFileContent”).innerHTML = `<pre class=”artifact-content”>${escapeHtml(payload.content || “Empty file.”)}</pre>`;
      } catch (err) {
        $(“evidenceFileContent”).innerHTML = `<p class=”evidence-missing”>${escapeHtml(err.message)}</p>`;
      }
    });
  });
  if (scratchFiles.length) {
    const first = scratchFiles.find((f) => f.endsWith(“stdout.txt”)) || scratchFiles[0];
    const firstBtn = $(“evidenceContent”).querySelector(`.evidence-file-btn[data-idx=”${scratchFiles.indexOf(first)}”]`);
    if (firstBtn) firstBtn.click();
  }
}

$("caseSelect").addEventListener("change", (event) => {
  state.selectedRoom = null;
  const id = event.target.value;
  history.replaceState(null, "", id ? `?case=${encodeURIComponent(id)}` : "/");
  loadCase(id);
});
$("technicalToggle").addEventListener("click", () => {
  state.technical = true;
  $("technicalToggle").classList.add("active");
  $("plainToggle").classList.remove("active");
  if (state.snapshot) renderSidePanel(state.snapshot);
});
$("plainToggle").addEventListener("click", () => {
  state.technical = false;
  $("plainToggle").classList.add("active");
  $("technicalToggle").classList.remove("active");
  if (state.snapshot) renderSidePanel(state.snapshot);
});
$("streamToggle").addEventListener("click", () => {
  state.sideView = "stream";
  if (state.snapshot) renderSidePanel(state.snapshot);
});
$("finalToggle").addEventListener("click", () => {
  state.sideView = "final";
  if (state.snapshot) renderSidePanel(state.snapshot);
});
$("newCaseButton").addEventListener("click", () => $("newCaseDialog").showModal());
$("closeDialog").addEventListener("click", () => $("newCaseDialog").close());
$("closeReport").addEventListener("click", () => $("reportDialog").close());
$("closeEvidence").addEventListener("click", () => $("evidenceDialog").close());
$("newCaseForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("formError").textContent = "";
  const payload = Object.fromEntries(new FormData(event.target).entries());
  try {
    await api("/api/investigations", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
    });
    $("newCaseDialog").close();
    location.href = `?case=${encodeURIComponent(payload.case_id)}`;
  } catch (error) {
    $("formError").textContent = error.message;
  }
});

function scheduleNextPoll() {
  const delay = state.snapshot?.complete ? 10000 : 1500;
  state.timer = setTimeout(async () => {
    if (state.caseId) await loadCase(state.caseId);
    scheduleNextPoll();
  }, delay);
}

loadCases().then(() => { scheduleNextPoll(); });
