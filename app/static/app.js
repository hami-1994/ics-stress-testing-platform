// app.js — 前端邏輯（純 vanilla JS，無需建置流程，開了就能跑）

const state = {
  projectId: null,
  ws: null,
  categories: {},          // { category: [item, ...] }
  testItemsByModule: {},    // { module_path: item }，開頁就先載入一份給各處查「這個測項是什麼類型」用
  selectedItem: null,       // 目前在「測試佇列」表單選到的測項物件
  selectedPortsCache: [],
  currentRun: null,         // { id, name, port, attempt, duration } 目前執行中的測項（給 test_progress 用，避免被覆蓋掉名稱）
  monitorHistory: {},       // { monitorType: { values: [...], levels: [...] } } 給 sparkline/心跳條用
};

// 攻擊手法類型 icon/label（跟 app/registry.py 的 TEST_TYPE_LABELS 對應，這裡重複一份純粹是
// 給沒有帶 test_type_label/test_type_icon 欄位的舊快取資料當保險，正常情況下都直接讀後端給的值）
const TEST_TYPE_FALLBACK = {
  traffic: { icon: "🌊", label: "流量型" },
  resource: { icon: "🧠", label: "資源占用型" },
};

// ---- 「建議測項」服務關鍵字比對表 ----
// 目的是即使服務跑在非標準 port 上，也能被辨識出來並出現在建議測項清單。
// key 跟各 plugin 模組的 CATEGORY 完全一致；value 是一組小寫關鍵字，只要 nmap -sV 掃到的
// service_name／banner，或使用者手動幫 Port 填寫的 note，包含其中任何一個關鍵字（不分
// 大小寫、部分字串比對），就視為「這個 Port 疑似在跑這個分類的服務」，不管 Port 號碼是不是
// 這個分類的標準 Port。「一般」與「網路層 (ARP/ICMP/IGMP/LLDP)」是通用/L2 分類，不需要
// （也無法）用服務關鍵字比對，維持原本純 Port／協定比對的邏輯，不列在這裡。
const CATEGORY_KEYWORDS = {
  "Modbus TCP": ["modbus", "mbap"],
  "DNP3": ["dnp3", "dnp "],
  "IEC 60870-5-104": ["iec104", "iec-104", "iec 104", "60870"],
  "IEC 61850 (GOOSE)": ["goose", "iec61850", "iec 61850", "61850"],
  "IEC 61850 (MMS)": ["iec61850", "iec 61850", "61850", "mms"],
  "BACnet": ["bacnet"],
  "EtherNet/IP (CIP)": ["ethernet/ip", "ethernetip", "enip", "cip"],
  "Siemens S7": ["s7comm", "s7 ", "step7", "step 7", "siemens"],
  "PROFINET": ["profinet", "profi-net"],
  "EtherCAT": ["ethercat"],
  "FINS (Omron PLC)": ["fins", "omron"],
  "KNX/IP (建築自動化)": ["knx", "knxnet"],
  "OPC UA": ["opcua", "opc-ua", "opc.tcp", "opc ua"],
  "MQTT": ["mqtt"],
  "CoAP (物聯網)": ["coap"],
  "LoRaWAN Gateway Bridge": ["lorawan", "lora "],
  "RTSP/ONVIF (IP攝影機)": ["rtsp", "onvif"],
  "UPnP/SSDP (物聯網)": ["upnp", "ssdp"],
  "mDNS (物聯網服務發現)": ["mdns", "zeroconf", "bonjour"],
  "SNMP": ["snmp"],
  "NTP": ["ntp"],
  "DNS": ["domain", "dns"],
  "FTP": ["ftp"],
  "TFTP (韌體更新)": ["tftp"],
  "Telnet": ["telnet"],
  "SSH": ["ssh"],
  "RDP": ["rdp", "ms-wbt-server", "terminal services"],
  "VNC": ["vnc", "rfb"],
  "SMB/CIFS": ["smb", "cifs", "microsoft-ds", "netbios"],
  "RPC": ["rpcbind", "msrpc", "portmapper", " rpc"],
  "Redis": ["redis"],
  "HTTP/Web": ["http", "www"],
  "工控閘道器 (Gateway)": ["gateway"],
};

function testTypeBadge(item) {
  if (!item) return "";
  const icon = item.test_type_icon || (TEST_TYPE_FALLBACK[item.test_type] || {}).icon || "";
  const label = item.test_type_label || (TEST_TYPE_FALLBACK[item.test_type] || {}).label || "";
  if (!label) return "";
  return `<span class="test-type-badge test-type-${item.test_type || "traffic"}">${icon} ${label}</span>`;
}

function testTypeBadgeForModule(moduleName) {
  return testTypeBadge(state.testItemsByModule[moduleName]);
}

async function loadTestItemsIndex() {
  try {
    const items = await api("/api/test-items");
    state.testItemsByModule = Object.fromEntries(items.map((it) => [it.module, it]));
  } catch (e) { /* 非關鍵資料，載入失敗不影響其他功能 */ }
}

const LEVEL_ICON = { ok: "🟢", warn: "🟡", critical: "🔴" };
const LEVEL_LABEL = { ok: "正常", warn: "警示", critical: "異常", na: "不適用" };
const VERDICT_ICON = {
  pass: "✅", warn: "⚠️", fail: "❌", unknown: "❔",
  skipped: "⏭️", aborted_self_protect: "🛡️", unreachable: "🚫",
};
const VERDICT_LABEL = {
  pass: "通過", warn: "通過(有警示)", fail: "未通過", unknown: "無法判斷",
  skipped: "已跳過", aborted_self_protect: "已中止(資源保護)",
  unreachable: "無法測試(Port無回應)",
};
// 判定拆成兩個獨立維度（見 app/orchestrator.py 的
// _compute_axis_verdicts() 說明）——📶 過程穩定性看「執行期間」有沒有中斷超標，
// 🔁 恢復能力看「結束後」有沒有在時限內恢復，VERDICT_ICON/LABEL 的 pass/warn/fail/
// unknown 沿用共用，這裡只補兩個維度各自獨有的值（stability 的 warn、兩者共用的 na）。
const STABILITY_ICON = { pass: "🟢", warn: "🟡", fail: "🔴", unknown: "❔", na: "⚪" };
const STABILITY_LABEL = {
  pass: "過程穩定", warn: "曾短暫中斷(未超標)", fail: "中斷超過可接受秒數",
  unknown: "無法判斷", na: "不適用",
};
const RECOVERY_ICON = { pass: "🟢", fail: "🔴", unknown: "❔", na: "⚪" };
const RECOVERY_LABEL = {
  pass: "已恢復", fail: "未如期恢復", unknown: "無法判斷", na: "不適用",
};

// 各監控器類型的「主要數值」欄位，給心跳條旁邊的 sparkline 用
const MONITOR_PRIMARY_METRIC = {
  ping: "rtt_ms", service: "latency_ms", udp: "latency_ms",
  iface: "bps_recv", tcp: "established", self_resource: "cpu_percent",
};

// ---------- 共用小工具 ----------

async function api(path, options = {}) {
  const opts = { headers: { "Content-Type": "application/json" }, ...options };
  const res = await fetch(path, opts);
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (e) {}
    alert(`錯誤：${detail}`);
    throw new Error(detail);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}

function el(html) {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}

function fmtTs(iso) {
  if (!iso) return "-";
  return new Date(iso).toLocaleString("zh-TW", { hour12: false });
}

// ---------- Tab 切換 ----------

// 畫面分為「管理」／「執行專案」兩大分組（見 index.html 的
// #mode-switch、nav#tabs 內的 .tab-group[data-group]）。點任何一個分頁按鈕
// （不論是使用者手動點、還是程式呼叫 .click() 跳頁，例如建立專案後自動跳到
// Port Scan）都要連帶把該分頁所屬的分組顯示出來、另一組收起來，並同步
// #mode-switch 上對應按鈕的 active 樣式——所有分組切換邏輯集中在這一處，
// 避免各處手動 .click() 的地方要各自記得同步分組顯示。
function switchToGroup(groupName) {
  document.querySelectorAll("#mode-switch button").forEach((b) => b.classList.toggle("active", b.dataset.mode === groupName));
  document.querySelectorAll("#tabs .tab-group").forEach((g) => {
    g.style.display = g.dataset.group === groupName ? "" : "none";
  });
  document.querySelectorAll("[data-mode-hint]").forEach((s) => {
    s.style.display = s.dataset.modeHint === groupName ? "" : "none";
  });
}

document.querySelectorAll("#tabs button").forEach((btn) => {
  btn.addEventListener("click", () => {
    const group = btn.closest(".tab-group").dataset.group;
    switchToGroup(group);
    document.querySelectorAll("#tabs button").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
    if (btn.dataset.tab === "target-mgmt") loadTargets();
    if (btn.dataset.tab === "project-mgmt") loadHistory();
    if (btn.dataset.tab === "testitem-mgmt") loadTestItemMgmt();
    if (btn.dataset.tab === "storage") loadStorage();
    if (btn.dataset.tab === "scan") loadScanHistory();
    if (btn.dataset.tab === "ports") loadPorts();
    if (btn.dataset.tab === "monitors") { loadMonitorTypes(); loadMonitors(); }
    if (btn.dataset.tab === "plan") {
      loadPlan();
      Promise.all([loadCategories(), loadPortOptions()]).then(loadSuggestedItems);
    }
    if (btn.dataset.tab === "run") loadRunLiveTable();
  });
});

document.querySelectorAll("#mode-switch button").forEach((btn) => {
  btn.addEventListener("click", () => {
    // 切換模式時，跳到該分組底下第一個分頁（會觸發上面的分頁點擊邏輯，含分組顯示同步）。
    document.querySelector(`#tabs .tab-group[data-group="${btn.dataset.mode}"] button`).click();
  });
});

function fmtBytes(n) {
  if (n === null || n === undefined) return "-";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function setProject(project) {
  state.projectId = project.id;
  state.currentProject = project;
  document.getElementById("current-project-badge").textContent =
    `專案 #${project.id}：${project.name}（${project.status}）`;
  // 切換專案時清空上一個專案殘留的即時畫面狀態，避免看到舊資料
  state.currentRun = null;
  state.monitorHistory = {};
  const monitorLive = document.getElementById("monitor-live");
  if (monitorLive) monitorLive.innerHTML = "";
  const logEl = document.getElementById("log-live");
  if (logEl) logEl.textContent = "";
  const verdictLive = document.getElementById("run-verdict-live");
  if (verdictLive) verdictLive.innerHTML = "";
  const progressBar = document.getElementById("run-progress-bar");
  if (progressBar) progressBar.style.display = "none";
  document.getElementById("run-status").textContent = "尚未開始";
  // Port Scan 紀錄是 by 專案的（後端本來就有依 project_id 過濾），但畫面上的表格是
  // 上一個專案留下的殘留 DOM，不會自動清掉——切換專案時先清空，再重新載入這個專案自己的掃描紀錄，
  // 避免使用者誤以為新專案「還留著」上一個專案的掃描結果。
  const scanStatus = document.getElementById("scan-status");
  if (scanStatus) scanStatus.textContent = "";
  const scanTbody = document.querySelector("#scan-history-table tbody");
  if (scanTbody) scanTbody.innerHTML = "";
  loadScanHistory();
  connectWS(project.id);
}

// ---------- 1. 目標 / 專案 ----------

document.getElementById("form-target").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const body = {
    ip_or_host: f.get("ip_or_host"),
    description: f.get("description") || "",
    operator_name: f.get("operator_name"),
    scope_confirmed: f.get("scope_confirmed") === "on",
  };
  await api("/api/targets", { method: "POST", body: JSON.stringify(body) });
  e.target.reset();
  await loadTargets();
});

let allTargetsCache = [];

async function loadTargets() {
  allTargetsCache = await api("/api/targets");
  renderTargetsTable(allTargetsCache);

  const sel = document.getElementById("select-target");
  sel.innerHTML = allTargetsCache.map((t) => `<option value="${t.id}">#${t.id} ${t.ip_or_host} (${t.description || ""})</option>`).join("");
  return allTargetsCache;
}

function renderTargetsTable(targets) {
  const tbody = document.querySelector("#targets-table tbody");
  tbody.innerHTML = targets.map((t) => `
    <tr>
      <td>${t.id}</td>
      <td>${t.ip_or_host}</td>
      <td><input value="${t.description || ""}" onchange="updateTargetDescription(${t.id}, this.value)" style="width:220px"></td>
      <td>${t.confirmed_by}</td>
      <td>${fmtTs(t.confirmed_at)}</td>
      <td>${t.project_count}</td>
      <td>
        <button onclick="deleteTarget(${t.id})" ${t.project_count > 0 ? "disabled title=\"仍有專案使用中，無法刪除\"" : ""}>刪除</button>
      </td>
    </tr>
  `).join("");
}

document.getElementById("target-search").addEventListener("input", (e) => {
  const q = e.target.value.trim().toLowerCase();
  const filtered = allTargetsCache.filter(
    (t) => t.ip_or_host.toLowerCase().includes(q) || (t.description || "").toLowerCase().includes(q)
  );
  renderTargetsTable(filtered);
});

async function updateTargetDescription(targetId, description) {
  await api(`/api/targets/${targetId}`, { method: "PATCH", body: JSON.stringify({ description }) });
  await loadTargets();
}

async function deleteTarget(targetId) {
  if (!confirm(`確定要刪除目標 #${targetId} 嗎？`)) return;
  await api(`/api/targets/${targetId}`, { method: "DELETE" });
  await loadTargets();
}

document.getElementById("form-project").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const body = {
    name: f.get("name"),
    target_id: parseInt(f.get("target_id"), 10),
    operator_name: f.get("operator_name"),
    max_interruption_sec: parseInt(f.get("max_interruption_sec"), 10) || 0,
    recovery_wait_sec: parseInt(f.get("recovery_wait_sec"), 10) || 0,
  };
  const project = await api("/api/projects", { method: "POST", body: JSON.stringify(body) });
  setProject(project);
  document.querySelector('#tabs button[data-tab="scan"]').click();
});

// ---------- 2. Port Scan ----------

document.getElementById("form-scan").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!requireProject()) return;
  const f = new FormData(e.target);
  const body = { scan_type: f.get("scan_type"), port_range: f.get("port_range") };
  const scanRow = await api(`/api/projects/${state.projectId}/scans`, { method: "POST", body: JSON.stringify(body) });
  document.getElementById("scan-status").textContent = `掃描 #${scanRow.id} 已啟動，狀態：${scanRow.status}`;
  pollScan(scanRow.id);
});

async function pollScan(scanId) {
  const poll = async () => {
    const s = await api(`/api/projects/${state.projectId}/scans/${scanId}`);
    document.getElementById("scan-status").textContent = `掃描 #${s.id} 狀態：${s.status}${s.error ? " — " + s.error : ""}`;
    await loadScanHistory();
    if (s.status === "pending" || s.status === "running") {
      setTimeout(poll, 2000);
    } else if (s.status === "completed") {
      alert("掃描完成，可以切到「Port 選擇」查看結果");
    }
  };
  poll();
}

async function loadScanHistory() {
  if (!state.projectId) return;
  const scans = await api(`/api/projects/${state.projectId}/scans`);
  const tbody = document.querySelector("#scan-history-table tbody");
  tbody.innerHTML = scans.map((s) => `
    <tr><td>${s.id}</td><td>${s.scan_type}</td><td>${s.port_range}</td>
    <td class="status-${s.status}">${s.status}</td>
    <td>${fmtTs(s.started_at)}</td><td>${fmtTs(s.finished_at)}</td></tr>
  `).join("");
}

// ---------- 3. Port 選擇 ----------

document.getElementById("form-add-port").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!requireProject()) return;
  const f = new FormData(e.target);
  const body = {
    port: parseInt(f.get("port"), 10),
    protocol: f.get("protocol"),
    service_name: f.get("service_name") || "",
  };
  await api(`/api/projects/${state.projectId}/ports`, { method: "POST", body: JSON.stringify(body) });
  e.target.reset();
  await loadPorts();
});

async function loadPorts() {
  if (!state.projectId) return;
  const ports = await api(`/api/projects/${state.projectId}/ports`);
  const tbody = document.querySelector("#ports-table tbody");
  tbody.innerHTML = ports.map((p) => `
    <tr>
      <td><input type="checkbox" ${p.selected ? "checked" : ""} onchange="togglePort(${p.id}, this.checked)"></td>
      <td>${p.port}</td><td>${p.protocol}</td><td>${p.state}</td>
      <td>${p.service_name}</td><td>${p.banner}</td><td>${p.source}</td>
      <td><input value="${p.note || ""}" onchange="updatePortNote(${p.id}, this.value)" style="width:120px"></td>
      <td><button onclick="deletePort(${p.id})">刪除</button></td>
    </tr>
  `).join("");
}

async function togglePort(portId, checked) {
  await api(`/api/projects/${state.projectId}/ports/${portId}`, { method: "PATCH", body: JSON.stringify({ selected: checked }) });
}
async function updatePortNote(portId, note) {
  await api(`/api/projects/${state.projectId}/ports/${portId}`, { method: "PATCH", body: JSON.stringify({ note }) });
}
async function deletePort(portId) {
  await api(`/api/projects/${state.projectId}/ports/${portId}`, { method: "DELETE" });
  await loadPorts();
}

// ---------- 4. 監控器 ----------

async function loadMonitorTypes() {
  const types = await api(`/api/projects/${state.projectId || 0}/monitors/available`);
  state.availableMonitorTypes = types;
  const container = document.getElementById("monitor-types");
  container.innerHTML = types.map((t) => `<button onclick="addMonitor('${t.type}')">+ ${t.name}</button>`).join(" ");
}

async function addMonitor(type) {
  if (!requireProject()) return;
  await api(`/api/projects/${state.projectId}/monitors`, { method: "POST", body: JSON.stringify({ type, enabled: true, config_json: {} }) });
  await loadMonitors();
}

// 監控器頁預設全選（除了 UDP 服務監控——只有測試範圍（已選 Port）
// 涵蓋 UDP 協定時才預設加入），讓使用者一進來就有一組合理的預設組合可以用，
// 不用每次都自己一個一個點「+」加。使用者仍然可以自由移除/新增，只有「這個專案
// 目前一個監控器都還沒設定」時才會觸發自動預設，不會覆蓋使用者自己調整過的組合。
async function ensureDefaultMonitors(existingMonitors) {
  if (existingMonitors.length > 0) return existingMonitors; // 使用者已經有自己的設定，不動它
  if (!state.projectId) return existingMonitors;

  const types = state.availableMonitorTypes || await api(`/api/projects/${state.projectId}/monitors/available`);
  let ports = [];
  try { ports = await api(`/api/projects/${state.projectId}/ports`); } catch (e) { ports = []; }
  const hasUdpInScope = ports.some((p) => p.protocol === "udp" && p.selected);

  const defaultTypes = types
    .map((t) => t.type)
    .filter((type) => type !== "udp" || hasUdpInScope);

  if (defaultTypes.length === 0) return existingMonitors;

  await Promise.all(defaultTypes.map((type) =>
    api(`/api/projects/${state.projectId}/monitors`, { method: "POST", body: JSON.stringify({ type, enabled: true, config_json: {} }) })
      .catch(() => null)));

  return api(`/api/projects/${state.projectId}/monitors`);
}

async function loadMonitors() {
  if (!state.projectId) return;
  let monitors = await api(`/api/projects/${state.projectId}/monitors`);
  monitors = await ensureDefaultMonitors(monitors);
  const tbody = document.querySelector("#monitors-table tbody");
  tbody.innerHTML = monitors.map((m) => `
    <tr><td>${m.type}</td><td><code>${JSON.stringify(m.config_json)}</code></td>
    <td><button onclick="removeMonitor(${m.id})">移除</button></td></tr>
  `).join("");
}

async function removeMonitor(id) {
  await api(`/api/projects/${state.projectId}/monitors/${id}`, { method: "DELETE" });
  await loadMonitors();
}

// ---------- 5. 測試佇列 ----------

async function loadCategories() {
  state.categories = await api("/api/test-items/by-category");
  const catSel = document.getElementById("category-select");
  catSel.innerHTML = Object.keys(state.categories).map((c) => `<option value="${c}">${c}</option>`).join("");
  catSel.onchange = renderItemOptions;
  renderItemOptions();
}

function renderItemOptions() {
  const cat = document.getElementById("category-select").value;
  const items = state.categories[cat] || [];
  const itemSel = document.getElementById("test-item-select");
  itemSel.innerHTML = items.map((it) => `<option value="${it.module}">${it.test_type_icon || ""} ${it.name}</option>`).join("");
  itemSel.onchange = renderParamFields;
  renderParamFields();
}

function renderParamFields() {
  const cat = document.getElementById("category-select").value;
  const moduleName = document.getElementById("test-item-select").value;
  const item = (state.categories[cat] || []).find((it) => it.module === moduleName);
  state.selectedItem = item;
  const container = document.getElementById("param-fields");
  if (!item) { container.innerHTML = ""; return; }

  // 有上下限的參數會顯示可調範圍，超出範圍時擋下送出。
  // 這裡在每個數值欄位旁邊補上「可調範圍：min ~ max」的提示文字，並預留一個錯誤訊息 span
  // （data-param-error），送出時如果超出範圍就把訊息寫進這個 span，同時整段送出動作會被擋下。
  container.innerHTML = Object.entries(item.param_schema).map(([key, spec]) => {
    const inputType = spec.type === "bool" ? "checkbox" : (spec.type === "int" || spec.type === "float" ? "number" : "text");
    const attrs = inputType === "checkbox"
      ? (spec.default ? "checked" : "")
      : `value="${spec.default ?? ""}" ${spec.min !== undefined ? `min="${spec.min}"` : ""} ${spec.max !== undefined ? `max="${spec.max}"` : ""} ${spec.type === "float" ? 'step="any"' : ""}`;
    const rangeHint = (spec.min !== undefined && spec.max !== undefined)
      ? `<span class="param-range-hint">可調範圍：${spec.min} ~ ${spec.max}</span>` : "";
    return `<label>${key}${spec.desc ? ` — ${spec.desc}` : ""}${rangeHint}
      <input type="${inputType}" data-param="${key}" data-type="${spec.type}" ${attrs}>
      <span class="param-error" data-param-error="${key}"></span></label>`;
  }).join("");
}

// 共用的參數區間驗證，供「測試佇列」新增表單與「編輯」JSON 表單共用。
// 回傳超出範圍（或不是合法數字）的項目清單；空陣列代表全部合法。
function validateParamsAgainstSchema(schema, params) {
  const violations = [];
  for (const [key, spec] of Object.entries(schema || {})) {
    if (spec.type !== "int" && spec.type !== "float") continue;
    if (!(key in params)) continue;
    const v = params[key];
    if (typeof v !== "number" || Number.isNaN(v)) {
      violations.push({ key, value: params[key], reason: "不是有效數字" });
      continue;
    }
    if (spec.min !== undefined && v < spec.min) {
      violations.push({ key, value: v, min: spec.min, max: spec.max });
    } else if (spec.max !== undefined && v > spec.max) {
      violations.push({ key, value: v, min: spec.min, max: spec.max });
    }
  }
  return violations;
}

function violationsToMessage(violations) {
  return violations.map((v) => v.reason
    ? `「${v.key}」：${v.reason}`
    : `「${v.key}」目前輸入 ${v.value}，超出允許範圍（${v.min} ~ ${v.max}），請修改後再送出`
  ).join("\n");
}

// 依 module 名稱找回該測項的 param_schema（供「編輯」JSON 表單驗證用；state.categories 在
// loadCategories() 已載入，涵蓋所有分類底下的測項）。
function findItemByModule(moduleName) {
  const allItems = Object.values(state.categories || {}).flat();
  return allItems.find((it) => it.module === moduleName);
}

async function loadPortOptions() {
  if (!state.projectId) return;
  const ports = await api(`/api/projects/${state.projectId}/ports`);
  state.selectedPortsCache = ports.filter((p) => p.selected);
  const sel = document.getElementById("port-select");
  sel.innerHTML = `<option value="">（不指定 / Layer2 測項）</option>` +
    state.selectedPortsCache.map((p) => `<option value="${p.id}">${p.port}/${p.protocol} ${p.service_name || ""}</option>`).join("");
}

function defaultParamsFor(item) {
  const params = {};
  Object.entries(item.param_schema || {}).forEach(([key, spec]) => { params[key] = spec.default; });
  return params;
}

// 把一個 port 掃描結果可能帶有的服務線索（nmap -sV 的 service_name/banner，或使用者手動
// 填寫的 note）組成一個小寫字串，供關鍵字比對用。
function portKeywordText(p) {
  return [p.service_name, p.banner, p.note].filter(Boolean).join(" ").toLowerCase();
}

// 找出這個測項的分類關鍵字裡，有沒有任一個出現在 port 的服務線索字串中；有的話回傳「命中
// 的關鍵字」，沒有回傳 null。呼應使用者需求：「即使服務出現在奇怪的 port，也可以識別出來」
// ——不看 Port 號碼，只看 nmap 掃到的服務名稱/banner 或使用者填寫的備註內容。
function matchedServiceKeyword(item, p) {
  const keywords = CATEGORY_KEYWORDS[item.category];
  if (!keywords || !keywords.length) return null;
  const text = portKeywordText(p);
  if (!text) return null;
  return keywords.find((kw) => text.includes(kw)) || null;
}

function loadSuggestedItems() {
  const container = document.getElementById("suggested-items");
  if (!container) return;
  const allItems = Object.values(state.categories).flat();
  const ports = state.selectedPortsCache || [];

  // 找出每個測項適用的 port（一般/L2 測項不限定特定 port，仍然建議，但不特別綁定某一個 port）
  const suggestions = [];
  const seen = new Set(); // 用來去重：同一個測項 + 同一個 port 只建議一次（避免 port 比對跟關鍵字比對重複列出）
  const addSuggestion = (item, port, reason) => {
    const key = `${item.module}::${port ? port.id : "null"}`;
    if (seen.has(key)) return;
    seen.add(key);
    suggestions.push({ item, port, reason });
  };

  for (const item of allItems) {
    if (item.protocol === "L2") {
      addSuggestion(item, null, "Layer2 測項，不限定 Port");
      continue;
    }
    for (const p of ports) {
      const protocolMatch = item.protocol && item.protocol.toLowerCase() === p.protocol;
      const isGeneric = item.category === "一般" && protocolMatch;
      const isPortMatch = item.default_port && item.default_port === p.port;
      if (isGeneric || isPortMatch) {
        addSuggestion(item, p, isPortMatch ? `符合 Port ${p.port} 的預設協定` : `一般 ${p.protocol.toUpperCase()} 測項，適用 Port ${p.port}`);
      }
    }
  }

  // 服務關鍵字比對（不管 Port 號碼是不是這個分類的標準 Port）：只要 nmap 掃到的服務名稱/
  // banner，或使用者手動填的備註，包含這個分類的關鍵字，就建議套用到「這個實際掃到的 Port」
  // ——套用時 addSuggestionToQueue() 本來就是用 s.port.id 帶入實際 Port（見下方），不是測項
  // 自己的 default_port，所以這裡不用額外處理「自動轉換成對應 Port」，只要正確產生建議即可。
  for (const item of allItems) {
    if (item.protocol === "L2" || item.category === "一般") continue;
    for (const p of ports) {
      const kw = matchedServiceKeyword(item, p);
      if (!kw) continue;
      const nonStandardPort = !item.default_port || item.default_port !== p.port;
      const reason = nonStandardPort
        ? `偵測到服務關鍵字「${kw}」（Port ${p.port} 非此協定標準 Port），建議套用到 Port ${p.port} 測試`
        : `偵測到服務關鍵字「${kw}」，符合 Port ${p.port}`;
      addSuggestion(item, p, reason);
    }
  }

  if (!ports.length) {
    container.innerHTML = `<p class="suggest-empty">尚未在「3. Port 選擇」勾選任何 Port——目前僅顯示 Layer2 測項建議，勾選 Port 後會列出更多適用測項。</p>`;
  }
  if (!suggestions.length) {
    container.innerHTML += `<p class="suggest-empty">目前沒有符合的建議測項，可直接在下方表單手動選擇。</p>`;
    state._suggestions = [];
    return;
  }

  container.innerHTML += suggestions.map((s, i) => `
    <div class="suggest-card">
      <div class="cat">${s.item.category}${s.port ? " · Port " + s.port.port + "/" + s.port.protocol : ""} ${testTypeBadge(s.item)}</div>
      <div class="name">${s.item.name}</div>
      <div class="field-hint" style="margin:0">${s.reason}</div>
      <button type="button" onclick='addSuggestionToQueue(${i})'>加入佇列</button>
    </div>
  `).join("");
  state._suggestions = suggestions;
}

async function addSuggestionToQueue(index) {
  const s = state._suggestions[index];
  if (!s || !requireProject()) return;
  const body = {
    port_id: s.port ? s.port.id : null,
    test_item_module: s.item.module,
    params_json: defaultParamsFor(s.item),
    duration_sec: parseInt(document.getElementById("duration-input").value, 10) || 300,
    capture_mode: document.getElementById("capture-mode-select").value || "summary",
  };
  await api(`/api/projects/${state.projectId}/runs`, { method: "POST", body: JSON.stringify(body) });
  await loadPlan();
}

document.getElementById("btn-add-all-suggestions").addEventListener("click", async () => {
  if (!requireProject()) return;
  const suggestions = state._suggestions || [];
  if (!suggestions.length) { alert("目前沒有建議測項可加入"); return; }
  if (!confirm(`確定要把目前列出的 ${suggestions.length} 個建議測項全部加入佇列嗎？`)) return;
  for (let i = 0; i < suggestions.length; i++) {
    await addSuggestionToQueue(i);
  }
});

document.getElementById("form-add-run").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!requireProject()) return;
  if (!state.selectedItem) { alert("請先選擇測項"); return; }
  const portValRaw = document.getElementById("port-select").value;
  if (state.selectedItem.protocol !== "L2" && !portValRaw) {
    alert(`「${state.selectedItem.name}」不是 Layer2 測項，必須先在「3. Port 選擇」勾選並在這裡指定目標 Port`);
    return;
  }

  const params = {};
  document.querySelectorAll("#param-fields [data-param]").forEach((input) => {
    const key = input.dataset.param;
    const type = input.dataset.type;
    if (type === "bool") params[key] = input.checked;
    else if (type === "int") params[key] = parseInt(input.value, 10);
    else if (type === "float") params[key] = parseFloat(input.value);
    else params[key] = input.value;
  });

  // 送出前檢查每個數值參數是否落在 schema 的 min~max 區間內，
  // 超出範圍就把訊息寫在對應欄位下面並整段擋下，不呼叫 API、不加入佇列。
  document.querySelectorAll("#param-fields [data-param-error]").forEach((el) => { el.textContent = ""; });
  const violations = validateParamsAgainstSchema(state.selectedItem.param_schema, params);
  if (violations.length) {
    violations.forEach((v) => {
      const el = document.querySelector(`#param-fields [data-param-error="${v.key}"]`);
      if (el) el.textContent = v.reason || `超出範圍（${v.min} ~ ${v.max}），目前輸入 ${v.value}`;
    });
    alert(`以下參數超出允許範圍，請修改後再加入佇列：\n\n${violationsToMessage(violations)}`);
    return;
  }

  const portId = document.getElementById("port-select").value;
  const body = {
    port_id: portId ? parseInt(portId, 10) : null,
    test_item_module: state.selectedItem.module,
    params_json: params,
    duration_sec: parseInt(document.getElementById("duration-input").value, 10),
    capture_mode: document.getElementById("capture-mode-select").value,
  };
  await api(`/api/projects/${state.projectId}/runs`, { method: "POST", body: JSON.stringify(body) });
  await loadPlan();
});

async function loadPlan() {
  if (!state.projectId) return;
  const [runs, ports] = await Promise.all([
    api(`/api/projects/${state.projectId}/runs`),
    api(`/api/projects/${state.projectId}/ports`),
  ]);
  state._planRunsCache = runs;
  state._planPortsCache = ports;
  const tbody = document.querySelector("#plan-table tbody");
  tbody.innerHTML = runs.map((r, i) => `
    <tr id="plan-row-${r.id}"><td>${i + 1}</td><td>${r.test_item_name}</td>
    <td>${testTypeBadgeForModule(r.test_item_module)}</td><td>${r.category}</td>
    <td>${portLabel(r.port_id, ports)}</td><td>${r.duration_sec}s</td><td>${r.capture_mode}</td>
    <td class="status-${r.status}">${r.status}</td>
    <td>${r.status === "pending" ? `<button onclick="editRun(${r.id})">編輯</button> <button onclick="deleteRun(${r.id})">移除</button>` : ""}</td></tr>
  `).join("");
}

function portLabel(portId, ports) {
  if (!portId) return "Layer2 / 不指定";
  const p = (ports || []).find((x) => x.id === portId);
  return p ? `${p.port}/${p.protocol}${p.service_name ? " " + p.service_name : ""}` : `port#${portId}`;
}

function editRun(runId) {
  const run = (state._planRunsCache || []).find((r) => r.id === runId);
  const row = document.getElementById(`plan-row-${runId}`);
  if (!run || !row) return;
  const ports = state._planPortsCache || [];
  const portOptions = `<option value="">（不指定 / Layer2）</option>` +
    ports.map((p) => `<option value="${p.id}" ${p.id === run.port_id ? "selected" : ""}>${p.port}/${p.protocol} ${p.service_name || ""}</option>`).join("");
  row.innerHTML = `
    <td colspan="9">
      <div class="inline-edit">
        <label>Port<select id="edit-port-${runId}">${portOptions}</select></label>
        <label>時長(秒)<input id="edit-duration-${runId}" type="number" value="${run.duration_sec}" min="1" max="1800"></label>
        <label>封包擷取<select id="edit-capture-${runId}">
          <option value="none" ${run.capture_mode === "none" ? "selected" : ""}>不錄</option>
          <option value="pcap" ${run.capture_mode === "pcap" ? "selected" : ""}>完整 pcap</option>
          <option value="summary" ${run.capture_mode === "summary" ? "selected" : ""}>流量摘要</option>
          <option value="both" ${run.capture_mode === "both" ? "selected" : ""}>兩者都要</option>
        </select></label>
        <label>參數（JSON 格式）<textarea id="edit-params-${runId}" rows="2">${JSON.stringify(run.params_json)}</textarea></label>
        <div class="button-row">
          <button type="button" class="primary" onclick="saveRunEdit(${runId})">儲存</button>
          <button type="button" onclick="loadPlan()">取消</button>
        </div>
      </div>
    </td>
  `;
}

async function saveRunEdit(runId) {
  const portVal = document.getElementById(`edit-port-${runId}`).value;
  const body = {
    port_id: portVal ? parseInt(portVal, 10) : null,
    duration_sec: parseInt(document.getElementById(`edit-duration-${runId}`).value, 10),
    capture_mode: document.getElementById(`edit-capture-${runId}`).value,
  };
  try {
    body.params_json = JSON.parse(document.getElementById(`edit-params-${runId}`).value || "{}");
  } catch (e) {
    alert("參數欄位不是合法的 JSON 格式，請檢查後再儲存");
    return;
  }

  // 這裡是自由填寫的 JSON，一樣要對照該測項的 param_schema 檢查
  // min~max，超出範圍需顯示錯誤訊息且不能存檔。
  const run = (state._planRunsCache || []).find((r) => r.id === runId);
  const item = run ? findItemByModule(run.test_item_module) : null;
  if (item && item.param_schema) {
    const violations = validateParamsAgainstSchema(item.param_schema, body.params_json);
    if (violations.length) {
      alert(`以下參數超出允許範圍，無法儲存：\n\n${violationsToMessage(violations)}`);
      return;
    }
  }

  await api(`/api/projects/${state.projectId}/runs/${runId}`, { method: "PATCH", body: JSON.stringify(body) });
  await loadPlan();
}

async function deleteRun(runId) {
  await api(`/api/projects/${state.projectId}/runs/${runId}`, { method: "DELETE" });
  await loadPlan();
}

// ---------- 6. 執行控制 ----------

async function runControlAction(btn, path, busyText, opts = {}) {
  if (!requireProject()) return;
  if (opts.confirmMsg && !confirm(opts.confirmMsg)) return;
  const originalText = btn.textContent;
  btn.disabled = true;
  btn.textContent = busyText;
  document.getElementById("run-status").textContent = busyText;
  try {
    await api(`/api/projects/${state.projectId}/runs/${path}`, { method: "POST" });
  } finally {
    btn.disabled = false;
    btn.textContent = originalText;
  }
}

document.getElementById("btn-start-queue").addEventListener("click", (e) => {
  requestNotificationPermissionIfNeeded();
  runControlAction(e.target, "start", "正在啟動測試佇列...");
});
document.getElementById("btn-stop-current").addEventListener("click", (e) =>
  runControlAction(e.target, "stop", "正在送出停止指令，請稍候（子行程結束前最多幾百毫秒延遲）..."));
document.getElementById("btn-skip-current").addEventListener("click", (e) =>
  runControlAction(e.target, "skip", "正在跳過目前測項...",
    { confirmMsg: "確定要跳過目前測項嗎？會直接中止、不判定通過/失敗，並自動接續下一項。" }));
document.getElementById("btn-resume-queue").addEventListener("click", (e) =>
  runControlAction(e.target, "resume", "正在恢復測試佇列..."));
document.getElementById("btn-kill-switch").addEventListener("click", (e) =>
  runControlAction(e.target, "kill-switch", "正在觸發緊急停止...",
    { confirmMsg: "確定要緊急停止全部測試嗎？剩餘佇列會全部標記為 stopped。" }));

async function loadRunLiveTable() {
  if (!state.projectId) return;
  const [runs, ports] = await Promise.all([
    api(`/api/projects/${state.projectId}/runs`),
    api(`/api/projects/${state.projectId}/ports`),
  ]);
  renderRunLiveTable(runs, ports);
}

function axisVerdictCellHtml(iconMap, labelMap, value) {
  if (!value || value === "unknown") return "-";
  return `${iconMap[value] || ""} ${labelMap[value] || value}`;
}

function renderRunLiveTable(runs, ports) {
  const tbody = document.querySelector("#run-live-table tbody");
  tbody.innerHTML = runs.map((r, i) => `
    <tr id="run-row-${r.id}"><td>${i + 1}</td><td>${r.test_item_name}</td>
    <td>${testTypeBadgeForModule(r.test_item_module)}</td>
    <td>${portLabel(r.port_id, ports)}</td>
    <td class="status-${r.status}">${r.status}</td><td>${r.attempt_no}</td>
    <td>${axisVerdictCellHtml(STABILITY_ICON, STABILITY_LABEL, r.stability_verdict)}</td>
    <td>${axisVerdictCellHtml(RECOVERY_ICON, RECOVERY_LABEL, r.recovery_verdict)}</td>
    <td>${r.verdict && r.verdict !== "unknown" ? (VERDICT_ICON[r.verdict] || "") + " " + (VERDICT_LABEL[r.verdict] || r.verdict) : "-"}</td></tr>
  `).join("");
}

// ---------- 7. 歷史專案 ----------

document.getElementById("btn-refresh-history").addEventListener("click", loadHistory);

// 刪除按鈕需要在確認對話框裡顯示專案名稱，但名稱是使用者自由輸入的文字，
// 直接把 JSON.stringify(p.name) 塞進 onclick="..." 這種雙引號 HTML 屬性裡，只要名稱本身包含雙引號，
// 屬性就會被提早截斷、產生「Unexpected end of input」的 JS 語法錯誤，導致整個刪除按鈕失效（連
// confirm() 對話框都不會跳出來）。改成把整批專案資料存起來，onclick 只傳純數字 id，需要名稱時
// 再從這裡查表，徹底避開字串跳脫的問題。
let _historyProjects = [];

async function loadHistory() {
  const [projects, targets] = await Promise.all([api("/api/projects"), api("/api/targets")]);
  _historyProjects = projects;
  const targetMap = Object.fromEntries(targets.map((t) => [t.id, t.ip_or_host]));
  const tbody = document.querySelector("#history-table tbody");
  tbody.innerHTML = projects.map((p) => `
    <tr>
      <td>${p.id}</td><td>${p.name}</td><td>${targetMap[p.target_id] || p.target_id}</td>
      <td>${p.operator_name}</td><td class="status-${p.status === "closed" ? "completed" : "running"}">${p.status}</td>
      <td>${fmtTs(p.created_at)}</td>
      <td><a href="#" onclick="openReport(${p.id}); return false;">檢視報告</a></td>
      <td><a href="#" onclick="downloadReportPdf(${p.id}); return false;">下載 PDF</a></td>
      <td><button onclick="toggleProjectFiles(${p.id})">Log／封包檔案</button></td>
      <td><button onclick="openOldProject(${p.id})">開啟此專案</button></td>
      <td><button class="danger" onclick="deleteProject(${p.id})">刪除</button></td>
    </tr>
  `).join("");
  document.getElementById("history-files-panel").innerHTML = "";
}

async function deleteProject(projectId) {
  const projectName = _historyProjects.find((p) => p.id === projectId)?.name || `#${projectId}`;
  if (!confirm(`確定要刪除專案「${projectName}」嗎？這個動作無法復原，會連同這個專案的所有測試紀錄、Log、封包擷取檔、報告一起永久刪除。`)) {
    return;
  }
  try {
    await api(`/api/projects/${projectId}`, { method: "DELETE" });
  } catch (e) {
    // api() 已經跳過 alert 顯示錯誤訊息，這裡只需要中止後續流程
    return;
  }
  if (state.projectId === projectId) {
    state.projectId = null;
    state.currentProject = null;
    document.getElementById("current-project-badge").textContent = "尚未選擇專案";
  }
  await loadHistory();
}

let _openFilesPanelProjectId = null;

async function toggleProjectFiles(projectId) {
  const panel = document.getElementById("history-files-panel");
  if (_openFilesPanelProjectId === projectId) {
    panel.innerHTML = "";
    _openFilesPanelProjectId = null;
    return;
  }
  _openFilesPanelProjectId = projectId;
  panel.innerHTML = `<p class="field-hint">載入中...</p>`;

  const [runs, storageData] = await Promise.all([
    api(`/api/projects/${projectId}/runs`),
    api("/api/storage/captures"),
  ]);
  const capturesByRun = {};
  storageData.items.filter((c) => c.project_id === projectId).forEach((c) => {
    (capturesByRun[c.test_run_id] = capturesByRun[c.test_run_id] || []).push(c);
  });

  const rows = runs.map((r) => {
    const captures = capturesByRun[r.id] || [];
    const captureLinks = captures.length
      ? captures.map((c) => c.deleted
          ? `<span style="color:var(--muted)">${c.mode}（已刪除，曾佔用 ${fmtBytes(c.size_bytes)}）</span>`
          : `<a href="/api/storage/captures/${c.id}/download">${c.mode} 下載（${fmtBytes(c.size_bytes)}）</a>`
        ).join("<br>")
      : "（無封包擷取檔案）";
    return `
      <tr>
        <td>#${r.id} ${r.test_item_name}</td>
        <td class="status-${r.status}">${r.status}</td>
        <td><a href="/api/projects/${projectId}/runs/${r.id}/log/download">下載 log</a></td>
        <td>${captureLinks}</td>
      </tr>`;
  }).join("");

  panel.innerHTML = `
    <h3>專案 #${projectId} — 各測項 Log／封包檔案</h3>
    <table>
      <thead><tr><th>測項</th><th>狀態</th><th>Log</th><th>封包擷取檔案</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="4">此專案還沒有任何測項</td></tr>`}</tbody>
    </table>
  `;
}

async function openReport(projectId) {
  const info = await api(`/api/projects/${projectId}/report`);
  if (!info.available) { alert("此專案尚未產生報告（測試佇列全部完成後才會自動產生）"); return; }
  window.open(info.html_url, "_blank");
}

async function downloadReportPdf(projectId) {
  const info = await api(`/api/projects/${projectId}/report`);
  if (!info.available) { alert("此專案尚未產生報告（測試佇列全部完成後才會自動產生）"); return; }
  if (!info.pdf_url) {
    alert("此環境尚未安裝 weasyprint（PDF 產生套件），無法下載 PDF。可以改用「檢視報告」開啟 HTML 版本，再用瀏覽器的「列印 -> 另存為 PDF」功能產生 PDF。");
    return;
  }
  window.open(info.pdf_url, "_blank");
}

// ---------- 8. 檔案管理（跨專案封包擷取檔案） ----------

document.getElementById("btn-storage-refresh").addEventListener("click", loadStorage);
document.getElementById("btn-storage-select-all").addEventListener("click", () => {
  const boxes = document.querySelectorAll("#storage-table tbody input[type=checkbox]");
  const anyUnchecked = Array.from(boxes).some((b) => !b.checked);
  boxes.forEach((b) => { b.checked = anyUnchecked; });
});
document.getElementById("btn-storage-delete-selected").addEventListener("click", async () => {
  const boxes = document.querySelectorAll("#storage-table tbody input[type=checkbox]:checked");
  const ids = Array.from(boxes).map((b) => parseInt(b.dataset.id, 10));
  if (!ids.length) { alert("請先勾選要刪除的檔案"); return; }
  if (!confirm(`確定要刪除勾選的 ${ids.length} 個檔案嗎？只會刪除實際檔案釋放空間，紀錄本身會保留（標示已刪除），此動作無法復原。`)) return;
  const operatorName = state.currentProject ? state.currentProject.operator_name : "";
  const result = await api("/api/storage/captures/delete", {
    method: "POST",
    body: JSON.stringify({ ids, operator_name: operatorName }),
  });
  if (result.errors && result.errors.length) {
    alert(`部分檔案刪除失敗：\n${result.errors.map((e) => `#${e.id}: ${e.error}`).join("\n")}`);
  } else {
    alert(`已刪除 ${result.deleted_ids.length} 個檔案，釋放 ${fmtBytes(result.freed_bytes)} 空間`);
  }
  loadStorage();
});

async function loadStorage() {
  const data = await api("/api/storage/captures");
  const s = data.summary;
  document.getElementById("storage-summary").innerHTML = `
    現存檔案 ${s.active_count} 個，共佔用 <strong>${fmtBytes(s.active_bytes)}</strong>
    ${s.deleted_count ? `　|　已刪除 ${s.deleted_count} 個，已釋放 ${fmtBytes(s.deleted_bytes_freed)}` : ""}
  `;
  const tbody = document.querySelector("#storage-table tbody");
  tbody.innerHTML = data.items.map((c) => {
    const statusLabel = c.deleted
      ? `<span style="color:var(--muted)">已刪除${c.deleted_at ? "（" + fmtTs(c.deleted_at) + "）" : ""}</span>`
      : (c.file_exists ? `<span style="color:var(--ok)">正常</span>` : `<span style="color:var(--warn)">紀錄存在但檔案遺失</span>`);
    const actions = c.deleted
      ? "-"
      : `<a href="/api/storage/captures/${c.id}/download">下載</a>
         <button onclick="deleteOneCapture(${c.id})" class="danger" style="padding:2px 8px">刪除</button>`;
    return `
      <tr>
        <td>${c.deleted ? "" : `<input type="checkbox" data-id="${c.id}">`}</td>
        <td>#${c.project_id} ${c.project_name}</td>
        <td>${c.target}</td>
        <td>#${c.test_run_id} ${c.run_name}</td>
        <td>${c.mode}</td>
        <td>${fmtBytes(c.size_bytes)}</td>
        <td>${statusLabel}</td>
        <td>${actions}</td>
      </tr>`;
  }).join("") || `<tr><td colspan="8">目前沒有任何封包擷取檔案</td></tr>`;
}

async function deleteOneCapture(captureId) {
  if (!confirm("確定要刪除這個檔案嗎？只會刪除實際檔案釋放空間，紀錄本身會保留，此動作無法復原。")) return;
  const operatorName = state.currentProject ? state.currentProject.operator_name : "";
  const result = await api("/api/storage/captures/delete", {
    method: "POST",
    body: JSON.stringify({ ids: [captureId], operator_name: operatorName }),
  });
  if (result.errors && result.errors.length) {
    alert(`刪除失敗：${result.errors[0].error}`);
  } else {
    alert(`已刪除，釋放 ${fmtBytes(result.freed_bytes)} 空間`);
  }
  loadStorage();
}

async function openOldProject(projectId) {
  const project = await api(`/api/projects/${projectId}`);
  setProject(project);
  document.querySelector('#tabs button[data-tab="plan"]').click();
}

// ---------- 測項管理（命名/預設參數覆寫、啟用停用、健康檢查） ----------

const HEALTH_ICON = { ok: "🟢", error: "🔴", unknown: "⚪" };
const HEALTH_LABEL = { ok: "健康檢查通過", error: "偵測到異常", unknown: "尚未檢查" };

let testItemMgmtCache = [];
let testItemParamEditorOpenFor = null; // 目前展開中的「編輯預設參數」列（module path），一次只開一個避免畫面太亂

function escapeHtml(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

document.getElementById("btn-testitem-recheck").addEventListener("click", async () => {
  const btn = document.getElementById("btn-testitem-recheck");
  btn.disabled = true;
  btn.textContent = "檢查中...（依測項數量可能需要數秒）";
  try {
    const result = await api("/api/test-items/healthcheck/run", { method: "POST" });
    alert(`健康檢查完成：共 ${result.total} 個測項，${result.ok} 個通過，${result.failed} 個偵測到異常。\n（已手動調整過啟用/停用狀態的測項不會被這次檢查覆寫）`);
    await loadTestItemMgmt();
  } finally {
    btn.disabled = false;
    btn.textContent = "重新檢查全部測項";
  }
});

document.getElementById("testitem-filter-status").addEventListener("change", renderTestItemTable);
document.getElementById("testitem-search").addEventListener("input", renderTestItemTable);

async function loadTestItemMgmt() {
  const data = await api("/api/test-items/health");
  testItemMgmtCache = data.items;
  const s = data.summary;
  document.getElementById("testitem-summary").innerHTML = `
    共 <strong>${s.total}</strong> 個測項　|
    🟢 通過 ${s.ok}　|　🔴 異常 ${s.error}　|　⚪ 尚未檢查 ${s.unknown}　|　已停用 ${s.disabled}
  `;
  renderTestItemTable();
}

function renderTestItemTable() {
  const statusFilter = document.getElementById("testitem-filter-status").value;
  const q = document.getElementById("testitem-search").value.trim().toLowerCase();
  const items = testItemMgmtCache.filter((it) => {
    if (statusFilter === "disabled" && it.enabled) return false;
    if (statusFilter !== "all" && statusFilter !== "disabled" && it.health_status !== statusFilter) return false;
    if (q && !(it.display_name.toLowerCase().includes(q) || it.category.toLowerCase().includes(q) || it.name.toLowerCase().includes(q))) return false;
    return true;
  });

  const tbody = document.querySelector("#testitem-table tbody");
  tbody.innerHTML = items.map((it) => {
    const moduleAttr = escapeHtml(it.module);
    const rowId = `ti-row-${it.module.replace(/[^a-zA-Z0-9]/g, "_")}`;
    const healthDetail = it.health_detail ? escapeHtml(it.health_detail) : "";
    const rows = [`
      <tr id="${rowId}">
        <td><input type="checkbox" ${it.enabled ? "checked" : ""} onchange="toggleTestItemEnabled('${moduleAttr}', this.checked)"></td>
        <td title="${healthDetail}">${HEALTH_ICON[it.health_status] || "⚪"} ${HEALTH_LABEL[it.health_status] || ""}
          ${it.health_status === "error" ? `<div class="field-hint" style="max-width:240px">${healthDetail}</div>` : ""}
        </td>
        <td>
          <input value="${escapeHtml(it.display_name)}" style="width:260px"
                 onchange="updateTestItemName('${moduleAttr}', this.value)">
          ${it.display_name !== it.name ? `<div class="field-hint">原始名稱：${escapeHtml(it.name)}</div>` : ""}
        </td>
        <td>${escapeHtml(it.category)}</td>
        <td>${escapeHtml(it.protocol)}${it.default_port ? ` :${it.default_port}` : ""}</td>
        <td>${testTypeBadge(it)}</td>
        <td>${renderEngineModeCell(it)}</td>
        <td><button onclick="toggleTestItemParamEditor('${moduleAttr}')" style="padding:2px 8px">
          預設參數（${Object.keys(it.param_schema || {}).length}）
        </button></td>
      </tr>`];
    if (testItemParamEditorOpenFor === it.module) {
      rows.push(`<tr><td colspan="8">${renderTestItemParamEditor(it)}</td></tr>`);
    }
    return rows.join("");
  }).join("") || `<tr><td colspan="8">沒有符合篩選條件的測項</td></tr>`;
}

function renderTestItemParamEditor(item) {
  const schema = item.param_schema || {};
  const fields = Object.entries(schema).map(([pname, pdef]) => {
    const id = `ti-param-${item.module.replace(/[^a-zA-Z0-9]/g, "_")}-${pname}`;
    const desc = pdef.desc ? `<div class="field-hint">${escapeHtml(pdef.desc)}</div>` : "";
    // 這裡改的是「日後套用到佇列的預設值」，一樣要顯示區間、
    // 存檔前一樣要擋超界的值，跟「4. 測試佇列」表單的邏輯一致。
    const rangeHint = (pdef.min !== undefined && pdef.max !== undefined)
      ? `<div class="param-range-hint">可調範圍：${pdef.min} ~ ${pdef.max}</div>` : "";
    let inputHtml;
    if (pdef.type === "bool") {
      inputHtml = `<select id="${id}"><option value="true" ${pdef.default ? "selected" : ""}>是</option><option value="false" ${!pdef.default ? "selected" : ""}>否</option></select>`;
    } else if (pdef.options) {
      inputHtml = `<select id="${id}">${pdef.options.map((o) => `<option value="${escapeHtml(o)}" ${o === pdef.default ? "selected" : ""}>${escapeHtml(o)}</option>`).join("")}</select>`;
    } else {
      const numType = pdef.type === "int" || pdef.type === "float";
      inputHtml = `<input id="${id}" type="${numType ? "number" : "text"}" ${pdef.type === "float" ? 'step="0.1"' : ""} ${pdef.min !== undefined ? `min="${pdef.min}"` : ""} ${pdef.max !== undefined ? `max="${pdef.max}"` : ""} value="${escapeHtml(pdef.default)}">`;
    }
    return `<label>${escapeHtml(pname)}${inputHtml}${rangeHint}${desc}<span class="param-error" data-param-error="${escapeHtml(pname)}"></span></label>`;
  }).join("");

  return `
    <div class="inline-edit">
      ${fields || "<p class='field-hint'>此測項沒有可調參數</p>"}
      <div class="button-row">
        <button class="primary" onclick="saveTestItemParams('${escapeHtml(item.module)}')">儲存為預設值</button>
        <button onclick="resetTestItemParams('${escapeHtml(item.module)}')">還原為測項原始預設值</button>
        <button onclick="toggleTestItemParamEditor('${escapeHtml(item.module)}')">關閉</button>
      </div>
    </div>`;
}

function toggleTestItemParamEditor(module) {
  testItemParamEditorOpenFor = testItemParamEditorOpenFor === module ? null : module;
  renderTestItemTable();
}

async function toggleTestItemEnabled(module, enabled) {
  await api(`/api/test-items/${encodeURIComponent(module)}`, { method: "PATCH", body: JSON.stringify({ enabled }) });
  await loadTestItemMgmt();
  await loadTestItemsIndex(); // 同步刷新其他分頁（測試佇列建議測項等）用到的測項索引快取
}

async function updateTestItemName(module, name) {
  await api(`/api/test-items/${encodeURIComponent(module)}`, { method: "PATCH", body: JSON.stringify({ custom_name: name }) });
  await loadTestItemMgmt();
  await loadTestItemsIndex();
}

// 「加速引擎」欄位——每個測項預設依系統建議
// （流量型 = 高並發加速版／資源占用型 = 標準版，見 registry.py 說明），使用者可在
// 這裡針對個別測項覆寫偏好；選「依系統建議」等於把偏好清空（PATCH engine_mode:null），
// 恢復成「跟隨系統建議」而不是寫死成當下這個建議值，之後系統建議策略調整時會自動跟上。
function renderEngineModeCell(item) {
  const moduleAttr = escapeHtml(item.module);
  const modeSelectId = `ti-engine-mode-${item.module.replace(/[^a-zA-Z0-9]/g, "_")}`;
  const workersInputId = `ti-engine-workers-${item.module.replace(/[^a-zA-Z0-9]/g, "_")}`;
  const isDefault = item.engine_mode_is_default;
  const modeSelect = `
    <select id="${modeSelectId}" onchange="updateTestItemEngineMode('${moduleAttr}', this.value)" style="width:150px">
      <option value="" ${isDefault ? "selected" : ""}>依系統建議（${escapeHtml(item.engine_mode_label)}）</option>
      <option value="native" ${!isDefault && item.engine_mode === "native" ? "selected" : ""}>標準版</option>
      <option value="concurrent" ${!isDefault && item.engine_mode === "concurrent" ? "selected" : ""}>高並發加速版</option>
    </select>`;
  const workersInput = item.engine_mode === "concurrent" ? `
    <input id="${workersInputId}" type="number" min="1" max="32" placeholder="10"
           value="${item.engine_workers != null ? item.engine_workers : ""}"
           title="並發執行緒數，留空使用系統預設值（10）"
           style="width:52px;margin-top:4px"
           onchange="updateTestItemEngineWorkers('${moduleAttr}', this.value)">` : "";
  return `${modeSelect}${workersInput}`;
}

async function updateTestItemEngineMode(module, value) {
  await api(`/api/test-items/${encodeURIComponent(module)}`, {
    method: "PATCH", body: JSON.stringify({ engine_mode: value || null }),
  });
  await loadTestItemMgmt();
}

async function updateTestItemEngineWorkers(module, value) {
  const n = value === "" ? null : parseInt(value, 10);
  if (n !== null && (!Number.isFinite(n) || n < 1 || n > 32)) {
    alert("並發執行緒數可調範圍：1 ~ 32");
    await loadTestItemMgmt();
    return;
  }
  await api(`/api/test-items/${encodeURIComponent(module)}`, {
    method: "PATCH", body: JSON.stringify({ engine_workers: n }),
  });
  await loadTestItemMgmt();
}

async function saveTestItemParams(module) {
  const item = testItemMgmtCache.find((it) => it.module === module);
  if (!item) return;
  const schema = item.param_schema || {};
  const values = {};
  for (const [pname, pdef] of Object.entries(schema)) {
    const elInput = document.getElementById(`ti-param-${module.replace(/[^a-zA-Z0-9]/g, "_")}-${pname}`);
    if (!elInput) continue;
    let v = elInput.value;
    if (pdef.type === "bool") v = v === "true";
    else if (pdef.type === "int") v = parseInt(v, 10);
    else if (pdef.type === "float") v = parseFloat(v);
    values[pname] = v;
  }

  // 這裡存的是往後套用到佇列的「新預設值」，超出 schema 的
  // min~max 一樣要擋下、不送出 API、並在對應欄位標出錯誤訊息。
  document.querySelectorAll("#testitem-table [data-param-error]").forEach((el) => { el.textContent = ""; });
  const violations = validateParamsAgainstSchema(schema, values);
  if (violations.length) {
    violations.forEach((v) => {
      const el = document.querySelector(`[data-param-error="${v.key}"]`);
      if (el) el.textContent = v.reason || `超出範圍（${v.min} ~ ${v.max}），目前輸入 ${v.value}`;
    });
    alert(`以下參數超出允許範圍，無法儲存為預設值：\n\n${violationsToMessage(violations)}`);
    return;
  }

  await api(`/api/test-items/${encodeURIComponent(module)}`, { method: "PATCH", body: JSON.stringify({ custom_params_json: values }) });
  testItemParamEditorOpenFor = null;
  await loadTestItemMgmt();
  await loadTestItemsIndex();
}

async function resetTestItemParams(module) {
  await api(`/api/test-items/${encodeURIComponent(module)}`, { method: "PATCH", body: JSON.stringify({ custom_params_json: {} }) });
  testItemParamEditorOpenFor = null;
  await loadTestItemMgmt();
  await loadTestItemsIndex();
}

// ---------- WebSocket 即時事件 ----------

function connectWS(projectId) {
  if (state.ws) state.ws.close();
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  state.ws = new WebSocket(`${protocol}//${location.host}/ws/project/${projectId}`);
  state.ws.onmessage = (evt) => handleWsEvent(JSON.parse(evt.data));
}

function handleWsEvent(event) {
  const logEl = document.getElementById("log-live");
  const statusEl = document.getElementById("run-status");
  const monitorLive = document.getElementById("monitor-live");
  const progressBar = document.getElementById("run-progress-bar");
  const progressFill = document.getElementById("run-progress-fill");
  const verdictLive = document.getElementById("run-verdict-live");

  switch (event.type) {
    case "test_started":
      state.currentRun = { id: event.test_run_id, name: event.item_name, port: event.port, attempt: event.attempt_no, duration: event.duration_sec };
      statusEl.textContent = `▶ 執行中：${event.item_name}（Port ${event.port ?? "-"}，第 ${event.attempt_no} 次嘗試，時長 ${event.duration_sec}s，已過 0s）`;
      progressBar.style.display = "block";
      progressFill.style.width = "0%";
      verdictLive.innerHTML = "";
      updateRunRowStatus(event.test_run_id, "running", event.attempt_no);
      logEl.textContent += `\n=== 開始：${event.item_name} ===\n`;
      break;
    case "test_progress": {
      // 修正過的 bug：以前這裡會直接覆蓋掉 statusEl 的內容，導致使用者看不到「目前在測哪一條測項」，
      // 現在改成把目前執行中測項的名稱（優先用 state.currentRun，事件本身也帶了 item_name 當備援）
      // 跟已過/剩餘秒數合併顯示。
      const name = (state.currentRun && state.currentRun.id === event.test_run_id) ? state.currentRun.name : event.item_name;
      const port = (state.currentRun && state.currentRun.id === event.test_run_id) ? state.currentRun.port : event.port;
      statusEl.textContent = `▶ 執行中：${name}（Port ${port ?? "-"}）— 已過 ${event.elapsed_sec}s，剩餘約 ${event.remaining_sec}s`;
      const total = event.elapsed_sec + event.remaining_sec;
      const pct = total > 0 ? Math.min(100, (event.elapsed_sec / total) * 100) : 0;
      progressFill.style.width = `${pct}%`;
      break;
    }
    case "log_line":
      logEl.textContent += event.line + "\n";
      logEl.scrollTop = logEl.scrollHeight;
      break;
    case "monitor_sample":
      renderMonitorCard(event.monitor, event.metrics);
      break;
    case "test_completed":
      statusEl.textContent = `■ 測項 #${event.test_run_id} 結束，狀態：${event.status}` +
        (event.interruption_sec ? `｜測試過程最長連續中斷 ${event.interruption_sec} 秒` : "") +
        (event.skip_reason ? `｜${event.skip_reason}` : "");
      progressFill.style.width = "100%";
      updateRunRowStatus(event.test_run_id, event.status);
      logEl.textContent += `=== 結束：狀態 ${event.status}${event.skip_reason ? "（" + event.skip_reason + "）" : ""} ===\n`;
      break;
    case "run_verdict": {
      const icon = VERDICT_ICON[event.verdict] || "";
      const label = VERDICT_LABEL[event.verdict] || event.verdict;
      // 判定拆成兩個獨立維度，即時橫幅一次顯示三個badge——📶 過程穩定性／
      // 🔁 恢復能力／🧮 綜合判定，讓操作者不用等報告產生就能看出問題出在哪個環節。
      const stabilityHtml = event.stability_verdict && event.stability_verdict !== "unknown"
        ? `<span class="verdict-badge verdict-${event.stability_verdict === "na" ? "skipped" : event.stability_verdict}">📶 ${STABILITY_ICON[event.stability_verdict] || ""} ${STABILITY_LABEL[event.stability_verdict] || event.stability_verdict}</span> `
        : "";
      const recoveryHtml = event.recovery_verdict && event.recovery_verdict !== "unknown"
        ? `<span class="verdict-badge verdict-${event.recovery_verdict === "na" ? "skipped" : event.recovery_verdict}">🔁 ${RECOVERY_ICON[event.recovery_verdict] || ""} ${RECOVERY_LABEL[event.recovery_verdict] || event.recovery_verdict}</span> `
        : "";
      verdictLive.innerHTML =
        `${stabilityHtml}${recoveryHtml}<span class="verdict-badge verdict-${event.verdict}">🧮 ${icon} 判定：${label}</span>`;
      updateRunRowVerdict(event.test_run_id, event.verdict, event.stability_verdict, event.recovery_verdict);
      break;
    }
    case "alert": {
      const prefix = { critical: "🔴", warn: "🟡", ok: "🟢", info: "ℹ️" }[event.level] || `[${event.level}]`;
      statusEl.textContent = `${prefix} ${event.message}`;
      logEl.textContent += `${prefix} ${event.message}\n`;
      logEl.scrollTop = logEl.scrollHeight;
      break;
    }
    case "project_closed": {
      statusEl.textContent = "✅ 整個測試佇列已完成，專案已關閉，報告已產生（見「管理 → 專案管理」，可線上檢視或下載 PDF）。";
      progressBar.style.display = "none";
      state.currentRun = null;
      // 整個專案測試完成之後跳出系統通知並自動切換到結果頁面——執行的工程師未必
      // 一直守在畫面前，回來時能第一時間看到結果，不用自己再點回去找。
      notifyProjectCompleted(state.projectId, state.currentProject);
      break;
    }
  }
}

// ---------- 專案完成通知 ----------

// 瀏覽器原生通知需要使用者授權；在使用者第一次開始執行測試佇列時順便請求一次權限
// （比起一進頁面就跳授權視窗，這個時機點使用者比較能理解「為什麼要通知我」，同意率較高）。
// 不支援 Notification API 的環境（例如某些內嵌瀏覽器）或使用者拒絕授權都不影響其他功能，
// 只是不會跳出系統通知，畫面上的狀態文字／log 一樣會照常更新。
function requestNotificationPermissionIfNeeded() {
  if (!("Notification" in window)) return;
  if (Notification.permission === "default") {
    Notification.requestPermission().catch(() => {});
  }
}

function notifyProjectCompleted(projectId, project) {
  const title = "壓力測試佇列已完成";
  const body = project
    ? `專案 #${projectId}：${project.name} 已關閉，報告已產生。`
    : `專案 #${projectId} 已關閉，報告已產生。`;

  if ("Notification" in window && Notification.permission === "granted") {
    try {
      const n = new Notification(title, { body, tag: `project-${projectId}-closed` });
      n.onclick = () => {
        window.focus();
        n.close();
      };
    } catch (e) {
      // 部分瀏覽器/環境（例如非 https 或非 localhost 來源）可能不允許建立通知，
      // 不影響其他功能，畫面上的狀態文字/log 仍然看得到完成訊息。
    }
  }

  // 自動切換到「管理 → 專案管理」頁面，並把剛完成的這個專案捲動進畫面、短暫醒目提示，
  // 讓回來查看的工程師不用自己再去找是哪一列。
  const projectMgmtBtn = document.querySelector('#tabs button[data-tab="project-mgmt"]');
  if (projectMgmtBtn) projectMgmtBtn.click();
  setTimeout(() => highlightCompletedProjectRow(projectId), 400);
}

function highlightCompletedProjectRow(projectId) {
  const rows = document.querySelectorAll("#history-table tbody tr");
  for (const row of rows) {
    const firstCell = row.querySelector("td");
    if (firstCell && firstCell.textContent.trim() === String(projectId)) {
      row.scrollIntoView({ behavior: "smooth", block: "center" });
      row.classList.add("row-just-completed");
      setTimeout(() => row.classList.remove("row-just-completed"), 5000);
      break;
    }
  }
}

function renderMonitorCard(monitorType, metrics) {
  const monitorLive = document.getElementById("monitor-live");
  const level = metrics.level || "ok";
  let card = document.getElementById(`mon-${monitorType}`);
  if (!card) {
    card = el(`<div class="monitor-card" id="mon-${monitorType}">
      <div class="mon-header"><h4><span class="mon-dot level-ok"></span><span class="mon-name">${monitorType}</span></h4></div>
      <div class="heartbeat-strip"></div>
      <svg class="mon-sparkline" viewBox="0 0 100 36" preserveAspectRatio="none"></svg>
      <div class="mon-body"></div>
      <div class="mon-reason"></div>
    </div>`);
    monitorLive.appendChild(card);
  }

  card.className = `monitor-card level-${level}`;
  card.querySelector(".mon-dot").className = `mon-dot level-${level}`;
  card.querySelector(".mon-body").innerHTML = Object.entries(metrics)
    .filter(([k]) => !["ts", "level", "level_reason"].includes(k))
    .map(([k, v]) => `${k}: ${v}`).join("<br>");
  card.querySelector(".mon-reason").textContent = level !== "ok" ? (metrics.level_reason || "") : "";

  // 心跳條：最近 30 筆的異常狀態（紅/黃/綠色塊）
  const hist = state.monitorHistory[monitorType] || (state.monitorHistory[monitorType] = { values: [], levels: [] });
  hist.levels.push(level);
  if (hist.levels.length > 30) hist.levels.shift();
  const strip = card.querySelector(".heartbeat-strip");
  strip.innerHTML = hist.levels.map((lv) => `<div class="heartbeat-cell level-${lv}" title="${LEVEL_LABEL[lv] || lv}"></div>`).join("");

  // sparkline：主要數值欄位的趨勢線
  const primaryKey = MONITOR_PRIMARY_METRIC[monitorType];
  let val = primaryKey ? metrics[primaryKey] : null;
  if (val === null || val === undefined || typeof val !== "number") val = hist.values.length ? hist.values[hist.values.length - 1] : 0;
  hist.values.push(val);
  if (hist.values.length > 40) hist.values.shift();
  const svg = card.querySelector(".mon-sparkline");
  const vals = hist.values;
  const max = Math.max(...vals, 1);
  const min = Math.min(...vals, 0);
  const range = max - min || 1;
  const points = vals.map((v, i) => {
    const x = (i / Math.max(1, vals.length - 1)) * 100;
    const y = 34 - ((v - min) / range) * 32;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  const strokeColor = level === "critical" ? "#dc2626" : level === "warn" ? "#d97706" : "#3b82f6";
  svg.innerHTML = `<polyline points="${points}" fill="none" stroke="${strokeColor}" stroke-width="2"></polyline>`;
}

function updateRunRowStatus(runId, status, attempt) {
  const row = document.getElementById(`run-row-${runId}`);
  if (!row) return;
  // run-live-table 欄位順序：0=#, 1=測項, 2=類型, 3=Port, 4=狀態, 5=嘗試次數, 6=📶過程狀態, 7=🔁恢復能力, 8=🧮判定
  const statusCell = row.children[4];
  statusCell.textContent = status;
  statusCell.className = `status-${status}`;
  if (attempt) row.children[5].textContent = attempt;
}

function updateRunRowVerdict(runId, verdict, stabilityVerdict, recoveryVerdict) {
  const row = document.getElementById(`run-row-${runId}`);
  if (!row) return;
  const stabilityCell = row.children[6];
  const recoveryCell = row.children[7];
  const verdictCell = row.children[8];
  if (stabilityCell) stabilityCell.innerHTML = axisVerdictCellHtml(STABILITY_ICON, STABILITY_LABEL, stabilityVerdict);
  if (recoveryCell) recoveryCell.innerHTML = axisVerdictCellHtml(RECOVERY_ICON, RECOVERY_LABEL, recoveryVerdict);
  if (verdictCell) {
    verdictCell.textContent = verdict && verdict !== "unknown" ? `${VERDICT_ICON[verdict] || ""} ${VERDICT_LABEL[verdict] || verdict}` : "-";
  }
}

function requireProject() {
  if (!state.projectId) {
    alert("請先建立/選擇一個專案");
    return false;
  }
  return true;
}

// ---------- 執行頁「攻擊進行中」ASCII 動畫 ----------
// 用來當測項執行中的視覺化效果，搬進平台當「5. 執行」頁籤
// run-status 區塊下方的常駐動畫；有測項在跑（state.currentRun 有值）才播放，
// 閒置時面板整體淡化（見 style.css .attack-anim-panel.idle）且畫面維持在最後一格
// （不會歸零重播），避免使用者以為畫面卡住。
// 動畫本身只是裝飾用途，不代表任何真實攻擊/監控數據。
(function initAttackAnim() {
  // 箭矢連續不斷地從攻擊端往受測目標方向飛（多支箭同時在飛，模擬連發效果），
  // 飛到畫面右側邊界（受測目標所在位置）就消失，不做撞擊/彈回的動作。
  // 文字標籤與圖案的對齊採用 ch 單位絕對定位，直接對齊圖案的實際字元欄位，
  // 不受面板實際渲染寬度影響。
  const WIDTH = 62;
  const ARCHER_COL = 4;
  const ARROW_ROW = 2;
  const FIRE_START_COL = ARCHER_COL + 7; // 箭矢從弓手前方開始飛
  const TARGET_COL = WIDTH - 4; // 受測目標所在欄位（箭矢飛到這附近就視為抵達，消失）
  const ARROW_STEP = 3; // 每個 tick 箭矢往前飛幾格
  const TRAIL_LEN = 4; // 箭矢拖尾長度
  const SPAWN_EVERY_TICKS = 4; // 每幾個 tick 補發一支新箭（越小＝連發越密集）

  const ARCHER_ART = [
    "   |\\  ",
    " o=|  >",
    "   |/  ",
  ];
  const ARCHER_WIDTH = 7;

  const el = document.getElementById("attack-anim-scene");
  const panel = document.getElementById("attack-anim-panel");
  const labelArcher = document.getElementById("attack-anim-label-archer");
  const labelTarget = document.getElementById("attack-anim-label-target");
  if (!el || !panel) return; // 頁面上沒有這個區塊（例如未來版型調整）就靜默跳過

  // label 對齊：直接算出圖案的實際字元欄位中心點，設成 left: {col}ch，
  // 不管面板實際渲染寬度是多少都會精確對齊在圖案正下方。
  if (labelArcher) labelArcher.style.left = `${(ARCHER_COL - 2) + ARCHER_WIDTH / 2}ch`;
  if (labelTarget) labelTarget.style.left = `${TARGET_COL}ch`;

  let arrows = []; // 目前畫面上飛行中的箭矢，每支是 { pos }（箭頭目前所在欄位）
  let tickCount = 0;

  function blankRow() {
    return new Array(WIDTH).fill(" ").map((c) => ({ ch: c, cls: null }));
  }

  function placeArt(rows, art, col, rowOffset, spanClass) {
    for (let i = 0; i < art.length; i++) {
      const line = art[i];
      for (let j = 0; j < line.length; j++) {
        const c = line[j];
        if (c !== " " && col + j < WIDTH) {
          rows[rowOffset + i][col + j] = { ch: c, cls: spanClass };
        }
      }
    }
  }

  function render() {
    const rows = [];
    for (let r = 0; r < 6; r++) rows.push(blankRow());

    placeArt(rows, ARCHER_ART, ARCHER_COL - 2, 1, "aa-blue");

    for (const arrow of arrows) {
      for (let t = 1; t <= TRAIL_LEN; t++) {
        const tc = arrow.pos - t;
        if (tc > ARCHER_COL + 6 && tc < WIDTH && rows[ARROW_ROW][tc].ch === " ") {
          rows[ARROW_ROW][tc] = { ch: "-", cls: "aa-green" };
        }
      }
      if (arrow.pos >= ARCHER_COL + 6 && arrow.pos < WIDTH) {
        rows[ARROW_ROW][arrow.pos] = { ch: ">", cls: "aa-green" };
      }
    }

    let html = "";
    for (const row of rows) {
      for (const cell of row) {
        html += cell.cls ? `<span class="${cell.cls}">${cell.ch}</span>` : cell.ch;
      }
      html += "\n";
    }
    el.innerHTML = html;
  }

  function tick() {
    // 沒有測項在執行時暫停在最後一格畫面，不歸零、不繼續跑，面板由 CSS 淡化表示待機
    if (!state.currentRun) {
      panel.classList.add("idle");
      return;
    }
    panel.classList.remove("idle");

    tickCount++;
    if (tickCount % SPAWN_EVERY_TICKS === 0) {
      arrows.push({ pos: FIRE_START_COL });
    }
    arrows.forEach((a) => { a.pos += ARROW_STEP; });
    // 飛出畫面右側（含拖尾清空所需的緩衝距離）就移除，不做撞擊/彈回
    arrows = arrows.filter((a) => a.pos < WIDTH + TRAIL_LEN);

    render();
  }

  render();
  panel.classList.add("idle");
  setInterval(tick, 70);
})();

// ---------- 初始化 ----------

loadTargets();
loadTestItemsIndex();
