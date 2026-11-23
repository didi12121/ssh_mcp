const agentForm = document.querySelector("#agent-form");
const agentSearch = document.querySelector("#agent-search");
const agentList = document.querySelector("#agent-list");
const agentRefresh = document.querySelector("#agents-refresh");
const tokenList = document.querySelector("#token-list");
const tokenRefresh = document.querySelector("#tokens-refresh");
const tokenOwnerFilter = document.querySelector("#token-filter-owner");
const tokenStatusFilter = document.querySelector("#token-filter-status");
const tokenDialog = document.querySelector("#token-dialog");
const tokenForm = document.querySelector("#token-form");
const tokenSecret = document.querySelector("#token-secret");
const tokenDialogStatus = document.querySelector("#token-dialog-status");
const tokenExpiry = document.querySelector("#token-expiry");
const tokenExpiryDate = document.querySelector("#token-custom-expiry");
const identityPages = { agents: 1, tokens: 1 };
const identityLoads = { agents: 0, tokens: 0 };
let editingAgent;
let issueRequestId;
let dialogGeneration = 0;

const formField = (form, name) => form.elements.namedItem(name);
const splitItems = (value) => value.split(/[,，\n]/u).map((item) => item.trim()).filter(Boolean);
const selectedItems = (select) => Array.from(select.selectedOptions, (option) => option.value);
const distinct = (values) => Array.from(new Set(values)).sort();
const jsonBody = (method, body, headers) => ({
  method, headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body),
});

function displayTime(value) {
  return value ? new Date(value).toLocaleString("zh-CN") : "—";
}

const identityErrors = {
  AGENT_EXISTS: "此 Agent ID 已存在。",
  AGENT_NOT_FOUND: "找不到选中的 Agent。",
  TOKEN_INACTIVE: "只有有效的 Token 可以轮换。",
  TOKEN_ALREADY_ISSUED: "此操作已签发 Token。请刷新列表，确认结果后再操作。",
  INVALID_EXPIRY: "到期时间必须晚于当前时间。",
  INVALID_INPUT: "请检查 ID、权限字段或命令 JSON。",
  RATE_LIMITED: "Token 操作过于频繁，请稍后再试。",
};

async function identityRequest(resource, path = "", options) {
  try {
    return await request(path, options, resource);
  } catch (error) {
    throw new Error(identityErrors[error.code] ?? error.message);
  }
}

function control(text, handler, className = "quiet") {
  const button = element("button", text, className);
  button.type = "button";
  button.addEventListener("click", () => handler(button));
  return button;
}

function setOptions(select, options, values) {
  select.replaceChildren(...options.map(({ label, value }) => new Option(label, value)));
  for (const value of values) {
    if (!Array.from(select.options).some((option) => option.value === value)) select.add(new Option(value, value));
  }
  for (const option of select.options) option.selected = values.includes(option.value);
}

function resetAgentForm() {
  editingAgent = undefined;
  formField(agentForm, "owner_id").disabled = false;
  agentForm.reset();
  document.querySelector("#agent-form-title").textContent = "新增 Agent";
  document.querySelector("#agent-cancel").hidden = true;
}

function editAgent(agent) {
  editingAgent = agent;
  for (const key of ["owner_id", "name", "description"]) formField(agentForm, key).value = agent[key] ?? "";
  formField(agentForm, "owner_id").disabled = true;
  for (const key of ["shell", "custom_commands", "ssh_agent"]) formField(agentForm, key).checked = agent[key];
  const targetOptions = Array.from(formField(agentForm, "targets").options, (option) => option.value);
  for (const option of formField(agentForm, "targets").options) option.selected = agent.targets.includes(option.value);
  formField(agentForm, "extra_targets").value = agent.targets.filter((target) => !targetOptions.includes(target)).join("\n");
  const credentials = formField(agentForm, "credentials");
  setOptions(credentials, Array.from(credentials.options, (option) => ({ label: option.text, value: option.value })), agent.credentials);
  formField(agentForm, "workspaces").value = agent.workspaces.join(", ");
  formField(agentForm, "commands").value = JSON.stringify(agent.commands, null, 2);
  document.querySelector("#agent-form-title").textContent = "编辑 Agent";
  document.querySelector("#agent-cancel").hidden = false;
  formField(agentForm, "name").focus();
}

function renderAgent(agent) {
  const row = document.createElement("li");
  row.append(
    element("div", `${agent.name} · ${agent.owner_id}`, "key-name"),
    element("div", `${agent.enabled ? "已启用" : "已禁用"} · Shell ${agent.shell ? "允许" : "禁止"} · ${agent.token_count} 个 Token`, "key-info"),
    element("div", `最后认证 ${displayTime(agent.last_used_at)}`, "key-info"),
  );
  if (agent.description) row.append(element("div", agent.description, "key-info"));
  const buttons = element("div", "", "key-actions");
  buttons.append(
    control("编辑权限", () => editAgent(agent)),
    control("SSH 连接", () => showAgentConnections(agent.owner_id)),
    control("查看 Token", () => {
      tokenOwnerFilter.value = agent.owner_id;
      tokenStatusFilter.value = "";
      identityPages.tokens = 1;
      openManagementSection("tokens");
    }),
    control(agent.enabled ? "禁用" : "启用", (button) => {
      if (agent.enabled && !window.confirm("禁用后此 Agent 的所有 Token 将无法继续访问 MCP。已经运行的远端任务不会自动结束。")) return;
      void action(button, async () => {
        await identityRequest("agents", `/${agent.owner_id}`, jsonBody("PATCH", { enabled: !agent.enabled }));
        await loadAgents();
        message(agent.enabled ? "Agent 已禁用。" : "Agent 已启用。");
      });
    }, agent.enabled ? "quiet danger" : "quiet"),
  );
  row.append(buttons);
  return row;
}

function pages(prefix, data) {
  document.querySelector(`#${prefix}-pages`).hidden = data.total <= data.limit;
  document.querySelector(`#${prefix}-prev`).disabled = data.page <= 1;
  document.querySelector(`#${prefix}-next`).disabled = data.page * data.limit >= data.total;
}

async function loadAgents() {
  const load = ++identityLoads.agents;
  const params = new URLSearchParams({ page: identityPages.agents, search: agentSearch.value, catalog: "1" });
  const data = await identityRequest("agents", `?${params}`);
  if (load !== identityLoads.agents || document.querySelector("#agents").hidden) return;
  const targets = formField(agentForm, "targets");
  const credentials = formField(agentForm, "credentials");
  setOptions(targets, data.targets.map((host) => ({ label: host, value: host })), selectedItems(targets));
  setOptions(credentials, data.credentials.map(({ ref, kind }) => ({ label: `${ref} · ${kind}`, value: ref })),
    selectedItems(credentials));
  agentList.replaceChildren(...data.agents.map(renderAgent));
  document.querySelector("#agents-empty").hidden = data.agents.length > 0;
  pages("agent", data);
}

agentForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const previous = editingAgent;
  const fields = agentForm.elements;
  void action(event.submitter, async () => {
    let commands;
    try {
      commands = JSON.parse(fields.commands.value || "{}");
    } catch {
      throw new Error("预定义命令需使用有效的 JSON。");
    }
    const data = {
      name: fields.name.value, description: fields.description.value.trim() || null,
      targets: distinct([...selectedItems(fields.targets), ...splitItems(fields.extra_targets.value)]),
      credentials: distinct(selectedItems(fields.credentials)), workspaces: distinct(splitItems(fields.workspaces.value)),
      shell: fields.shell.checked, custom_commands: fields.custom_commands.checked, ssh_agent: fields.ssh_agent.checked,
      commands,
    };
    if (previous) {
      const changes = Object.fromEntries(Object.entries(data).filter(([key, value]) => {
        const before = Array.isArray(previous[key]) ? distinct(previous[key]) : previous[key];
        return JSON.stringify(before) !== JSON.stringify(value);
      }));
      if (Object.keys(changes).length) await identityRequest("agents", `/${previous.owner_id}`, jsonBody("PATCH", changes));
    } else {
      await identityRequest("agents", "", jsonBody("POST", { owner_id: fields.owner_id.value, ...data }));
      identityPages.agents = 1;
    }
    resetAgentForm();
    await loadAgents();
    message("Agent 已保存。");
  });
});

function updateExpiryField() {
  const custom = tokenExpiry.value === "custom";
  tokenExpiryDate.hidden = !custom;
  tokenExpiryDate.required = custom;
  document.querySelector("#token-custom-label").hidden = !custom;
}

function clearTokenDialog() {
  ++dialogGeneration;
  issueRequestId = undefined;
  tokenSecret.value = "";
  tokenForm.reset();
  updateExpiryField();
  document.querySelector("#token-reveal").hidden = true;
  message("", false, tokenDialogStatus);
}

function showTokenDialog(creating) {
  clearTokenDialog();
  tokenForm.hidden = !creating;
  document.querySelector("#token-dialog-title").textContent = creating ? "创建 MCP Token" : "轮换 MCP Token";
  formField(tokenForm, "owner_id").value = tokenOwnerFilter.value;
  issueRequestId = crypto.randomUUID();
  tokenDialog.showModal();
  return dialogGeneration;
}

function revealToken(value, generation) {
  if (!tokenDialog.open || generation !== dialogGeneration) return;
  tokenForm.hidden = true;
  tokenSecret.value = value;
  document.querySelector("#token-reveal").hidden = false;
  message("新 Token 已签发。", false, tokenDialogStatus);
  document.querySelector("#token-copy").focus();
}

async function runTokenIssue(button, path, body, generation) {
  await action(button, async () => {
    const result = await identityRequest("tokens", path, jsonBody("POST", body, { "Idempotency-Key": issueRequestId }));
    revealToken(result.token, generation);
    await loadTokens();
  }, tokenDialogStatus);
}

function renderToken(item) {
  const row = document.createElement("li");
  const label = { ACTIVE: "有效", REVOKED: "已撤销", EXPIRED: "已过期" }[item.status];
  const ownerLabel = item.owner_name === item.owner_id ? item.owner_id : `${item.owner_name} (${item.owner_id})`;
  row.append(element("div", `${item.name} · ${ownerLabel} · ${label}${item.owner_enabled ? "" : " · Agent 已禁用"}`, "key-name"));
  const metadata = element("div", "", "key-info token-meta");
  for (const value of [
    `ID ${item.token_id}`, `创建 ${displayTime(item.created_at)}`,
    `到期 ${item.expires_at ? displayTime(item.expires_at) : "永不过期"}`,
    `最后认证 ${displayTime(item.last_used_at)}`,
  ]) metadata.append(element("span", value));
  row.append(metadata);
  const buttons = element("div", "", "key-actions");
  if (item.status === "ACTIVE") {
    buttons.append(
      control("轮换", (button) => {
        if (!window.confirm(`轮换 ${item.name}？新 Token 签发后旧 Token 将立即失效。Agent、服务器和正在执行的远端任务继续保留。`)) return;
        const generation = showTokenDialog(false);
        message("正在签发新 Token…", false, tokenDialogStatus);
        void runTokenIssue(button, `/${item.token_id}/rotate`, {}, generation);
      }),
      control("撤销", (button) => {
        if (!window.confirm("撤销后，此 Token 将立即无法访问 MCP，操作不可撤销。")) return;
        void action(button, async () => {
          await identityRequest("tokens", `/${item.token_id}/revoke`, jsonBody("POST", {}));
          await loadTokens();
          message("Token 已撤销。");
        });
      }, "quiet danger"),
    );
  }
  buttons.append(control("删除", (button) => {
    if (!window.confirm("删除此 Token？它将无法再认证，并从列表移除。")) return;
    void action(button, async () => {
      await identityRequest("tokens", `/${item.token_id}`, { method: "DELETE" });
      if (tokenList.children.length === 1) identityPages.tokens = Math.max(1, identityPages.tokens - 1);
      await loadTokens();
      message("Token 已删除。");
    });
  }, "quiet danger"));
  row.append(buttons);
  return row;
}

async function loadTokens() {
  const load = ++identityLoads.tokens;
  const params = new URLSearchParams({ page: identityPages.tokens });
  if (tokenOwnerFilter.value.trim()) params.set("owner", tokenOwnerFilter.value.trim());
  if (tokenStatusFilter.value) params.set("status", tokenStatusFilter.value);
  const data = await identityRequest("tokens", `?${params}`);
  if (load !== identityLoads.tokens || document.querySelector("#tokens").hidden) return;
  tokenList.replaceChildren(...data.tokens.map(renderToken));
  document.querySelector("#tokens-empty").hidden = data.tokens.length > 0;
  document.querySelector("#token-default-expiry").textContent = `服务器默认（${data.default_days} 天）`;
  pages("token", data);
}

async function loadTokenAgents() {
  const data = await identityRequest("agents", "?limit=100");
  document.querySelector("#token-agent-options").replaceChildren(
    ...data.agents.map((agent) => new Option(agent.name, agent.owner_id)),
  );
}

function resetIdentitySections() {
  for (const section of ["agents", "tokens"]) {
    document.querySelector(`#${section}`).hidden = true;
    identityPages[section] = 1;
    ++identityLoads[section];
  }
  agentSearch.value = tokenOwnerFilter.value = tokenStatusFilter.value = "";
  agentList.replaceChildren();
  tokenList.replaceChildren();
  resetAgentForm();
  clearTokenDialog();
  tokenDialog.close();
}

function loadIdentitySection(section) {
  if (section === "agents") void action(agentRefresh, loadAgents);
  else void action(tokenRefresh, async () => {
    await Promise.all([loadTokens(), loadTokenAgents()]);
  });
}

for (const [section, prefix, options, refresh, loader] of [
  ["agents", "agent", [agentSearch], agentRefresh, loadAgents],
  ["tokens", "token", [tokenOwnerFilter, tokenStatusFilter], tokenRefresh, loadTokens],
]) {
  document.querySelector(`#nav-${section}`).addEventListener("click", () => openManagementSection(section));
  refresh.addEventListener("click", () => action(refresh, loader));
  for (const option of options) {
    option.addEventListener("change", () => {
      identityPages[section] = 1;
      void action(refresh, loader);
    });
  }
  for (const [name, step] of [["prev", -1], ["next", 1]]) {
    document.querySelector(`#${prefix}-${name}`).addEventListener("click", () => {
      identityPages[section] += step;
      void action(refresh, loader);
    });
  }
}

document.querySelector("#agent-cancel").addEventListener("click", resetAgentForm);
document.querySelector("#token-create").addEventListener("click", () => showTokenDialog(true));
document.querySelector("#token-close").addEventListener("click", () => {
  clearTokenDialog();
  tokenDialog.close();
});
tokenDialog.addEventListener("cancel", clearTokenDialog);
tokenDialog.addEventListener("close", () => {
  if (!tokenDialog.open) clearTokenDialog();
});
tokenExpiry.addEventListener("change", updateExpiryField);
tokenForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const { owner_id, name, expiry } = Object.fromEntries(new FormData(tokenForm));
  const body = { owner_id: owner_id.trim(), name };
  if (expiry === "never") body.expires_at = null;
  else if (expiry !== "default") {
    const date = expiry === "custom" ? new Date(tokenExpiryDate.value) : new Date(Date.now() + Number(expiry) * 86400000);
    if (!Number.isFinite(date.valueOf()) || date.valueOf() <= Date.now()) {
      message("到期时间必须晚于当前时间。", true, tokenDialogStatus);
      return;
    }
    body.expires_at = date.toISOString();
  }
  void runTokenIssue(event.submitter, "", body, dialogGeneration);
});
document.querySelector("#token-copy").addEventListener("click", (event) => {
  void action(event.currentTarget, async () => {
    try {
      await navigator.clipboard.writeText(tokenSecret.value);
      message("Token 已复制。", false, tokenDialogStatus);
    } catch {
      tokenSecret.select();
      message("请按 Ctrl+C 或 ⌘C 复制所选 Token。", false, tokenDialogStatus);
    }
  }, tokenDialogStatus);
});
