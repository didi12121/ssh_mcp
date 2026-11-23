const tokenList = document.querySelector("#token-list");
const tokenRefresh = document.querySelector("#tokens-refresh");
const tokenStatusFilter = document.querySelector("#token-filter-status");
const tokenDialog = document.querySelector("#token-dialog");
const tokenForm = document.querySelector("#token-form");
const tokenSecret = document.querySelector("#token-secret");
const tokenDialogStatus = document.querySelector("#token-dialog-status");
const tokenExpiry = document.querySelector("#token-expiry");
const tokenExpiryDate = document.querySelector("#token-custom-expiry");
let tokenPage = 1;
let tokenLoad = 0;
let profileCatalog = [];
let issueRequestId;
let dialogGeneration = 0;
let tokenMode = "create";
let selectedToken;

const formField = (form, name) => form.elements.namedItem(name);
const jsonBody = (method, body, headers) => ({
  method, headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body),
});
const displayTime = (value) => value ? new Date(value).toLocaleString("zh-CN") : "—";
const splitWorkspaces = (value) => value.split(/[,，\n]/u).map((item) => item.trim()).filter(Boolean);

const tokenErrors = {
  TOKEN_INACTIVE: "只有有效的 Token 可以进行此操作。",
  TOKEN_ALREADY_ISSUED: "此操作已签发 Token。请刷新列表，确认结果后再操作。",
  INVALID_EXPIRY: "到期时间必须晚于当前时间。",
  INVALID_PROFILE_GRANT: "请检查所选 SSH 连接是否存在并启用。",
  INVALID_INPUT: "请检查权限、工作区、到期时间或命令 JSON。",
  RATE_LIMITED: "Token 操作过于频繁，请稍后再试。",
};

async function tokenRequest(path = "", options) {
  try {
    return await request(path, options, "tokens");
  } catch (error) {
    throw new Error(tokenErrors[error.code] ?? error.message);
  }
}

function tokenButton(text, handler, className = "quiet") {
  const button = element("button", text, className);
  button.type = "button";
  button.addEventListener("click", () => handler(button));
  return button;
}

function updateExpiryField() {
  const custom = tokenMode !== "edit" && tokenExpiry.value === "custom";
  tokenExpiryDate.hidden = !custom;
  tokenExpiryDate.required = custom;
  document.querySelector("#token-custom-label").hidden = !custom;
}

function clearTokenDialog() {
  ++dialogGeneration;
  issueRequestId = undefined;
  selectedToken = undefined;
  tokenSecret.value = "";
  tokenForm.reset();
  updateExpiryField();
  document.querySelector("#token-profile-options").replaceChildren();
  document.querySelector("#token-reveal").hidden = true;
  message("", false, tokenDialogStatus);
}

function showTokenDialog(mode, item) {
  clearTokenDialog();
  tokenMode = mode;
  selectedToken = item;
  const issuing = mode === "create" || mode === "attach";
  const editing = mode === "edit";
  const rotating = mode === "rotate";
  const title = { create: "创建 MCP Token", attach: "创建附加 Token", edit: "编辑 Token 权限", rotate: "轮换 MCP Token" };
  document.querySelector("#token-dialog-title").textContent = title[mode];
  document.querySelector("#token-submit").textContent = editing ? "保存权限" : rotating ? "轮换 Token" : "创建 Token";
  tokenForm.hidden = false;
  const name = formField(tokenForm, "name");
  name.hidden = name.disabled = !issuing;
  document.querySelector("#token-name-label").hidden = !issuing;
  document.querySelector("#token-permissions").hidden = rotating;
  document.querySelector("#token-command-fields").hidden = rotating;
  document.querySelector("#token-expiry-fields").hidden = editing;
  document.querySelector("#token-default-expiry").textContent = rotating
    ? "沿用原到期时间" : `服务器默认（${defaultTokenDays} 天）`;
  if (item) message(`${item.name} · 到期 ${item.expires_at ? displayTime(item.expires_at) : "永不过期"}`, false, tokenDialogStatus);
  if (!rotating) {
    const current = new Set(editing ? item.allowed_profile_ids : []);
    const names = new Map();
    for (const profile of profileCatalog) names.set(profile.name, (names.get(profile.name) ?? 0) + 1);
    const options = profileCatalog.map((profile) => {
      const label = element("label", "");
      const box = document.createElement("input");
      box.type = "checkbox";
      box.name = "profiles";
      box.value = profile.profile_id;
      box.checked = current.has(profile.profile_id);
      box.disabled = !profile.enabled && !box.checked;
      const name = names.get(profile.name) > 1 ? `${profile.name} · ${profile.profile_id.slice(0, 8)}` : profile.name;
      label.append(box, element("span", profile.enabled ? name : name + "（已禁用）"));
      return label;
    });
    if (!options.length) options.push(element("p", "请先在 SSH 连接中添加服务器。未选择服务器的 Token 没有访问权限。", "muted"));
    document.querySelector("#token-profile-options").replaceChildren(...options);
    if (editing) {
      formField(tokenForm, "shell").checked = item.shell;
      formField(tokenForm, "custom_commands").checked = item.custom_commands;
      formField(tokenForm, "workspaces").value = item.workspaces.join(", ");
      formField(tokenForm, "commands").value = JSON.stringify(item.commands, null, 2);
    }
  }
  issueRequestId = crypto.randomUUID();
  updateExpiryField();
  tokenDialog.showModal();
}

function revealToken(value, generation, expiresAt) {
  if (!tokenDialog.open || generation !== dialogGeneration) return;
  tokenForm.hidden = true;
  tokenSecret.value = value;
  document.querySelector("#token-reveal").hidden = false;
  message(`新 Token 已签发，到期 ${expiresAt ? displayTime(expiresAt) : "永不过期"}。`, false, tokenDialogStatus);
  document.querySelector("#token-copy").focus();
}

function renderToken(item) {
  const row = document.createElement("li");
  const label = { ACTIVE: "有效", REVOKED: "已撤销", EXPIRED: "已过期" }[item.status];
  row.append(element("div", `${item.name} · ${label}${item.owner_enabled ? "" : " · 内部身份已禁用"}`, "key-name"));
  row.append(element("div", `授权服务器 ${item.profiles.map((profile) => profile.name + (profile.enabled ? "" : "（已禁用）")).join("、") || "无"}`,
    "key-info"));
  row.append(element("div", `Shell ${item.shell ? "允许" : "禁止"} · 独立命令 ${item.custom_commands ? "允许" : "禁止"}`, "key-info"));
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
      tokenButton("编辑权限", () => showTokenDialog("edit", item)),
      tokenButton("轮换", () => showTokenDialog("rotate", item)),
      tokenButton("附加 Token", () => showTokenDialog("attach", item)),
      tokenButton("撤销", (button) => {
        if (!window.confirm("撤销后，此 Token 将立即无法访问 MCP，操作不可撤销。")) return;
        void action(button, async () => {
          await tokenRequest(`/${item.token_id}/revoke`, jsonBody("POST", {}));
          await loadTokens();
          message("Token 已撤销。");
        });
      }, "quiet danger"),
    );
  }
  buttons.append(tokenButton("删除", (button) => {
    if (!window.confirm("删除此 Token？它将无法再认证，并从列表移除。")) return;
    void action(button, async () => {
      await tokenRequest(`/${item.token_id}`, { method: "DELETE" });
      if (tokenList.children.length === 1) tokenPage = Math.max(1, tokenPage - 1);
      await loadTokens();
      message("Token 已删除。");
    });
  }, "quiet danger"));
  row.append(buttons);
  return row;
}

let defaultTokenDays = 90;

async function loadTokens() {
  const load = ++tokenLoad;
  const params = new URLSearchParams({ page: tokenPage, catalog: "1" });
  if (tokenStatusFilter.value) params.set("status", tokenStatusFilter.value);
  const data = await tokenRequest(`?${params}`);
  if (load !== tokenLoad || document.querySelector("#tokens").hidden) return;
  profileCatalog = data.catalog;
  defaultTokenDays = data.default_days;
  tokenList.replaceChildren(...data.tokens.map(renderToken));
  document.querySelector("#tokens-empty").hidden = data.tokens.length > 0;
  document.querySelector("#token-pages").hidden = data.total <= data.limit;
  document.querySelector("#token-prev").disabled = data.page <= 1;
  document.querySelector("#token-next").disabled = data.page * data.limit >= data.total;
}

function resetIdentitySections() {
  document.querySelector("#tokens").hidden = true;
  tokenPage = 1;
  profileCatalog = [];
  ++tokenLoad;
  tokenStatusFilter.value = "";
  tokenList.replaceChildren();
  clearTokenDialog();
  tokenDialog.close();
}

function loadIdentitySection() {
  void action(tokenRefresh, loadTokens);
}

document.querySelector("#nav-tokens").addEventListener("click", () => openManagementSection("tokens"));
tokenRefresh.addEventListener("click", loadIdentitySection);
tokenStatusFilter.addEventListener("change", () => {
  tokenPage = 1;
  loadIdentitySection();
});
for (const [name, step] of [["prev", -1], ["next", 1]]) {
  document.querySelector(`#token-${name}`).addEventListener("click", () => {
    tokenPage += step;
    loadIdentitySection();
  });
}
document.querySelector("#token-create").addEventListener("click", () => showTokenDialog("create"));
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
  const mode = tokenMode;
  const item = selectedToken;
  const generation = dialogGeneration;
  const body = {};
  if (mode !== "rotate") {
    try {
      body.commands = JSON.parse(formField(tokenForm, "commands").value || "{}");
    } catch {
      message("预定义命令需使用有效的 JSON。", true, tokenDialogStatus);
      return;
    }
    body.allowed_profile_ids = new FormData(tokenForm).getAll("profiles");
    body.workspaces = splitWorkspaces(formField(tokenForm, "workspaces").value);
    body.shell = formField(tokenForm, "shell").checked;
    body.custom_commands = formField(tokenForm, "custom_commands").checked;
    if (mode !== "edit") body.name = formField(tokenForm, "name").value.trim();
    if (mode === "attach") body.attach_to_token_id = item.token_id;
  }
  if (mode !== "edit") {
    if (tokenExpiry.value === "never") body.expires_at = null;
    else if (tokenExpiry.value !== "default") {
      const date = tokenExpiry.value === "custom" ? new Date(tokenExpiryDate.value)
        : new Date(Date.now() + Number(tokenExpiry.value) * 86400000);
      if (!Number.isFinite(date.valueOf()) || date.valueOf() <= Date.now()) {
        message("到期时间必须晚于当前时间。", true, tokenDialogStatus);
        return;
      }
      body.expires_at = date.toISOString();
    }
  }
  if (mode === "rotate" && !window.confirm(`轮换 ${item.name}？旧 Token 将立即失效，现有终端和任务将保留。`)) return;
  const resource = mode === "rotate" ? `/${item.token_id}/rotate` : mode === "edit" ? `/${item.token_id}/permissions` : "";
  void action(event.submitter, async () => {
    const result = await tokenRequest(resource,
      jsonBody(mode === "edit" ? "PATCH" : "POST", body, { "Idempotency-Key": issueRequestId }));
    if (mode !== "edit") revealToken(result.token, generation, result.expires_at);
    await loadTokens();
    if (mode === "edit" && generation === dialogGeneration) {
      clearTokenDialog();
      tokenDialog.close();
      message("Token 权限已更新。");
    }
  }, tokenDialogStatus);
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
