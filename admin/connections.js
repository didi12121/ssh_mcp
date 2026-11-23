const navKeys = document.querySelector("#nav-keys");
const navConnections = document.querySelector("#nav-connections");
const connectionSection = document.querySelector("#connections");
const connectionForm = document.querySelector("#connection-form");
const connectionList = document.querySelector("#connection-list");
const connectionCredential = document.querySelector("#connection-credential");
const connectionRefresh = document.querySelector("#connections-refresh");
const connectionPrev = document.querySelector("#connections-prev");
const connectionNext = document.querySelector("#connections-next");
let editProfileId = "";
let editedProfile;
let connectionPage = 1;
let connectionLoad = 0;

function resetConnectionSection() {
  ++connectionLoad;
  document.querySelector("#sections").hidden = true;
  connectionSection.hidden = true;
  connectionList.replaceChildren();
  connectionPage = 1;
  resetConnectionForm();
}

function openManagementSection(section) {
  for (const [id, panel, button] of [
    ["keys", workspace, navKeys], ["connections", connectionSection, navConnections],
    ["tokens", document.querySelector("#tokens"), document.querySelector("#nav-tokens")],
  ]) {
    panel.hidden = section !== id;
    button.setAttribute("aria-pressed", String(section === id));
  }
  message("");
  if (section === "connections") void action(connectionRefresh, loadConnections);
  if (section === "tokens") loadIdentitySection();
}

function connectionRequest(path = "", options, page = connectionPage) {
  const query = new URLSearchParams({ page: String(page) });
  return request(`${path}?${query}`, options, "connections");
}

function resetConnectionForm() {
  editProfileId = "";
  editedProfile = undefined;
  connectionForm.reset();
  document.querySelector("#connection-form-title").textContent = "新增连接";
  document.querySelector("#connections-cancel-edit").hidden = true;
}

function editConnection(profile) {
  resetConnectionForm();
  editProfileId = profile.profile_id;
  editedProfile = profile;
  document.querySelector("#connection-form-title").textContent = "编辑连接";
  document.querySelector("#connections-cancel-edit").hidden = false;
  const fields = connectionForm.elements;
  for (const name of ["name", "host", "username", "port", "description"]) {
    fields.namedItem(name).value = profile[name] ?? "";
  }
  fields.namedItem("tags").value = profile.tags.join(", ");
  fields.namedItem("enabled").checked = profile.enabled;
  connectionCredential.value = profile.credential_ref ?? "";
  fields.namedItem("name").focus();
}

const connectionErrors = {
  HOST_KEY_UNVERIFIED: "目标主机指纹未登记或已变化。请核对主机公钥后更新终端服务的 known_hosts。",
  SSH_AUTH_FAILED: "SSH 登录被拒绝。请核对用户，并确认对应公钥已安装到目标账号。",
  SSH_UNAVAILABLE: "无法连接 SSH，或终端服务无法读取目标主机的 known_hosts。",
  SSH_TIMEOUT: "SSH 连接超时，请检查地址、端口和网络。",
  PROFILE_IN_USE: "此连接仍有终端引用，请关闭相关终端后再删除。",
  EXECUTION_ACTIVE: "仍有分离任务运行，结束任务后再清理终端。",
  CREDENTIAL_UNAVAILABLE: "所选凭据不可用，请检查密钥库或服务端凭据配置。",
};

async function connectionAction(path, options) {
  try {
    return await connectionRequest(path, options);
  } catch (error) {
    throw new Error(connectionErrors[error.code] ?? error.message);
  }
}

function connectionRow(profile) {
  const row = document.createElement("li");
  const details = [`${profile.username}@${profile.host} · 端口 ${profile.port}`, profile.enabled ? "已启用" : "已禁用"];
  if (profile.credential_ref) details.push(profile.credential_ref);
  if (profile.tags.length) details.push(profile.tags.join("、"));
  row.append(element("div", profile.name, "key-name"), element("div", details.join(" · "), "key-info"));
  if (profile.description) row.append(element("div", profile.description, "key-info"));
  const controls = element("div", "", "key-actions");
  const test = element("button", "测试连接", "quiet");
  test.addEventListener("click", () => action(test, async () => {
    const result = await connectionAction(`/${profile.profile_id}/test`, { method: "POST" });
    message(`${profile.name} 已通过 SSH 验证，延迟 ${result.latency_ms} ms。${result.tmux_available ? "目标已安装 tmux。" : "目标未安装 tmux。"}`);
  }));
  const edit = element("button", "编辑", "quiet");
  edit.addEventListener("click", () => editConnection(profile));
  const terminals = element("button", "管理终端", "quiet");
  const terminalList = element("div", "", "key-info");
  const loadTerminals = async () => {
    const { sessions } = await connectionAction(`/${profile.profile_id}/sessions`);
    terminalList.replaceChildren();
    if (!sessions.length) terminalList.append(element("p", "没有待清理的终端。"));
    for (const session of sessions) {
      const detail = element("div", "", "key-actions");
      detail.append(element("span", `${session.name} · ${session.workspace_id} · ${session.status}`));
      const close = element("button", "关闭终端", "quiet danger");
      close.addEventListener("click", () => {
        if (!window.confirm(`关闭 ${session.name} 并清理远端终端？`)) return;
        void action(close, async () => {
          await connectionAction(`/${profile.profile_id}/sessions/${session.session_id}/close`, { method: "POST" });
          await loadTerminals();
        });
      });
      detail.append(close);
      terminalList.append(detail);
    }
  };
  terminals.addEventListener("click", () => action(terminals, loadTerminals));
  const remove = element("button", "删除", "quiet danger");
  remove.addEventListener("click", () => {
    if (!window.confirm(`删除连接 ${profile.name}？`)) return;
    void action(remove, async () => {
      await connectionAction(`/${profile.profile_id}`, { method: "DELETE" });
      if (connectionList.children.length === 1) connectionPage = Math.max(1, connectionPage - 1);
      if (editProfileId === profile.profile_id) resetConnectionForm();
      await loadConnections();
      message("连接已删除。");
    });
  });
  controls.append(test, edit, terminals, remove);
  row.append(controls, terminalList);
  return row;
}

async function loadConnections() {
  const load = ++connectionLoad;
  const selectedCredential = connectionCredential.value;
  const data = await connectionRequest();
  if (load !== connectionLoad || connectionSection.hidden) return;
  const options = data.credentials.map(({ ref, auth_type }) => {
    const label = ref.startsWith("managed_") ? ref.slice("managed_".length) : ref;
    const option = new Option(label, ref);
    option.dataset.auth = auth_type;
    return option;
  });
  if (data.ssh_agent) {
    const agent = new Option("SSH Agent", "");
    agent.dataset.auth = "agent";
    options.push(agent);
  }
  connectionCredential.replaceChildren(...options);
  connectionCredential.required = !data.ssh_agent;
  if (options.some((option) => option.value === selectedCredential)) connectionCredential.value = selectedCredential;
  document.querySelector("#connection-no-credentials").hidden = options.length > 0;
  document.querySelector("#connections-save").disabled = options.length === 0;
  connectionForm.hidden = false;
  connectionList.replaceChildren(...data.profiles.map(connectionRow));
  document.querySelector("#connections-empty").hidden = data.profiles.length > 0;
  document.querySelector("#connection-pages").hidden = data.total <= 25;
  connectionPrev.disabled = data.page <= 1;
  connectionNext.disabled = data.page * 25 >= data.total;
}

navKeys.addEventListener("click", () => openManagementSection("keys"));
navConnections.addEventListener("click", () => openManagementSection("connections"));
connectionRefresh.addEventListener("click", () => action(connectionRefresh, loadConnections));
for (const [button, delta] of [[connectionPrev, -1], [connectionNext, 1]]) {
  button.addEventListener("click", () => {
    connectionPage += delta;
    void action(connectionRefresh, loadConnections);
  });
}
document.querySelector("#connections-cancel-edit").addEventListener("click", resetConnectionForm);
connectionForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const option = connectionCredential.selectedOptions[0];
  if (!option) return;
  const fields = Object.fromEntries(new FormData(connectionForm));
  const payload = {
    ...fields, port: Number(fields.port),
    tags: fields.tags.split(/[,，]/u).map((tag) => tag.trim()).filter(Boolean),
    auth_type: option.dataset.auth, credential_ref: option.value || null,
    enabled: connectionForm.elements.namedItem("enabled").checked,
  };
  const editing = editProfileId;
  if (editedProfile && ["host", "port", "username", "auth_type", "credential_ref"].some(
    (field) => editedProfile[field] !== payload[field],
  ) && !window.confirm("修改目标或凭据会撤销这条连接的 Token 授权。旧终端将保留供管理员清理。继续？")) return;
  void action(event.submitter, async () => {
    const result = await connectionAction(editing ? `/${editing}` : "", {
      method: editing ? "PATCH" : "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    resetConnectionForm();
    await loadConnections();
    message(result.grants_invalidated ? "连接已更新。请重新授予需要使用新目标的 Token。" : "连接已保存。");
  });
});
