const login = document.querySelector("#login");
const workspace = document.querySelector("#workspace");
const logout = document.querySelector("#logout");
const importForm = document.querySelector("#import");
const generateForm = document.querySelector("#generate");
const showGenerate = document.querySelector("#show-generate");
const showImport = document.querySelector("#show-import");
const installDialog = document.querySelector("#install-dialog");
const installForm = document.querySelector("#install-form");
const installTarget = document.querySelector("#install-target");
const installAddress = document.querySelector("#install-address");
const installUser = document.querySelector("#install-user");
const installPort = document.querySelector("#install-port");
const installResult = document.querySelector("#install-result");
const installCommand = document.querySelector("#install-command");
const installStatus = document.querySelector("#install-status");
const material = document.querySelector("#material");
const list = document.querySelector("#keys");
const status = document.querySelector("#status");
const tokenField = document.querySelector("#token");
let token = "";
let targets = [];
let selectedKeyId = "";

function message(text, error = false, region = status) {
  region.textContent = text;
  region.dataset.error = String(error);
}

function lock() {
  token = "";
  login.reset();
  importForm.reset();
  generateForm.reset();
  installDialog.close();
  list.replaceChildren();
  login.hidden = false;
  workspace.hidden = true;
  resetConnectionSection();
  resetIdentitySections();
  logout.hidden = true;
  tokenField.focus();
}

async function request(path, options, api = "keys") {
  const sentToken = token;
  const response = await fetch(`/api/${api}${path}`, {
    ...options,
    headers: { Authorization: `Bearer ${token}`, ...options?.headers },
  });
  if (sentToken !== token) throw new Error("管理会话已结束。");
  if (response.status === 401) {
    lock();
    throw new Error("管理员令牌无效，请重新解锁。");
  }
  if (response.status === 204) return;
  const payload = await response.json();
  if (!response.ok) throw Object.assign(new Error(payload.error ?? "请求失败。"), { code: payload.code });
  return payload;
}

async function action(button, callback, region = status) {
  button.disabled = true;
  message("", false, region);
  try {
    await callback();
  } catch (error) {
    message(error.message, true, region.closest("dialog")?.open ? region : status);
  } finally {
    button.disabled = false;
  }
}

function element(tag, text, className) {
  const node = document.createElement(tag);
  node.textContent = text;
  if (className) node.className = className;
  return node;
}

function setMode(generate) {
  generateForm.hidden = !generate;
  importForm.hidden = generate;
  showGenerate.setAttribute("aria-pressed", String(generate));
  showImport.setAttribute("aria-pressed", String(!generate));
}

function clearInstallCommand() {
  installResult.hidden = true;
  installCommand.value = "";
  message("", false, installStatus);
}

function fillInstallTarget() {
  const target = targets.find((item) => item.id === installTarget.value);
  installAddress.value = target?.address ?? "";
  installUser.value = target?.user ?? "";
  installPort.value = target?.port ?? 22;
  clearInstallCommand();
}

function openInstall(key) {
  selectedKeyId = key.id;
  document.querySelector("#install-key").textContent = `${key.id} · ${key.fingerprint}`;
  installTarget.replaceChildren(new Option("手动填写", ""),
    ...targets.map((host) => new Option(`${host.id} · ${host.address}`, host.id)));
  installTarget.value = targets.find((host) => key.hosts.includes(host.id))?.id ?? "";
  fillInstallTarget();
  installDialog.showModal();
}

function keyRow(key) {
  const row = document.createElement("li");
  const details = document.createElement("details");
  details.append(element("summary", "查看公钥"), element("pre", key.publicKey));
  const controls = element("div", "", "key-actions");
  const copy = element("button", "复制公钥", "quiet");
  copy.addEventListener("click", () => action(copy, async () => {
    await navigator.clipboard.writeText(key.publicKey);
    message("公钥已复制。");
  }));
  const install = element("button", "安装公钥", "quiet");
  install.addEventListener("click", () => openInstall(key));
  const remove = element("button", "移除", "quiet danger");
  remove.disabled = key.hosts.length > 0;
  remove.addEventListener("click", () => {
    if (!window.confirm(`移除密钥 ${key.id}？此操作会从密钥库删除该条目。`)) return;
    void action(remove, async () => {
      await request(`/${encodeURIComponent(key.id)}`, { method: "DELETE" });
      await refresh();
      message("密钥已移除。");
    });
  });
  controls.append(copy, install, remove);
  const kind = key.kind === "private" ? "私钥" : "公钥";
  row.append(
    element("div", key.label ? `${key.label} · ${key.id}` : key.id, "key-name"),
    element("div", `${kind} · ${key.algorithm} · ${key.fingerprint}`, "key-info"),
  );
  if (key.hosts.length) row.append(element("div", `已被主机引用：${key.hosts.join("、")}`, "key-info"));
  row.append(details, controls);
  return row;
}

async function refresh() {
  const result = await request("");
  const { keys } = result;
  targets = result.targets;
  document.querySelector("#empty").hidden = keys.length > 0;
  list.replaceChildren(...keys.map(keyRow));
}

login.addEventListener("submit", (event) => {
  event.preventDefault();
  token = tokenField.value.trim();
  tokenField.value = "";
  void action(event.submitter, async () => {
    await refresh();
    login.hidden = true;
    openManagementSection("keys");
    document.querySelector("#sections").hidden = false;
    logout.hidden = false;
    document.querySelector(generateForm.hidden ? "#key-id" : "#generate-id").focus();
  });
});

logout.addEventListener("click", () => {
  lock();
  message("");
});
document.querySelector("#refresh").addEventListener("click", (event) => action(event.currentTarget, refresh));
showGenerate.addEventListener("click", () => setMode(true));
showImport.addEventListener("click", () => setMode(false));

generateForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(generateForm));
  void action(event.submitter, async () => {
    const key = await request("/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    generateForm.reset();
    await refresh();
    message(`密钥 ${key.id} 已生成。点击「安装公钥」将它加入目标服务器。`);
  });
});

document.querySelector("#close-install").addEventListener("click", () => installDialog.close());
installDialog.addEventListener("close", clearInstallCommand);
installTarget.addEventListener("change", fillInstallTarget);
for (const field of [installAddress, installUser, installPort]) {
  field.addEventListener("input", clearInstallCommand);
}

installForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const keyId = selectedKeyId;
  const target = Object.fromEntries(new FormData(installForm));
  target.port = Number(target.port);
  void action(event.submitter, async () => {
    const { command } = await request(`/${encodeURIComponent(keyId)}/install-command`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(target),
    });
    if (!installDialog.open || selectedKeyId !== keyId ||
        installAddress.value !== target.address || installUser.value !== target.user ||
        Number(installPort.value) !== target.port) return;
    installCommand.value = command;
    installResult.hidden = false;
  }, installStatus);
});

const copyInstall = document.querySelector("#copy-install");
copyInstall.addEventListener("click", () => action(copyInstall, async () => {
  try {
    await navigator.clipboard.writeText(installCommand.value);
    message("安装命令已复制。", false, installStatus);
  } catch {
    installCommand.select();
    message("请按 Ctrl+C 或 ⌘C 复制所选命令。", false, installStatus);
  }
}, installStatus));

document.querySelector("#key-file").addEventListener("change", async (event) => {
  const file = event.currentTarget.files[0];
  event.currentTarget.value = "";
  if (!file) return;
  if (file.size > 32768) {
    message("密钥文件不得超过 32 KB。", true);
    return;
  }
  const sessionToken = token;
  try {
    const content = await file.text();
    if (sessionToken !== token) return;
    material.value = content;
    document.querySelector("#kind").value = content.includes("PRIVATE KEY-----") ? "private" : "public";
    message("");
  } catch {
    message("无法读取密钥文件。", true);
  }
});

importForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(importForm));
  material.value = "";
  void action(event.submitter, async () => {
    await request("", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    importForm.reset();
    await refresh();
    message("密钥已导入。");
  });
});
