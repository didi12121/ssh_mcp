const args = process.argv.slice(2);
const remoteCommand = args.at(-1) ?? "";

if (remoteCommand.includes("mcp-ssh-ok")) {
  process.stdout.write("mcp-ssh-ok\n");
} else {
  process.stdout.write(`${JSON.stringify({ args, remoteCommand })}\n`);
}
