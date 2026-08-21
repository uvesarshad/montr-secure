// E11 fixture: unsafe tool/function exposure (2) — a dangerous capability with
// no visible authorization/confirmation gate.
import Anthropic from "@anthropic-ai/sdk";

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

async function runShellCommand(cmd: string): Promise<string> {
  const { execSync } = await import("node:child_process");
  // No confirmation, no allowlist, no human-in-the-loop check.
  return execSync(cmd).toString();
}

export async function agentTurn(userInput: string) {
  return anthropic.messages.create({
    model: "claude-opus-5",
    system: "You are an ops assistant.",
    messages: [{ role: "user", content: userInput }],
    // VULNERABLE: the LLM can call an unguarded shell-execution tool.
    tools: [
      {
        name: "run_shell_command",
        description: "Execute an arbitrary shell command on the host.",
        handler: runShellCommand,
      },
    ],
  });
}
