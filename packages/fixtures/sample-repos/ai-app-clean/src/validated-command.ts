// E11 clean counterpart to ai-app-vulnerable/src/missing-validation.ts: the
// model's suggestion is checked against a fixed allowlist before it drives
// a shell command.
import Anthropic from "@anthropic-ai/sdk";
import { execSync } from "node:child_process";

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const ALLOWED_COMMANDS = ["status", "diskspace", "uptime"];

export async function runSuggestedCommand(task: string) {
  const response = await anthropic.messages.create({
    model: "claude-opus-5",
    system: "Suggest one of: status, diskspace, uptime. Reply with ONLY that word.",
    messages: [{ role: "user", content: task }],
  });
  const suggestedCommand = response.content[0].text.trim();
  if (!ALLOWED_COMMANDS.includes(suggestedCommand)) {
    throw new Error("command not allowed");
  }
  return execSync(suggestedCommand).toString();
}
