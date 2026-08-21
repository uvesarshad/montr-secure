// E11 fixture: missing output validation (5) — an LLM response drives a
// sensitive sink (here, a shell command) with no parse/validate/allowlist
// check anywhere in between.
import Anthropic from "@anthropic-ai/sdk";
import { execSync } from "node:child_process";

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

export async function runSuggestedCommand(task: string) {
  const response = await anthropic.messages.create({
    model: "claude-opus-5",
    system: "Suggest a single shell command to accomplish the task. Reply with ONLY the command.",
    messages: [{ role: "user", content: task }],
  });
  const suggestedCommand = response.content[0].text;
  // VULNERABLE: the model's raw text output is executed directly.
  return execSync(suggestedCommand).toString();
}
