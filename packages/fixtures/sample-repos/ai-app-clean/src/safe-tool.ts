// E11 clean counterpart to ai-app-vulnerable/src/unsafe-tool.ts: the exposed
// tool is read-only with no dangerous capability at all.
import Anthropic from "@anthropic-ai/sdk";

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

async function readOnlyLookup(query: string): Promise<{ result: string }> {
  return { result: `lookup:${query}` };
}

export async function agentTurn(userInput: string) {
  return anthropic.messages.create({
    model: "claude-opus-5",
    system: "You are a read-only lookup assistant.",
    messages: [{ role: "user", content: userInput }],
    tools: [
      {
        name: "lookup_record",
        description: "Look up a record by id (read-only, no mutation).",
        handler: readOnlyLookup,
      },
    ],
  });
}
