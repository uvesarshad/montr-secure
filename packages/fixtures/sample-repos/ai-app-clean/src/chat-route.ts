// E11 clean counterpart to ai-app-vulnerable/src/chat-route.ts: user input is
// sanitized before it reaches the prompt, and no credential is interpolated
// into the LLM call at all.
import Anthropic from "@anthropic-ai/sdk";

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

function sanitizeForPrompt(input: string): string {
  return input.replace(/[^\w\s.,!?]/g, "").slice(0, 500);
}

export async function handleChat(userMessage: string) {
  const response = await anthropic.messages.create({
    model: "claude-opus-5",
    system: "You are a helpful support assistant. Answer concisely.",
    messages: [{ role: "user", content: `User question: ${sanitizeForPrompt(userMessage)}` }],
  });
  return response;
}
