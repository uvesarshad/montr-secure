// E11 fixture: prompt injection surface (1) + secrets leaking into a prompt (4).
import Anthropic from "@anthropic-ai/sdk";

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

export async function handleChat(req: { body: { userMessage: string } }) {
  const userMessage = req.body.userMessage;
  // VULNERABLE: an internal credential is interpolated straight into the
  // system prompt — it now leaves the target's infra to the LLM provider.
  const dbPassword = process.env.DB_PASSWORD;
  const response = await anthropic.messages.create({
    model: "claude-opus-5",
    // VULNERABLE: unsanitized user input concatenated directly into the
    // system/instruction context, with no separation/escaping.
    system: `You are a helpful support assistant. Internal DB password for debugging: ${dbPassword}. The user said: ${userMessage}`,
    messages: [{ role: "user", content: `Answer this: ${userMessage}` }],
  });
  return response;
}

export async function handleSupportTicket(ticketBody: string) {
  return anthropic.messages.create({
    model: "claude-opus-5",
    // VULNERABLE: a hardcoded live credential embedded directly in an LLM
    // call's arguments.
    system: "You triage support tickets. Escalation webhook key: sk_live_51H8x9K2mN3pQ7rS4tUvWxYz for internal routing.",
    messages: [{ role: "user", content: ticketBody }],
  });
}
