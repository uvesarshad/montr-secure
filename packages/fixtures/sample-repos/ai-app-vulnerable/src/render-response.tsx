// E11 fixture: unescaped LLM output rendered to users (3) — XSS, but the
// untrusted source is the model instead of direct user input.
import Anthropic from "@anthropic-ai/sdk";

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

export async function AnswerPanel({ question }: { question: string }) {
  const response = await anthropic.messages.create({
    model: "claude-opus-5",
    system: "Answer the user's question and format the answer as HTML.",
    messages: [{ role: "user", content: question }],
  });
  const html = response.content[0].text;
  // VULNERABLE: the raw LLM response is injected into the DOM with no escaping.
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
