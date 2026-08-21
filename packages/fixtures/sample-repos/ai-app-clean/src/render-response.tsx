// E11 clean counterpart to ai-app-vulnerable/src/render-response.tsx: the LLM
// response is sanitized before it reaches dangerouslySetInnerHTML.
import Anthropic from "@anthropic-ai/sdk";
import DOMPurify from "dompurify";

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

export async function AnswerPanel({ question }: { question: string }) {
  const response = await anthropic.messages.create({
    model: "claude-opus-5",
    system: "Answer the user's question and format the answer as HTML.",
    messages: [{ role: "user", content: question }],
  });
  const rawHtml = response.content[0].text;
  const safeHtml = DOMPurify.sanitize(rawHtml);
  return <div dangerouslySetInnerHTML={{ __html: safeHtml }} />;
}
