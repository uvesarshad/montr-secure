// app/search/page.tsx
type Props = { searchParams: { q?: string } };
export default function SearchPage({ searchParams }: Props) {
  const q = searchParams.q ?? "";
  // VULN #2 (CWE-79): reflected XSS — user input rendered as raw HTML on line 8.
  return (
    <div>
      <div dangerouslySetInnerHTML={{ __html: q }} />
    </div>
  );
}
