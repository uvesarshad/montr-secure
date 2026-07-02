// Ambient declarations so `tsc` can resolve non-code imports that the Next.js /
// PostCSS toolchain handles at build time.
declare module "*.css";
declare module "*.module.css" {
  const classes: Record<string, string>;
  export default classes;
}
