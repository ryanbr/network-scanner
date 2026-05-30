import globals from "globals";
import { defineConfig } from "eslint/config";

export default defineConfig([
  {
    files: ["**/*.{js,mjs,cjs}"],
    // Node globals (require/module/process/Buffer/...) plus browser globals
    // (document/window/navigator) — the latter are referenced inside
    // page.evaluate() callbacks that eslint parses as part of the file.
    languageOptions: { globals: { ...globals.node, ...globals.browser } },
    // Catch undefined-variable references statically. node --check only
    // validates syntax, so an orphaned identifier (e.g. a const that was
    // removed while a usage remained) passes parsing but throws
    // ReferenceError at runtime only when that branch executes. no-undef
    // turns that whole class into a build-time failure.
    rules: { "no-undef": "error" },
  },
]);
