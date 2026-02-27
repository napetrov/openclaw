const fs = require("fs");
let f2 = fs.readFileSync("src/agents/tools/sessions-spawn-tool.ts", "utf8");
f2 = f2.replace(/import crypto from "node:crypto";\n/, "");
f2 = f2.replace(/import { promises as fs } from "node:fs";\n/, "");
f2 = f2.replace(/import path from "node:path";\n/, "");
f2 = f2.replace(/import { loadConfig } from "\.\.\/\.\.\/config\/config\.js";\n/, "");
f2 = f2.replace(
  /import { resolveAgentModelPrimaryValue } from "\.\.\/\.\.\/config\/model-input\.js";\n/,
  "",
);
f2 = f2.replace(/import { callGateway } from "\.\.\/\.\.\/gateway\/call\.js";\n/, "");
f2 = f2.replace(
  /import { getGlobalHookRunner } from "\.\.\/\.\.\/plugins\/hook-runner-global\.js";\n/,
  "",
);
f2 = f2.replace(
  /import { normalizeAgentId, parseAgentSessionKey } from "\.\.\/\.\.\/routing\/session-key\.js";\n/,
  "",
);
f2 = f2.replace(
  /import { normalizeDeliveryContext } from "\.\.\/\.\.\/utils\/delivery-context\.js";\n/,
  "",
);
f2 = f2.replace(/import { resolveAgentConfig } from "\.\.\/agent-scope\.js";\n/, "");
f2 = f2.replace(/import { resolveDefaultModelForAgent } from "\.\.\/model-selection\.js";\n/, "");
fs.writeFileSync("src/agents/tools/sessions-spawn-tool.ts", f2);
