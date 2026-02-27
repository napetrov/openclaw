const fs = require("fs");

let f1 = fs.readFileSync("src/agents/subagent-spawn.ts", "utf8");
f1 = f1.replace("attachments?: any;", "attachments?: unknown;");
fs.writeFileSync("src/agents/subagent-spawn.ts", f1);

let f2 = fs.readFileSync("src/agents/tools/sessions-spawn-tool.ts", "utf8");
f2 = f2.replace(
  /import \{\n  resolveDisplaySessionKey,\n  resolveInternalSessionKey,\n  resolveMainSessionAlias,\n\} from "\.\/sessions-helpers\.js";/,
  "",
);
f2 = f2.replace(
  /import { resolveDisplaySessionKey, resolveInternalSessionKey, resolveMainSessionAlias } from "\.\/sessions-helpers\.js";/,
  "",
);
f2 = f2.replace(
  /import { resolveAgentConfig, resolveAgentWorkspaceDir } from "\.\.\/agent-scope\.js";/,
  'import { resolveAgentConfig } from "../agent-scope.js";',
);
fs.writeFileSync("src/agents/tools/sessions-spawn-tool.ts", f2);

let f3 = fs.readFileSync("src/agents/session-transcript-repair.ts", "utf8");
f3 = f3.replace(
  /type ToolCallBlock = {\n  type: "toolCall";\n  id: string;\n  name: string;\n  arguments: Record<string, unknown>;\n};\n\n/,
  "",
);
f3 = f3.replace(
  /nextContent\.push\(sanitized as any\);/,
  "nextContent.push(sanitized as unknown as typeof block);",
);
f3 = f3.replace(
  /nextContent\.push\(block\);/g,
  "nextContent.push(block as unknown as typeof block);",
);
fs.writeFileSync("src/agents/session-transcript-repair.ts", f3);
