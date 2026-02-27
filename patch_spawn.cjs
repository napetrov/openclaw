const fs = require("fs");
const file = "src/agents/subagent-spawn.ts";
let content = fs.readFileSync(file, "utf8");

content = content.replace(
  `  cleanup?: "delete" | "keep";
  expectsCompletionMessage?: boolean;
  attachmentsDir?: string;
  attachmentsRootDir?: string;
  retainAttachmentsOnKeep?: boolean;
};`,
  `  cleanup?: "delete" | "keep";
  expectsCompletionMessage?: boolean;
  attachments?: Record<string, unknown>[];
  attachAs?: { mountPath?: string };
};`,
);

content = content.replace(
  `  note?: string;
  modelApplied?: boolean;
  error?: string;
};`,
  `  note?: string;
  modelApplied?: boolean;
  error?: string;
  attachments?: any;
};`,
);

fs.writeFileSync(file, content);
