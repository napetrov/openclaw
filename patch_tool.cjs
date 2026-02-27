const fs = require("fs");
const file = "src/agents/tools/sessions-spawn-tool.ts";
let content = fs.readFileSync(file, "utf8");

content = content.replace(
  `      const thread = params.thread === true;

      const result =
        runtime === "acp"`,
  `      const thread = params.thread === true;

      const requestedAttachments = Array.isArray(params.attachments)
        ? (params.attachments as Array<Record<string, unknown>>)
        : [];
      const attachAs = params.attachAs as { mountPath?: string } | undefined;

      const result =
        runtime === "acp"`,
);

content = content.replace(
  `                mode,
                cleanup,
                expectsCompletionMessage: true,
              },`,
  `                mode,
                cleanup,
                expectsCompletionMessage: true,
                attachments: requestedAttachments,
                attachAs,
              },`,
);

// Let's also remove `decodeStrictBase64` from sessions-spawn-tool.ts since it's now in subagent-spawn.ts
content = content.replace(/function decodeStrictBase64.*?return decoded;\n}/s, "");

fs.writeFileSync(file, content);
