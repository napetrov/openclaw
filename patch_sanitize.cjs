const fs = require("fs");
const file = "src/agents/session-transcript-repair.ts";
let content = fs.readFileSync(file, "utf8");

const newSanitize = `function sanitizeToolCallBlock(block: RawToolCallBlock): RawToolCallBlock {
  const name = typeof block.name === "string" ? block.name : undefined;

  if (name !== "sessions_spawn") {
    return block;
  }

  // Redact large/sensitive inline attachment content from persisted transcripts.
  // Apply redaction to both \`.arguments\` and \`.input\` properties since block structures can vary
  const nextArgs = redactSessionsSpawnAttachmentsArgs(block.arguments);
  const nextInput = redactSessionsSpawnAttachmentsArgs(block.input);
  
  if (nextArgs === block.arguments && nextInput === block.input) {
    return block;
  }
  
  const merged = { ...block };
  if ("arguments" in block) {
    merged.arguments = nextArgs;
  }
  if ("input" in block) {
    merged.input = nextInput;
  }
  
  return merged;
}`;

content = content.replace(
  /function sanitizeToolCallBlock\(block: RawToolCallBlock\): ToolCallBlock \{[\s\S]*?return \{ \.\.\.normalized, arguments: merged \};\n\}/,
  newSanitize,
);

fs.writeFileSync(file, content);
