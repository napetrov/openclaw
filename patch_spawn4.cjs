const fs = require("fs");
const file = "src/agents/subagent-spawn.ts";
let content = fs.readFileSync(file, "utf8");

content = content.replace(
  `      // Always delete the provisional child session after a failed spawn attempt.
      // If we already emitted subagent_ended above, suppress a duplicate lifecycle hook.
      try {
        await callGateway({
          method: "sessions.delete",
          params: {
            key: childSessionKey,
            deleteTranscript: true,
            emitLifecycleHooks: !endedHookEmitted,
          },
          timeoutMs: 10_000,
        });
      } catch {
        // Best-effort only.
      }
    }
    const messageText = summarizeError(err);`,
  `      // Always delete the provisional child session after a failed spawn attempt.
      // If we already emitted subagent_ended above, suppress a duplicate lifecycle hook.
      try {
        await callGateway({
          method: "sessions.delete",
          params: {
            key: childSessionKey,
            deleteTranscript: true,
            emitLifecycleHooks: !endedHookEmitted,
          },
          timeoutMs: 10_000,
        });
      } catch {
        // Best-effort only.
      }
    }
    // Spawn failed before registry enrollment; always remove staged attachments.
    if (attachmentAbsDir) {
      await fsPromises.rm(attachmentAbsDir, { recursive: true, force: true });
    }
    const messageText = summarizeError(err);`,
);

content = content.replace(
  `    runTimeoutSeconds,
    expectsCompletionMessage,
    spawnMode,
    attachmentsDir: params.attachmentsDir,
    attachmentsRootDir: params.attachmentsRootDir,
    retainAttachmentsOnKeep: params.retainAttachmentsOnKeep,
  });`,
  `    runTimeoutSeconds,
    expectsCompletionMessage,
    spawnMode,
    attachmentsDir: attachmentAbsDir,
    attachmentsRootDir: attachmentRootDir,
    retainAttachmentsOnKeep: retainOnSessionKeep,
  });`,
);

content = content.replace(
  `  const note =
    spawnMode === "session"
      ? SUBAGENT_SPAWN_SESSION_ACCEPTED_NOTE
      : isCronSession
        ? undefined
        : SUBAGENT_SPAWN_ACCEPTED_NOTE;

  return {
    status: "accepted",
    childSessionKey,
    runId: childRunId,
    mode: spawnMode,
    note,
    modelApplied: resolvedModel ? modelApplied : undefined,
  };`,
  `  const note =
    spawnMode === "session"
      ? SUBAGENT_SPAWN_SESSION_ACCEPTED_NOTE
      : isCronSession
        ? undefined
        : SUBAGENT_SPAWN_ACCEPTED_NOTE;

  return {
    status: "accepted",
    childSessionKey,
    runId: childRunId,
    mode: spawnMode,
    note,
    modelApplied: resolvedModel ? modelApplied : undefined,
    attachments: attachmentsReceipt,
  };`,
);

fs.writeFileSync(file, content);
