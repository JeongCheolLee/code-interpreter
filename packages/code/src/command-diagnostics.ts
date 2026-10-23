/** Worker-local diagnostics: never add these fields to bridge settlements. */
export type CommandFailureStage =
    | 'allocation'
    | 'sandbox_startup'
    | 'programmatic_preflight'
    | 'credential_resolution'
    | 'command_wrapping'
    | 'dispatch'
    | 'executor_transport'
    | 'cleanup';

const reasons = [
    'workspace_busy',
    'capacity_exhausted',
    'allocation_failed',
    'startup_failed',
    'prerequisite_failed',
    'credential_failed',
    'wrapping_failed',
    'executor_rejected',
    'executor_unavailable',
    'executor_lost',
    'send_failed',
    'rpc_timeout',
    'cleanup_failed',
] as const;
export type CommandFailureReason = (typeof reasons)[number];

const setupReasons = {
    sandbox_startup: 'startup_failed',
    programmatic_preflight: 'prerequisite_failed',
    credential_resolution: 'credential_failed',
    command_wrapping: 'wrapping_failed',
} as const;
export type CommandSetupStage = keyof typeof setupReasons;

export function commandSetupFailureDiagnostic(
    stage: CommandSetupStage,
    error: unknown,
): CommandFailureDiagnostic {
    return commandFailureDiagnostic(stage, setupReasons[stage], error);
}
export interface CommandFailureDiagnostic {
    stage: CommandFailureStage;
    reason: CommandFailureReason;
    osCode?: string;
}
const stages = new Set<string>([
    'allocation',
    'sandbox_startup',
    'programmatic_preflight',
    'credential_resolution',
    'command_wrapping',
    'dispatch',
    'executor_transport',
    'cleanup',
]);
const osCodes = new Set([
    'ENOSPC',
    'EDQUOT',
    'EACCES',
    'EPERM',
    'ENOMEM',
    'EMFILE',
    'ENFILE',
    'EIO',
    'ENOENT',
    'EPIPE',
    'ECONNRESET',
    'ETIMEDOUT',
]);

export function commandFailureDiagnostic(
    stage: CommandFailureStage,
    reason: CommandFailureReason,
    error?: unknown,
): CommandFailureDiagnostic {
    const code =
        error != null && typeof error === 'object' && 'code' in error
            ? error.code
            : undefined;
    return {
        stage,
        reason,
        ...(typeof code === 'string' && osCodes.has(code)
            ? { osCode: code }
            : {}),
    };
}

/** Reconstruct only allowlisted fields, even across the trusted executor IPC. */
export function readCommandFailureDiagnostic(
    value: unknown,
): CommandFailureDiagnostic | undefined {
    if (value == null || typeof value !== 'object') return;
    const v = value as Partial<CommandFailureDiagnostic>;
    if (!stages.has(v.stage ?? '') || !reasons.includes(v.reason!)) return;
    return commandFailureDiagnostic(v.stage!, v.reason!, { code: v.osCode });
}

export interface CommandFailureEvent extends CommandFailureDiagnostic {
    event: 'workspace_command_unavailable';
    assignmentId?: string;
    workspaceId?: string;
    workerId?: string;
    incarnationId?: string;
    operation: 'execute_command' | 'workspace_programmatic';
    mutationMayHaveCommitted: boolean;
    requiresQuarantine: boolean;
}

export function commandFailureEvent(
    diagnostic: CommandFailureDiagnostic | undefined,
    context: Omit<
        CommandFailureEvent,
        keyof CommandFailureDiagnostic | 'event'
    >,
): CommandFailureEvent {
    const id = (value?: string): string | undefined =>
        value && /^[A-Za-z0-9_-]{1,128}$/.test(value) ? value : undefined;
    return {
        event: 'workspace_command_unavailable',
        ...(readCommandFailureDiagnostic(diagnostic) ??
            commandFailureDiagnostic('dispatch', 'executor_rejected')),
        assignmentId: id(context.assignmentId),
        workspaceId: id(context.workspaceId),
        workerId: id(context.workerId),
        incarnationId: id(context.incarnationId),
        operation: context.operation,
        mutationMayHaveCommitted: context.mutationMayHaveCommitted,
        requiresQuarantine: context.requiresQuarantine,
    };
}
