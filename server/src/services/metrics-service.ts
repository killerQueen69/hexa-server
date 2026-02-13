type CommandResult = "success" | "timeout" | "error";
type SchedulerResult = "ok" | "error";

const LATENCY_BUCKETS_MS = [50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000];

type CommandCounterKey = `${string}|${string}|${string}`;
type CommandLatencyKey = `${string}|${string}`;
type ApiErrorKey = `${number}|${string}`;

type CommandHistogram = {
  buckets: number[];
  count: number;
  sum: number;
};

function commandCounterKey(source: string, scope: string, result: CommandResult): CommandCounterKey {
  return `${source}|${scope}|${result}`;
}

function commandLatencyKey(source: string, scope: string): CommandLatencyKey {
  return `${source}|${scope}`;
}

function apiErrorKey(statusCode: number, code: string): ApiErrorKey {
  return `${statusCode}|${code}`;
}

function escapeLabel(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/\n/g, "\\n")
    .replace(/"/g, '\\"');
}

class MetricsService {
  private readonly commandTotals = new Map<CommandCounterKey, number>();
  private readonly commandLatencies = new Map<CommandLatencyKey, CommandHistogram>();
  private schedulerTickOk = 0;
  private schedulerTickError = 0;
  private schedulerExecutionOk = 0;
  private schedulerExecutionError = 0;
  private readonly apiErrors = new Map<ApiErrorKey, number>();

  observeCommand(params: {
    source: string;
    scope: "single" | "all";
    result: CommandResult;
    latencyMs: number;
  }): void {
    const counterKey = commandCounterKey(params.source, params.scope, params.result);
    this.commandTotals.set(counterKey, (this.commandTotals.get(counterKey) ?? 0) + 1);

    const latencyKey = commandLatencyKey(params.source, params.scope);
    const existing = this.commandLatencies.get(latencyKey) ?? {
      buckets: new Array<number>(LATENCY_BUCKETS_MS.length).fill(0),
      count: 0,
      sum: 0
    };

    const boundedLatency = Math.max(0, params.latencyMs);
    existing.count += 1;
    existing.sum += boundedLatency;
    for (let i = 0; i < LATENCY_BUCKETS_MS.length; i += 1) {
      if (boundedLatency <= LATENCY_BUCKETS_MS[i]) {
        existing.buckets[i] += 1;
      }
    }
    this.commandLatencies.set(latencyKey, existing);
  }

  observeSchedulerTick(result: SchedulerResult): void {
    if (result === "ok") {
      this.schedulerTickOk += 1;
      return;
    }
    this.schedulerTickError += 1;
  }

  observeSchedulerExecution(result: SchedulerResult): void {
    if (result === "ok") {
      this.schedulerExecutionOk += 1;
      return;
    }
    this.schedulerExecutionError += 1;
  }

  observeApiError(params: { statusCode: number; code: string }): void {
    const key = apiErrorKey(params.statusCode, params.code);
    this.apiErrors.set(key, (this.apiErrors.get(key) ?? 0) + 1);
  }

  snapshot(): {
    command_totals: Array<{
      source: string;
      scope: string;
      result: CommandResult;
      total: number;
    }>;
    scheduler: {
      tick_ok: number;
      tick_error: number;
      execution_ok: number;
      execution_error: number;
    };
    api_errors: Array<{
      status_code: number;
      code: string;
      total: number;
    }>;
  } {
    return {
      command_totals: [...this.commandTotals.entries()].map(([key, total]) => {
        const [source, scope, result] = key.split("|");
        return {
          source,
          scope,
          result: result as CommandResult,
          total
        };
      }),
      scheduler: {
        tick_ok: this.schedulerTickOk,
        tick_error: this.schedulerTickError,
        execution_ok: this.schedulerExecutionOk,
        execution_error: this.schedulerExecutionError
      },
      api_errors: [...this.apiErrors.entries()].map(([key, total]) => {
        const [statusCode, code] = key.split("|");
        return {
          status_code: Number(statusCode),
          code,
          total
        };
      })
    };
  }

  renderPrometheus(): string {
    const lines: string[] = [];

    lines.push("# HELP hexa_command_total Relay command outcomes by source/scope/result.");
    lines.push("# TYPE hexa_command_total counter");
    for (const [key, value] of this.commandTotals) {
      const [source, scope, result] = key.split("|");
      lines.push(
        `hexa_command_total{source="${escapeLabel(source)}",scope="${escapeLabel(scope)}",result="${escapeLabel(result)}"} ${value}`
      );
    }

    lines.push("# HELP hexa_command_latency_ms Relay command latency histogram in milliseconds.");
    lines.push("# TYPE hexa_command_latency_ms histogram");
    for (const [key, histogram] of this.commandLatencies) {
      const [source, scope] = key.split("|");
      for (let i = 0; i < LATENCY_BUCKETS_MS.length; i += 1) {
        lines.push(
          `hexa_command_latency_ms_bucket{source="${escapeLabel(source)}",scope="${escapeLabel(scope)}",le="${LATENCY_BUCKETS_MS[i]}"} ${histogram.buckets[i]}`
        );
      }
      lines.push(
        `hexa_command_latency_ms_bucket{source="${escapeLabel(source)}",scope="${escapeLabel(scope)}",le="+Inf"} ${histogram.count}`
      );
      lines.push(
        `hexa_command_latency_ms_sum{source="${escapeLabel(source)}",scope="${escapeLabel(scope)}"} ${histogram.sum.toFixed(3)}`
      );
      lines.push(
        `hexa_command_latency_ms_count{source="${escapeLabel(source)}",scope="${escapeLabel(scope)}"} ${histogram.count}`
      );
    }

    lines.push("# HELP hexa_scheduler_tick_total Scheduler tick result counter.");
    lines.push("# TYPE hexa_scheduler_tick_total counter");
    lines.push(`hexa_scheduler_tick_total{result="ok"} ${this.schedulerTickOk}`);
    lines.push(`hexa_scheduler_tick_total{result="error"} ${this.schedulerTickError}`);

    lines.push("# HELP hexa_scheduler_execution_total Schedule execution result counter.");
    lines.push("# TYPE hexa_scheduler_execution_total counter");
    lines.push(`hexa_scheduler_execution_total{result="ok"} ${this.schedulerExecutionOk}`);
    lines.push(`hexa_scheduler_execution_total{result="error"} ${this.schedulerExecutionError}`);

    lines.push("# HELP hexa_api_errors_total API error responses by status/code.");
    lines.push("# TYPE hexa_api_errors_total counter");
    for (const [key, value] of this.apiErrors) {
      const [statusCode, code] = key.split("|");
      lines.push(
        `hexa_api_errors_total{status_code="${escapeLabel(statusCode)}",code="${escapeLabel(code)}"} ${value}`
      );
    }

    return lines.join("\n");
  }
}

export const metricsService = new MetricsService();
