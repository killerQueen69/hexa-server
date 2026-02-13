import * as cronParser from "cron-parser";

export type ScheduleType = "once" | "cron";

type CronModuleShape = {
  parseExpression?: (expression: string, options?: Record<string, unknown>) => {
    next: () => { toDate: () => Date };
  };
  CronExpressionParser?: {
    parse: (expression: string, options?: Record<string, unknown>) => {
      next: () => { toDate: () => Date };
    };
  };
};

function parseCronNextDate(
  expression: string,
  timezone: string,
  currentDate: Date
): Date {
  const parser = cronParser as unknown as CronModuleShape;
  const options = {
    tz: timezone,
    currentDate
  };

  if (typeof parser.parseExpression === "function") {
    const interval = parser.parseExpression(expression, options);
    return interval.next().toDate();
  }

  if (parser.CronExpressionParser?.parse) {
    const interval = parser.CronExpressionParser.parse(expression, options);
    return interval.next().toDate();
  }

  throw new Error("cron_parser_unavailable");
}

export function ensureValidTimezone(timezone: string): void {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: timezone }).format(new Date());
  } catch {
    throw new Error("invalid_timezone");
  }
}

export function computeNextExecution(params: {
  scheduleType: ScheduleType;
  cronExpression?: string | null;
  executeAt?: string | Date | null;
  timezone: string;
  from?: Date;
}): Date | null {
  const from = params.from ?? new Date();
  ensureValidTimezone(params.timezone);

  if (params.scheduleType === "once") {
    if (!params.executeAt) {
      throw new Error("execute_at_required");
    }

    const at = params.executeAt instanceof Date
      ? params.executeAt
      : new Date(params.executeAt);
    if (Number.isNaN(at.getTime())) {
      throw new Error("invalid_execute_at");
    }
    return at.getTime() > from.getTime() ? at : null;
  }

  if (!params.cronExpression || params.cronExpression.trim().length === 0) {
    throw new Error("cron_expression_required");
  }

  return parseCronNextDate(params.cronExpression.trim(), params.timezone, from);
}

export function validateCronExpression(expression: string, timezone: string): void {
  if (!expression || expression.trim().length === 0) {
    throw new Error("cron_expression_required");
  }
  ensureValidTimezone(timezone);
  parseCronNextDate(expression.trim(), timezone, new Date());
}

export function toIsoOrNull(value: Date | string | null): string | null {
  if (!value) {
    return null;
  }
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return null;
  }
  return date.toISOString();
}
