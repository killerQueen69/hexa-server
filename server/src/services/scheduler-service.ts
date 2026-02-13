import { query } from "../db/connection";
import { newId } from "../utils/crypto";
import { nowIso } from "../utils/time";
import { metricsService } from "./metrics-service";
import { RelayServiceError, relayService } from "./relay-service";
import { ScheduleType, computeNextExecution, toIsoOrNull } from "./schedule-utils";

const TICK_INTERVAL_MS = 10_000;
const DUE_BATCH_LIMIT = 100;

type LoggerLike = {
  info: (obj: unknown, msg?: string) => void;
  warn: (obj: unknown, msg?: string) => void;
  error: (obj: unknown, msg?: string) => void;
};

type DueScheduleRow = {
  id: string;
  user_id: string;
  device_id: string;
  relay_index: number | null;
  target_scope: "single" | "all";
  schedule_type: ScheduleType;
  cron_expression: string | null;
  execute_at: Date | string | null;
  timezone: string;
  action: "on" | "off" | "toggle";
  is_enabled: boolean;
  next_execution: Date | string | null;
};

async function writeScheduleFailureAudit(params: {
  scheduleId: string;
  deviceId: string;
  userId: string;
  errorCode: string;
  message: string;
}): Promise<void> {
  await query(
    `INSERT INTO audit_log (
       id, device_id, user_id, schedule_id, action, details, source, created_at
     ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)`,
    [
      newId(),
      params.deviceId,
      params.userId,
      params.scheduleId,
      "schedule_execution_failed",
      JSON.stringify({
        code: params.errorCode,
        message: params.message
      }),
      "schedule",
      nowIso()
    ]
  );
}

class SchedulerService {
  private timer: NodeJS.Timeout | null = null;
  private logger: LoggerLike | null = null;
  private tickInFlight = false;

  start(logger: LoggerLike): void {
    if (this.timer) {
      return;
    }

    this.logger = logger;
    this.timer = setInterval(() => {
      void this.tick();
    }, TICK_INTERVAL_MS);

    void this.tick();
  }

  stop(): void {
    if (!this.timer) {
      return;
    }

    clearInterval(this.timer);
    this.timer = null;
  }

  private async tick(): Promise<void> {
    if (this.tickInFlight) {
      return;
    }
    this.tickInFlight = true;

    try {
      const due = await query<DueScheduleRow>(
        `SELECT
           id, user_id, device_id, relay_index, target_scope, schedule_type,
           cron_expression, execute_at, timezone, action, is_enabled, next_execution
         FROM schedules
         WHERE is_enabled = TRUE
           AND next_execution IS NOT NULL
           AND next_execution <= now()
         ORDER BY next_execution ASC
         LIMIT $1`,
        [DUE_BATCH_LIMIT]
      );

      for (const schedule of due.rows) {
        await this.executeSchedule(schedule);
      }
      metricsService.observeSchedulerTick("ok");
    } catch (error) {
      metricsService.observeSchedulerTick("error");
      this.logger?.error(
        {
          err: error
        },
        "scheduler_tick_failed"
      );
    } finally {
      this.tickInFlight = false;
    }
  }

  private async executeSchedule(schedule: DueScheduleRow): Promise<void> {
    const now = nowIso();
    const currentDueAt = schedule.next_execution
      ? new Date(schedule.next_execution)
      : new Date();
    const from = Number.isNaN(currentDueAt.getTime()) ? new Date() : currentDueAt;

    let nextExecutionIso: string | null = null;
    let disableAfterRun = false;

    try {
      const next = computeNextExecution({
        scheduleType: schedule.schedule_type,
        cronExpression: schedule.cron_expression,
        executeAt: schedule.execute_at,
        timezone: schedule.timezone,
        from
      });

      if (schedule.schedule_type === "once") {
        disableAfterRun = true;
      }
      nextExecutionIso = toIsoOrNull(next);
    } catch (error) {
      this.logger?.warn(
        {
          schedule_id: schedule.id,
          err: error
        },
        "schedule_next_execution_invalid"
      );
      disableAfterRun = true;
      nextExecutionIso = null;
    }

    try {
      if (schedule.target_scope === "all") {
        await relayService.setAllRelays({
          deviceId: schedule.device_id,
          action: schedule.action === "toggle" ? "off" : schedule.action,
          source: {
            actorUserId: schedule.user_id,
            source: "schedule",
            scheduleId: schedule.id
          }
        });
      } else {
        if (!Number.isInteger(schedule.relay_index)) {
          throw new RelayServiceError(
            400,
            "invalid_relay_index",
            "Schedule relay index is invalid."
          );
        }

        await relayService.setRelay({
          deviceId: schedule.device_id,
          relayIndex: schedule.relay_index as number,
          action: schedule.action,
          source: {
            actorUserId: schedule.user_id,
            source: "schedule",
            scheduleId: schedule.id
          }
        });
      }
      metricsService.observeSchedulerExecution("ok");
    } catch (error) {
      metricsService.observeSchedulerExecution("error");
      const code = error instanceof RelayServiceError ? error.code : "schedule_execution_failed";
      const message = error instanceof Error ? error.message : "Schedule execution failed.";
      await writeScheduleFailureAudit({
        scheduleId: schedule.id,
        deviceId: schedule.device_id,
        userId: schedule.user_id,
        errorCode: code,
        message
      });
      this.logger?.warn(
        {
          schedule_id: schedule.id,
          device_id: schedule.device_id,
          code,
          message
        },
        "schedule_execution_failed"
      );
    } finally {
      const isEnabled = disableAfterRun ? false : schedule.is_enabled;
      await query(
        `UPDATE schedules
         SET last_executed = $1,
             execution_count = execution_count + 1,
             next_execution = $2,
             is_enabled = $3,
             updated_at = $1
         WHERE id = $4`,
        [now, nextExecutionIso, isEnabled, schedule.id]
      );
    }
  }
}

export const schedulerService = new SchedulerService();
