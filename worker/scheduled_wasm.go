//go:build js && wasm

// This file wires the weekly publish Cron Trigger (#13) into the Cloudflare
// Worker. It is deliberately separate from worker/main.go: the scheduled task is
// registered here from init() via cron.ScheduleTaskNonBlock, which only records a
// package-level callback and returns. init() runs before main(), so by the time
// main()'s workers.Serve signals the runtime ready both the fetch handler and
// this scheduled handler are registered — and worker/main.go needs no change
// (keeping this ticket's diff off the shared fetch wiring).
//
// Compiled only into the js/wasm Worker; excluded from host builds and tests. All
// non-trivial logic — the DST timezone gate and the list→publish orchestration —
// lives in internal/schedule, which is build-tag-free and host-tested; this file
// is the thin runtime adapter that binds the R2-backed lifecycle Manager to it.
package main

import (
	"context"
	"log"
	"time"

	"github.com/syumai/workers/cloudflare/cron"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/lifecycle"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/schedule"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/storage"
)

// init registers the Cron Trigger handler with the syumai/workers runtime. The
// cron package's own init installs the JS "runScheduler" binding; this call just
// selects which Task that binding runs.
func init() {
	cron.ScheduleTaskNonBlock(runWeeklyTrigger)
}

// runWeeklyTrigger is invoked by the Workers runtime on every Cron Trigger fire.
//
// Cloudflare Cron Triggers are UTC-only, so wrangler.jsonc schedules BOTH Friday
// UTC hours that can be 17:00 America/Chicago — 22:00 UTC during CDT (summer) and
// 23:00 UTC during CST (winter) — and this handler defers the timezone decision
// to schedule.Run. Run gates on the event's scheduled time so only the fire that
// is actually 17:00 Central lists the pending reports (via the R2-backed
// lifecycle Manager, #10) and hands their ids to the publish step; the sibling
// fire is a no-op. Net effect: publishing runs exactly once each Friday, correct
// across the DST boundary, from two static UTC crons.
func runWeeklyTrigger(ctx context.Context) error {
	event, err := cron.NewEvent(ctx)
	if err != nil {
		return err
	}

	// Resolve the R2 bucket binding (synchronous, no I/O). It goes unused on the
	// sibling fire, where Run's gate is closed; that happens at most once a week.
	store, err := storage.NewR2Store(storage.BucketBinding)
	if err != nil {
		return err
	}
	manager := lifecycle.New(store)

	// schedule.LogPublisher is the no-op default seam; the publish job (#14) will
	// replace it with the real GitHub-issue publisher without touching this file.
	ran, err := schedule.Run(ctx, event.ScheduledTime, manager, schedule.LogPublisher{})
	if err != nil {
		return err
	}
	if !ran {
		log.Printf("schedule: cron %q fired for %s, not Friday 17:00 America/Chicago; the sibling cron covers this week",
			event.Cron, event.ScheduledTime.Format(time.RFC3339))
	}
	return nil
}
