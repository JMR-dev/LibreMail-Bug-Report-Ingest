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
// non-trivial logic — the DST timezone gate (internal/schedule) and the
// decrypt→format→create publish pipeline (internal/publish) — lives in
// build-tag-free, host-tested packages; this file is the thin runtime adapter
// that binds the R2-backed lifecycle Manager, the encryption keyring, and the
// GitHub token/target-repo (from Cloudflare bindings) to them.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/syumai/workers/cloudflare"
	"github.com/syumai/workers/cloudflare/cron"

	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/crypto"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/lifecycle"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/publish"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/schedule"
	"github.com/JMR-dev/LibreMail-Bug-Report-Ingest/internal/storage"
)

// Cloudflare binding/var names for the publish step (#14), declared in
// wrangler.jsonc. The token is a Secrets Store secret (read via binding.get(),
// like the encryption keyring); the target repo is a plain var so it is
// configurable without a redeploy of code.
const (
	githubTokenBinding = "GITHUB_TOKEN" // Secrets Store secret holding the PAT
	githubRepoVar      = "GITHUB_REPO"  // "owner/repo", e.g. "JMR-dev/LibreMail"
	defaultTargetRepo  = "JMR-dev/LibreMail"
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
// 23:00 UTC during CST (winter) — and the timezone decision is schedule's
// IsFriday1700Central gate. Only the fire that is actually 17:00 Central lists
// the pending reports (via the R2-backed lifecycle Manager, #10) and publishes
// them as GitHub issues; the sibling fire is a no-op. Net effect: publishing runs
// exactly once each Friday, correct across the DST boundary, from two static UTC
// crons.
//
// The gate is checked up front so the sibling (no-op) fire does no Secrets Store
// I/O: the GitHub token and encryption keyring are read only when the gate is
// open. schedule.Run re-applies the same gate authoritatively.
func runWeeklyTrigger(ctx context.Context) error {
	event, err := cron.NewEvent(ctx)
	if err != nil {
		return err
	}

	// Fast path for the sibling cron: skip the publish wiring (and its secret
	// reads) entirely. The other Friday fire covers this week.
	if !schedule.IsFriday1700Central(event.ScheduledTime) {
		log.Printf("schedule: cron %q fired for %s, not Friday 17:00 America/Chicago; the sibling cron covers this week",
			event.Cron, event.ScheduledTime.Format(time.RFC3339))
		return nil
	}

	manager, publisher, err := buildPublish(ctx)
	if err != nil {
		return fmt.Errorf("schedule: build publisher: %w", err)
	}

	// schedule.Run re-checks the gate (open here) and hands the pending ids to the
	// publisher, which decrypts, formats, and creates one labeled GitHub issue per
	// report. Cross-run de-dup (marking reports published) is #15's job, wired via
	// the publisher's onPublished hook; #14 leaves that hook at its default no-op.
	if _, err := schedule.Run(ctx, event.ScheduledTime, manager, publisher); err != nil {
		return err
	}
	return nil
}

// buildPublish assembles the pending-report lister and the real publish.Publisher
// from the Worker's bindings: the R2-backed lifecycle Manager (source of pending
// ids + encrypted frames), the AES-256 keyring and GitHub token from Secrets
// Store, and the target repo from a plain var. It performs the (async) secret
// reads, so it is only called on the gate-open fire. The Manager is returned
// separately so schedule.Run uses the same instance as both lister and getter.
func buildPublish(_ context.Context) (*lifecycle.Manager, *publish.Publisher, error) {
	store, err := storage.NewR2Store(storage.BucketBinding)
	if err != nil {
		return nil, nil, fmt.Errorf("r2 binding: %w", err)
	}
	manager := lifecycle.New(store)

	keyringRaw, err := storage.ReadSecret(storage.KeyringBinding)
	if err != nil {
		return nil, nil, fmt.Errorf("read keyring secret: %w", err)
	}
	keyring, err := crypto.ParseKeyring(keyringRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("parse keyring: %w", err)
	}

	tokenRaw, err := storage.ReadSecret(githubTokenBinding)
	if err != nil {
		return nil, nil, fmt.Errorf("read github token secret: %w", err)
	}

	repo := cloudflare.Getenv(githubRepoVar)
	if repo == "" {
		repo = defaultTargetRepo
	}
	owner, name, err := publish.ParseRepo(repo)
	if err != nil {
		return nil, nil, err
	}

	client := publish.NewClient(string(tokenRaw), owner, name)
	// onPublished is left at its default no-op: #15 wires it to
	// lifecycle.MarkPublished to complete cross-run de-duplication.
	return manager, publish.New(client, keyring, manager), nil
}
