# Public bootstrap browser fixture: invalid asynchronous polling

Base checkout: 62f97d7cf5562943d545681fa788c31378523d87 plus uncommitted public
bootstrap WIP. This is not exact committed source acceptance.

Runs 37359 and 49898 both exited 1 after two real browser Node roots connected
through the Python Node. The initial request was queued, then the fixture read an
empty intake projection too early. First run raised TypeError; diagnostic run
recorded three empty list results. Neither establishes successful delivery, a
product deletion bug, or completed public bootstrap.

The harness used Playwright waitForFunction with an async predicate. Installed
playwright-core/lib/coreBundle.js around 25707 invokes predicate synchronously and
treats its Promise as truthy, finishing polling even if it resolves false. Thus the
fixture did not actually wait for the request to arrive. All five async predicates
in this tool now use explicit awaited page.evaluate polling with a fixed deadline.
Product source was not changed for this correction. Real browser rerun is required.

First source manifest and sanitized failure logs are adjacent to this file. The
manifest was captured after initial source snapshot, before owned runtime edits;
other agents' source is not inferred to be an immutable exact Git tree. Later
harness polling edits are not represented by the first-run manifest.
