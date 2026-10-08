# PRIVATE final receipt continuation

After bilateral local receipts, activation detaches BOOTSTRAP_ONLY and binds the
final Account route. A lost final receipt must not strand the other participant.
The encrypted bootstrap config now records a one-time continuation horizon of at
most 300 seconds (also bounded by original signed bundle expiry) and durable
16-send/16-receive budgets. Reload cannot renew the horizon or reset counters.

An ACTIVE owner may resend only an EXACT already persisted ACCEPT/CONFIRM receipt
for the selected exchange to its certified peer route. REQUEST and changed receipts
are refused; destination owner/current-grant guards still apply. The sender spends
its durable budget before sending. An ACTIVE receiver intercepts only the bootstrap
namespace, validates the stored selected receipt through the existing signature
codec, and consumes exact duplicate receipts without delivering them to Account
Inbox. New REQUEST is discarded; ordinary application packets retain the normal
Inbox path. No Account private key participates in Node dispatch or transit.

Worker ownership and root guards remain mandatory. Continuation fails closed after
expiry, budget exhaustion or retirement. Further exchange then requires an explicit
new pairing; this is not unbounded bootstrap activation or user-payload fallback.

UNIT coverage includes exact retry after simulated loss, duplicate receipt sink,
no REQUEST after ACTIVE, substituted receipt denial, budget persisted across
runtime reconstruction and expired horizon. These use storage/crypto doubles;
existing actual bootstrap signature/ownership tests are separate. Real two-Worker
PRIVATE loss/reload/UI acceptance remains required.
