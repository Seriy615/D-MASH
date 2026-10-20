#!/usr/bin/env python3
"""Bounded exhaustive SPECIFICATION model, never a production implementation.

One stable message ID; one remote mailbox, local Node, and Account. Storage writes
are atomic. Two packets allow duplicate/reorder exploration. Authentication is a
symbolic perfect predicate, not an implementation or cryptographic proof.
"""
from dataclasses import dataclass, replace, asdict
from collections import deque
import hashlib, json, pathlib, subprocess, sys

@dataclass(frozen=True)
class State:
    remote: bool = True
    leased: bool = False
    sent: bool = False
    wire: int = 0
    volatile: bool = False
    durable: bool = False
    jobs: int = 0
    ack: bool = False
    verified: bool = False
    account_commit: bool = False
    delivered: bool = False
    policy: bool = True
    generation: int = 0
    lease_generation: int = 0
    location: int = 0
    account_online: bool = True
    forwarded: bool = False


def moves(s, mode):
    def event(name, **kw): return name, replace(s, **kw)
    if s.remote and s.policy and not s.leased:
        yield event('lease-current-policy', leased=True, lease_generation=s.generation, sent=False)
    if s.remote and s.leased and s.policy and s.lease_generation == s.generation and s.wire < 2:
        yield event('send-or-retry', wire=s.wire+1, sent=True)
    if s.wire:
        yield event('lose-packet', wire=s.wire-1)
        if s.wire < 2: yield event('duplicate-network-packet', wire=2)
        if s.policy:
            yield event('receive-volatile', wire=s.wire-1, volatile=True)
    if s.volatile:
        yield event('persist-unique-local-job', durable=True, jobs=min(2,s.jobs+1) if mode=='no_dedupe' else 1, volatile=False)
    if s.volatile or s.leased:
        yield event('crash-restart', volatile=False, leased=False, sent=False)
    if s.leased:
        yield event('lease-expiry-retry', leased=False, sent=False)
    if s.durable or (mode=='volatile_ack' and s.volatile):
        yield event('emit-authenticated-custody-receipt', ack=True)
    if mode=='unauth_receipt':
        yield event('accept-forged-custody-receipt', verified=True)
    if mode=='custody_as_delivery' and s.durable:
        yield event('mislabel-custody-as-delivered', delivered=True)
    if s.ack:
        yield event('lose-receipt', ack=False)
        yield event('verify-matching-custody-receipt', verified=True, ack=False)
    # Invalid, old-generation and forged receipts leave state unchanged.
    yield event('reject-forged-or-wrong-message-receipt')
    if s.remote and ((mode=='send_delete' and s.sent) or (mode!='send_delete' and s.verified)):
        yield event('delete-remote', remote=False, leased=False, sent=False)
    if s.account_online and s.durable:
        yield event('account-decrypt-verify-persist', account_commit=True)
    if s.account_commit:
        yield event('authenticated-end-to-end-delivered', delivered=True)
    if s.account_online: yield event('account-offline', account_online=False)
    if not s.account_online: yield event('account-online', account_online=True)
    if s.policy and not s.forwarded:
        yield event('forward-opaque-transit-without-Account-read', forwarded=True)
    if s.policy:
        yield event('revoke-ingress-policy', policy=False, generation=1)
    # A route/address change has no effect on durable payload or stable job ID.
    if s.location == 0: yield event('mobility-address-change', location=1)


def violation(s):
    if not s.remote and not s.wire and not s.volatile and not s.durable:
        return 'custody-lost'
    if s.jobs > 1: return 'duplicate-local-jobs'
    if s.delivered and not s.account_commit: return 'false-delivered'


def explore(mode, depth=12):
    initial=State(); q=deque([(initial,())]); seen={initial}; counterexample=None
    transitions=0; coverage=set(); witnesses={}
    while q:
        s, trace=q.popleft()
        bad=violation(s)
        if bad and counterexample is None: counterexample={'violation':bad,'trace':list(trace),'state':asdict(s)}
        if s.delivered and s.location: witnesses.setdefault('mobility_delivery',list(trace))
        if s.durable and not s.policy: witnesses.setdefault('durable_custody_survives_policy_revoke',list(trace))
        if len(trace)==depth:continue
        for label,nxt in moves(s,mode):
            transitions+=1; coverage.add(label)
            if not s.account_online and label=='forward-opaque-transit-without-Account-read':
                witnesses.setdefault('offline_account_transit',list(trace+(label,)))
            # Invariants on transitions: revoked policy disallows new receive/send;
            # wrong receipts cannot retire remote or announce Account delivery.
            if not s.policy:
                assert label not in ('receive-volatile','send-or-retry','lease-current-policy')
            if label.startswith('reject-'): assert nxt==s
            if nxt not in seen:
                seen.add(nxt); q.append((nxt,trace+(label,)))
    return {'mode':mode,'max_depth':depth,'unique_states':len(seen),'transitions':transitions,'events_explored':sorted(coverage),'first_counterexample':counterexample,'witnesses':witnesses}



@dataclass(frozen=True)
class Handoff:
    application_intent: bool = True
    pending_request: bool = False
    daemon_jobs: int = 0
    reply_in_flight: bool = False
    caller_accepted: bool = False


def explore_handoff(early_reply=False, atomic_unique=True, depth=9):
    initial=Handoff(); seen={initial}; q=deque([(initial,())]); first=None; edges=0
    while q:
        s,trace=q.popleft()
        if (not s.application_intent and not s.daemon_jobs and not s.pending_request and not s.reply_in_flight) or s.daemon_jobs>1:
            if first is None:first={'trace':list(trace),'state':asdict(s)}
        if len(trace)==depth:continue
        events=[]
        def add(label,**kw):events.append((label,replace(s,**kw)))
        if s.application_intent:
            add('submit-same-scoped-operation-id',pending_request=True)
        if s.pending_request:
            add('atomic-persist-or-return-existing-job',daemon_jobs=1 if atomic_unique else min(2,s.daemon_jobs+1),pending_request=False,reply_in_flight=True)
            if early_reply:add('unsafe-reply-before-persist',reply_in_flight=True)
        if s.reply_in_flight:
            add('receive-durable-acceptance',reply_in_flight=False,caller_accepted=True)
            add('lose-IPC-reply',reply_in_flight=False)
        if s.caller_accepted:add('retire-application-transport-intent',application_intent=False)
        add('daemon-crash-restart',pending_request=False,reply_in_flight=False)
        # Conflicting digest is rejected without replacing an accepted job.
        add('reject-conflicting-digest')
        for label,nxt in events:
            edges+=1
            if nxt not in seen:seen.add(nxt);q.append((nxt,trace+(label,)))
    return {'early_reply':early_reply,'atomic_unique':atomic_unique,'max_depth':depth,'unique_states':len(seen),'transitions':edges,'first_counterexample':first}


def main():
    results=[explore(m) for m in ('durable_authenticated','send_delete','volatile_ack','no_dedupe','unauth_receipt','custody_as_delivery')]
    handoff=[explore_handoff(),explore_handoff(early_reply=True),explore_handoff(atomic_unique=False)]
    assert handoff[0]['first_counterexample'] is None
    assert handoff[1]['first_counterexample'] is not None
    assert handoff[2]['first_counterexample'] is not None
    good=results[0]
    assert good['first_counterexample'] is None
    assert set(good['witnesses'])=={'offline_account_transit','mobility_delivery','durable_custody_survives_policy_revoke'}
    assert results[1]['first_counterexample']['violation']=='custody-lost'
    assert results[2]['first_counterexample']['violation']=='custody-lost'
    assert results[3]['first_counterexample']['violation']=='duplicate-local-jobs'
    assert results[4]['first_counterexample']['violation']=='custody-lost'
    assert results[5]['first_counterexample']['violation']=='false-delivered'
    here=pathlib.Path(__file__).resolve(); root=here.parents[4]
    print(json.dumps({'kind':'SPEC MODEL, not product implementation','status':'PASS (expected counterexamples found)',
        'python':sys.version.split()[0], 'source_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
        'script_sha256':hashlib.sha256(here.read_bytes()).hexdigest(), 'results':results, 'local_handoff_results':handoff,
        'assumptions':['Single stable message ID; atomic durable write; storage not destroyed by crash','Perfect symbolic authenticated message-bound receipt; no key compromise','Two in-flight packets; depth 12; state merging; no fairness or unconditional liveness claim','Custody ACK and Account delivery receipt have distinct meanings','Revocation blocks new ingress/send; already durable custody remains available for local processing','Mobility changes transport address only; no native/NAT adaptation is modeled'],
        'limits':['Model verifies proposed stronger custody contract only; current send-then-delete is deliberately modeled as a weaker alternative','No RFC, native runtime, sockets, real signatures, persistence engine or NAT traversal is implemented/tested','Model does not establish all production transit paths are Account-independent']},indent=2))

if __name__=='__main__':main()
