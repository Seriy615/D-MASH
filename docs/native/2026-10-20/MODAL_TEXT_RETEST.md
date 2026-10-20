# Modal text boundary

`a22b2db`, release `.41`, fixes MODAL-TITLE-XSS-01 and related plain-message injection. A stored contact alias reached the incoming-call title through `call_runtime` → `showIncomingCall` → raw modal `<h4>`. The same alias reached rename/delete prompt messages. Titles and customAlert/Prompt/Confirm messages are now literal escaped text; DOM input values preserve the original string. Intentional HTML remains only through the explicit `openModal(title, template)` body contract. Three preescaped callers were corrected to avoid double escaping.

[Evidence](MODAL_TEXT_RETEST.json) distinguishes SOURCE/UNIT from actual UI: hostile alias text appears literally in a real rename prompt with zero inserted images; prompt Cancel and remove confirmation No preserve the test contact, Yes removes it and the completion alert closes normally. The same synthetic Root/Account profile and Saved row remain. The incoming-call title branch is NOT RUN; malicious error/value cases are UNIT only. Other intentional HTML template sinks remain an explicit review backlog.

[Exact immutable full JS run](MODAL_TEXT_ALL_JS.json):160/160PASS, inputs unchanged, Node24.19.0. Raw output stays private off Git. This is not Python/native/physical-platform acceptance.
