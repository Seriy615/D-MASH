# Frozen Account binding component replay

Author two-client30627 and worker/retained57941 exited0. First harness79305
exited1 at an unordered cross-socket login/cancel assertion; original private
profile is retained and its response code was not captured. The corrected test
observes accepted selection before injecting another connection's Cancel.
Product binary and deadlines were unchanged. Do not claim a diagnosed product
failure from the first assertion.

Source717a734 and both tested binaries are frozen under
`~/.cache/dmash-native-20261020/checkpoints/account-client-binding-candidate01`.
Check its manifest hashes before execution. It includes all source, binary and
runtime-library hashes, the private build wrapper and exact reused QuickJS
archive/header hashes. The retained C++ test's compiled fixture absolute path is
listed in buildDependencies; verify it equals the archived fixture before run.

```sh
TC=/home/jcode/.cache/dmash-native-20261020
PIN="$TC/checkpoints/account-client-binding-candidate01"
export LD_LIBRARY_PATH="$TC/Qt/6.12.0/gcc_64/lib:$TC/build/openssl-3.5.9"
/home/jcode/.cache/dmash-tools/python-s03-20261020/bin/python \
  "$PIN/source/native/credential_host/tests/account_client_binding_test.py" \
  "$PIN/dmash-credential-host" "$TC/private"
"$PIN/dmash_account_service_test"
```

Each two-client run creates a new private synthetic owning profile, preserves it
on success/failure, and never resets an accepted profile. This proves component
IPC and worker behavior. Actual Telegram adapters/UI still require integration
and their own real controls/reconnect acceptance.
