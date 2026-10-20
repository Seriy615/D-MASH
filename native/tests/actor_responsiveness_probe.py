"""Measure actual isolated owner RPC and primitive time without changing deadlines.
Synthetic profile only. Primitive records contain durations, never key material.
Usage: python actor_responsiveness_probe.py HOST PRIVATE_CACHE
"""
import json, os, pathlib, secrets, sys, tempfile, time
from ipc_delivery_test import mine, material, bind, RPC_TIMINGS
from local_ipc_test import start


def main():
    binary,cache=sys.argv[1:];os.environ['DMASH_NATIVE_BENCH']='1'
    key=mine()
    bundle=dict(version=1,nodeSeed=key.encode().hex(),storageKey=secrets.token_hex(32),baseNcrh=secrets.token_hex(32),generation=1,directEnabled=False,endpoints=[])
    with tempfile.TemporaryDirectory(prefix='responsiveness-',dir=cache) as folder:
        profile=pathlib.Path(folder);profile.chmod(0o700)
        process,boot,ready=start(binary,profile,bundle);connection=None
        try:
            began=time.monotonic();connection=bind(ready,material());elapsed=(time.monotonic()-began)*1000
        finally:
            if connection:connection.close()
            process.terminate();process.wait(timeout=10);boot.close();out,err=process.communicate()
        assert process.returncode==0
        timings={}
        for line in out.splitlines():
            event=json.loads(line)
            if event.get('event')=='benchmark-primitive':timings.setdefault(event['primitive'],[]).append(event['elapsedMs'])
        assert timings,'benchmark instrumentation missing'
        print(json.dumps(dict(suite='native-owner-responsiveness-probe',ownerRpcElapsedMs=round(elapsed),rpcTimings=RPC_TIMINGS,primitiveTimings={name:dict(count=len(values),totalMs=round(sum(values)),maxMs=max(values)) for name,values in timings.items()},mesh='NOT_RUN',unchangedSocketDeadlineSeconds=5)))


if __name__=='__main__':main()
