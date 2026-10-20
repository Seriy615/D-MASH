"""Linux CLI input validation; synthetic files, never a broker/profile reset."""
import os,pathlib,subprocess,sys,tempfile
binary=pathlib.Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='dmash-cli-boundary-') as name:
    root=pathlib.Path(name);profile=root/'unopened-profile';target=root/'input'
    target.write_bytes(b'{}');target.chmod(0o600)
    def reject(path):
        run=subprocess.run([str(binary),'--profile',str(profile),'--bundle',str(path),'--run-for','1'],capture_output=True,timeout=5)
        assert run.returncode==1,(path.name,run.returncode)
        assert not profile.exists(),path.name
    target.chmod(0o644);reject(target);target.chmod(0o600)
    link=root/'symlink';link.symlink_to(target);reject(link)
    fifo=root/'fifo';os.mkfifo(fifo,0o600);reject(fifo)
    target.write_bytes(b'x'*65537);reject(target)
    target.write_bytes(b'{"Root":"forbidden"}');reject(target)
    target.write_bytes(b'{"x":"\xff"}');reject(target)
print('CLI descriptor owner/mode/nofollow/regular-file/rawcap/invalidJSON rejection PASS')
