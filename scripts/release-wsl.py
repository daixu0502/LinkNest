#!/usr/bin/env python3
"""Build and accept a release using only the local WSL Docker daemon.

Run from Windows or its mounted source directory in WSL. Local test sources
and Playwright modules are prerequisites;
they deliberately do not ship in the source repository. No production changes.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
GO = "golang:1.26.10-bookworm"
BROWSER = "mcr.microsoft.com/playwright:v1.62.1-noble"

def source_version():
    return re.search(r'version\s*=\s*"([^"]+)"', (ROOT/"internal/app/config.go").read_text(encoding="utf-8"))[1]

def run(argv, log=None):
    if log:
        with log.open("w", encoding="utf-8") as out:
            p = subprocess.run(list(map(str, argv)), stdout=out, stderr=subprocess.STDOUT)
        if p.returncode:
            raise RuntimeError(f"Command failed; see {log}")
        return ""
    return subprocess.check_output(list(map(str, argv)), stderr=subprocess.STDOUT).decode("utf-8").strip()

def source_digest(root=ROOT):
    names = run(["git", "-c", "safe.directory="+root.as_posix(), "-C", root,
                 "ls-files", "-z", "--cached", "--others", "--exclude-standard"]).split("\0")
    digest = hashlib.sha256()
    names=sorted(set(n for n in names if n and (root/n).is_file()))
    # Honor Git's text/CRLF normalization so a clean release worktree and the
    # Windows source workspace refer to the same committed source content.
    hashes=subprocess.check_output(['git','-c','safe.directory='+root.as_posix(),'-C',str(root),'hash-object','--stdin-paths'],input=('\n'.join(names)+'\n').encode(),stderr=subprocess.PIPE,cwd=root).decode().splitlines()
    if len(hashes)!=len(names):raise RuntimeError('Source hash inventory mismatch')
    for name,blob in zip(names,hashes):digest.update(name.encode()+b'\0'+blob.encode()+b'\0')
    return digest.hexdigest()

def wsl_command(*values):
    return (["wsl.exe", "--exec"] if os.name == "nt" else []) + list(values)

def linux_path(value):
    resolved = Path(value).resolve()
    return run(wsl_command("wslpath", "-u", resolved)) if os.name == "nt" else str(resolved)

def archive_config_id(file):
    # Docker 29's containerd image store exposes a manifest digest as Id, while
    # Docker 19 on the router identifies images by the configuration digest.
    with tarfile.open(file) as archive:
        manifests=json.load(archive.extractfile('manifest.json'))
        if len(manifests)!=1:raise RuntimeError('Expected one exported platform')
        config=archive.extractfile(manifests[0]['Config']).read()
        return 'sha256:'+hashlib.sha256(config).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-modules", type=Path, required=True)
    parser.add_argument("--debian-mirror", default="http://mirrors.aliyun.com")
    parser.add_argument("--goproxy", default="https://goproxy.cn,direct")
    parser.add_argument("--proxy", help="HTTP proxy for the vulnerability database")
    args = parser.parse_args()
    if os.name != "nt" and not ROOT.as_posix().startswith("/mnt/"):
        raise SystemExit("Run from the Windows source workspace or its /mnt/ WSL mount")
    for name in ["internal/app/reliability120_test.go", "scripts/test-reliability.cjs", "scripts/smoke-release.py", ".tools/kernel-qa.Dockerfile", ".tools/test-forward-netns.py", ".tools/test-deploy120.py"]:
        if not (ROOT/name).is_file():
            raise SystemExit("Missing required local acceptance file: "+name)
    version = source_version()
    stage = ROOT/".tools"/("validation-"+version)
    stage.mkdir(parents=True, exist_ok=True)
    gate = stage/"accepted.json"
    if gate.exists():
        gate.unlink()  # A failed new run must never leave a previous pass usable.
    docker = wsl_command("docker", "--context", "default")
    context = json.loads(run(docker+["context", "inspect", "default"]))[0]
    if context["Endpoints"]["docker"]["Host"] != "unix:///var/run/docker.sock":
        raise SystemExit("Only the local WSL Docker socket is allowed")
    source = source_digest()
    root = linux_path(ROOT)
    mount = ["--mount", f"type=bind,source={root},target=/src", "-w", "/src"]
    cache = ["--mount", f"type=bind,source={root}/.tools/cache/go/pkg/mod,target=/go/pkg/mod", "-v", "linknest-go-build:/root/.cache/go-build"]
    print("WSL Go vet / race tests", flush=True)
    run(docker+["run", "--rm", *mount, *cache, "-e", "GOPROXY=off", "-e", "GORACE=atexit_sleep_ms=0", GO, "sh", "-ec", "go vet ./...; go test -race ./..."], stage/"go.log")
    print("WSL official Go vulnerability check", flush=True)
    proxy = ["-e", "HTTP_PROXY="+args.proxy, "-e", "HTTPS_PROXY="+args.proxy] if args.proxy else []
    run(docker+["run", "--rm", *mount, *cache, *proxy, "-e", "GOPROXY="+args.goproxy, GO, "go", "run", "golang.org/x/vuln/cmd/govulncheck@v1.9.0", "./..."], stage/"security.log")
    print("WSL browser acceptance", flush=True)
    run(docker+["run", "--rm", "--network", "none", *mount, "--mount", f"type=bind,source={linux_path(args.node_modules)},target=/modules,readonly", "-e", "NODE_PATH=/modules", "-e", "LINKNEST_QA_OUTPUT=/src/.tools/validation-"+version, BROWSER, "sh", "-ec", 'for f in web/*.js; do node --check "$f"; done; for f in scripts/test-*.mjs scripts/test-*.cjs; do node "$f"; done'], stage/"browser.log")
    run(docker+["run", "--privileged", "--rm", "tonistiigi/binfmt:latest", "--install", "arm64"], stage/"binfmt.log")
    print("WSL isolated kernel and UDP runtime acceptance", flush=True)
    module_command = (["wsl.exe", "--user", "root", "--exec"] if os.name == "nt" else (["sudo", "-n"] if os.geteuid() else [])) + ["bash", "-c", "exec -a modprobe /usr/bin/kmod ip6table_nat"]
    run(module_command, stage/"kernel-module.log")
    run(docker+["build", "-f", root+"/.tools/kernel-qa.Dockerfile", "-t", "linknest-kernel-qa:local", root+"/.tools"], stage/"kernel-build.log")
    run(docker+["run", "--rm", "--privileged", "--network", "none", *mount, *cache, "-e", "GOPROXY=off", "linknest-kernel-qa:local", "sh", "-ec", "go test -c -o .tools/forward-tests-linux-amd64 ./internal/app; python3 .tools/test-forward-netns.py; LINKNEST_LONG_NETWORK_QA=1 go test -run '^TestUDPUnidirectionalKeepsSession$' -v ./internal/app"], stage/"network.log")
    created = datetime.now(timezone.utc).isoformat()
    images = {}
    for arch in ["amd64", "arm64"]:
        tag = f"linknest:{version}-candidate-{arch}"
        print("Building and accepting "+tag, flush=True)
        run(docker+["build", "--platform", "linux/"+arch, "--build-arg", "GOPROXY="+args.goproxy, "--build-arg", "DEBIAN_MIRROR="+args.debian_mirror, "--build-arg", "VERSION="+version, "--build-arg", "BUILD_DATE="+created, "--build-arg", "SOURCE_REVISION="+source, "-t", tag, root], stage/(arch+"-build.log"))
        info = json.loads(run(docker+["image", "inspect", "--platform", "linux/"+arch, tag]))[0]
        if info["Architecture"] != arch or info["Size"] > 64*1024*1024:
            raise RuntimeError("Unexpected architecture or oversized runtime")
        run(docker+["run", "--rm", "--network", "host", *mount, "--mount", "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock", "--mount", "type=bind,source=/usr/bin/docker,target=/usr/bin/docker,readonly", BROWSER, "python3", "scripts/smoke-release.py", "--image", tag, "--version", version, "--arch", arch], stage/(arch+"-smoke.log"))
        exported=stage/("candidate-"+arch+".tar")
        run(docker+["image","save","--platform","linux/"+arch,"-o",linux_path(exported),tag])
        images[arch] = {"tag": tag, "id": archive_config_id(exported), "localID":info["Id"], "bytes": info["Size"], "archiveSHA256": hashlib.sha256(exported.read_bytes()).hexdigest()}
        container = run(docker+["create", "--platform", "linux/"+arch, "--label", "linknest.test=true", tag])
        binary = stage/("linknest-"+arch)
        try:
            run(docker+["cp", container+":/usr/local/bin/linknest", linux_path(binary)])
        finally:
            run(docker+["rm", container])
        build_info = stage/(arch+"-build-info.log")
        run(docker+["run", "--rm", *mount, GO, "go", "version", "-m", "/src/.tools/validation-"+version+"/linknest-"+arch], build_info)
        if "go1.26.10" not in build_info.read_text(encoding="utf-8").splitlines()[0]:
            raise RuntimeError("Candidate Go compiler version mismatch")
    if source_digest() != source:
        raise RuntimeError("Source changed during acceptance; rerun before deploying")
    archive = stage/"candidate-arm64.tar"
    run(docker+["pull", "--platform", "linux/arm64", "busybox:1.37"], stage/"rollback-helper.log")
    helper=json.loads(run(docker+["image","inspect","--platform","linux/arm64","busybox:1.37"]))[0]
    if helper["Architecture"]!="arm64":raise RuntimeError("Rollback helper architecture mismatch")
    run(docker+["run","--rm","--network","none","--platform","linux/arm64","busybox:1.37","sh","-ec","test $(uname -m) = aarch64; mkdir -p /tmp/restore; touch /tmp/restore/old; find /tmp/restore -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +; test ! -e /tmp/restore/old"],stage/"rollback-helper-runtime.log")
    helper_archive=stage/"rollback-helper-arm64.tar"
    run(docker+["image","save","--platform","linux/arm64","-o",linux_path(helper_archive),"busybox:1.37"])
    run(docker+["run","--rm","--network","host",*mount,"--mount","type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock","--mount","type=bind,source=/usr/bin/docker,target=/usr/bin/docker,readonly","-e","SOURCE_HOST_PATH="+root,BROWSER,"python3",".tools/test-deploy120.py"],stage/"rollback-drill.log")
    if source_digest()!=source:raise RuntimeError('Source changed during final rollback validation')
    result = {"version": version, "sourceSHA256": source, "validatedAt": created,
              "environment": "WSL Docker unix:///var/run/docker.sock", "images": images,
              "archiveSHA256": hashlib.sha256(archive.read_bytes()).hexdigest(),
              "helperID":archive_config_id(helper_archive),"helperLocalID":helper["Id"],"helperArchiveSHA256":hashlib.sha256(helper_archive.read_bytes()).hexdigest(),
              "checks": ["go-vet", "go-race", "govulncheck", "binary-build-info", "browser", "kernel-dualstack-source-ip", "udp-one-way-idle", "amd64-runtime", "arm64-runtime", "backup-restore", "rollback-helper", "full-image-data-rollback"]}
    gate.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
