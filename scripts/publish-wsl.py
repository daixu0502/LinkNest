#!/usr/bin/env python3
"""Publish exact WSL-accepted images, with explicit deployed or release-only mode."""
import argparse
import getpass
import hashlib
import importlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_CHECKS = {
    'go-vet', 'go-race', 'govulncheck', 'binary-build-info', 'browser',
    'kernel-dualstack-source-ip', 'udp-one-way-idle', 'amd64-runtime',
    'arm64-runtime', 'backup-restore', 'rollback-helper', 'full-image-data-rollback',
}


def validate_release(release, stage, source, deployment_path, release_only):
    gate = json.loads((stage / 'accepted.json').read_text(encoding='utf-8'))
    if gate['version'] != release.source_version():
        raise RuntimeError('Accepted release version differs from the source workspace')
    if gate.get('environment') != 'WSL Docker unix:///var/run/docker.sock':
        raise RuntimeError('Local WSL acceptance is required')
    if not REQUIRED_CHECKS <= set(gate.get('checks', [])):
        raise RuntimeError('Required release acceptance checks are missing')
    if set(gate['images']) != {'amd64', 'arm64'}:
        raise RuntimeError('Both accepted architectures are required')
    git = ['git', '-c', 'safe.directory=' + source.as_posix(), '-C', str(source)]
    if release.run(git + ['status', '--porcelain']):
        raise RuntimeError('Use a clean committed source worktree')
    if any(release.source_digest(root) != gate['sourceSHA256'] for root in [ROOT, source]):
        raise RuntimeError('Accepted source, workspace and committed worktree must match')
    for arch, image in gate['images'].items():
        archive = stage / ('candidate-' + arch + '.tar')
        if release.archive_config_id(archive) != image['id']:
            raise RuntimeError('Accepted architecture archive changed: ' + arch)
        if image.get('archiveSHA256') and hashlib.sha256(archive.read_bytes()).hexdigest() != image['archiveSHA256']:
            raise RuntimeError('Accepted archive checksum changed: ' + arch)
    for name, key in [('candidate-arm64.tar', 'archiveSHA256'),
                      ('rollback-helper-arm64.tar', 'helperArchiveSHA256')]:
        if hashlib.sha256((stage / name).read_bytes()).hexdigest() != gate[key]:
            raise RuntimeError('Accepted archive changed: ' + name)
    deployment = None
    if not release_only:
        deployment = json.loads(deployment_path.read_text(encoding='utf-8'))
        if deployment['result'] != 'deployed' or deployment['image'] != gate['images']['arm64']['id']:
            raise RuntimeError('Router verification of this exact candidate is required')
    return gate, git, deployment


def publish(release, args, gate, git, deployment, directory=None):
    proxy = ['env', 'HTTP_PROXY=' + args.registry_proxy, 'HTTPS_PROXY=' + args.registry_proxy] if args.registry_proxy else []
    docker = release.wsl_command(*proxy, 'docker', '--context', 'default')
    if directory:
        docker += ['--config', release.linux_path(directory)]

    def command(*values):
        return release.run(docker + list(values))

    context = json.loads(command('context', 'inspect', 'default'))[0]
    if context['Endpoints']['docker']['Host'] != 'unix:///var/run/docker.sock':
        raise RuntimeError('Only the local WSL Docker socket is allowed')
    if directory:
        token = getpass.getpass('Docker Hub token: ')
        login = subprocess.run(docker + ['login', '-u', 'jacoyyyy', '--password-stdin'],
                               input=(token + '\n').encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        del token
        if login.returncode:
            raise RuntimeError('Docker Hub login failed; no image was published')
    try:
        version = gate['version']
        for arch, image in gate['images'].items():
            before = json.loads(command('image', 'inspect', '--platform', 'linux/' + arch, image['tag']))[0]
            if before['Id'] != image['localID'] or before['Architecture'] != arch:
                raise RuntimeError('Local architecture image differs from accepted image: ' + arch)
            tag = f'{REPOSITORY}:{version}-{arch}'
            command('tag', image['tag'], tag)
            command('push', tag)
            command('pull', '--platform', 'linux/' + arch, tag)
            remote = json.loads(command('image', 'inspect', '--platform', 'linux/' + arch, tag))[0]
            if remote['Id'] != image['localID']:
                raise RuntimeError('Remote architecture image differs from accepted image: ' + arch)
        tag = f'{REPOSITORY}:{version}'
        command('buildx', 'imagetools', 'create', '--tag', tag, tag + '-amd64', tag + '-arm64')
        manifest = json.loads(command('buildx', 'imagetools', 'inspect', tag, '--raw'))
        architectures = {m.get('platform', {}).get('architecture') for m in manifest['manifests']}
        if not {'amd64', 'arm64'} <= architectures:
            raise RuntimeError('Missing published architecture')

        def digest(reference):
            return re.search(r'^Digest:\s+(sha256:[a-f0-9]{64})',
                             command('buildx', 'imagetools', 'inspect', reference), re.M)[1]

        published = digest(tag)
        command('buildx', 'imagetools', 'create', '--tag', REPOSITORY + ':latest', REPOSITORY + '@' + published)
        if digest(REPOSITORY + ':latest') != published:
            raise RuntimeError('latest digest mismatch')
        result = {'version': version, 'digest': published,
                  'sourceCommit': release.run(git + ['rev-parse', 'HEAD']),
                  'sourceSHA256': gate['sourceSHA256'], 'images': gate['images'],
                  'mode': 'release-only' if args.release_only else 'router-verified',
                  'routerImage': deployment['image'] if deployment else None}
        (args.stage / 'published.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        print(json.dumps(result, indent=2))
    finally:
        # Only remove a login created by this invocation; never log out the user.
        if directory:
            subprocess.run(docker + ['logout', 'docker.io'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


REPOSITORY = 'jacoyyyy/linknest'


def main():
    release = importlib.import_module('release-wsl')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stage', type=Path, default=ROOT / '.tools' / ('validation-' + release.source_version()))
    p.add_argument('--registry-proxy', help='HTTP proxy for WSL registry commands, including Buildx')
    p.add_argument('--source-worktree', type=Path, required=True)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--deployment', type=Path, help='Record verifying this exact candidate on the router')
    mode.add_argument('--release-only', action='store_true', help='Publish after full local acceptance without deploying a device')
    p.add_argument('--use-existing-login', action='store_true', help='Use the current WSL Docker login; never read a token from arguments')
    args = p.parse_args()
    args.stage = args.stage.resolve()
    gate, git, deployment = validate_release(release, args.stage, args.source_worktree.resolve(), args.deployment, args.release_only)
    if args.use_existing_login:
        publish(release, args, gate, git, deployment)
    else:
        with tempfile.TemporaryDirectory(prefix='registry-auth-', dir=ROOT / '.tools') as directory:
            assert Path(directory).resolve().parent == ROOT / '.tools'
            publish(release, args, gate, git, deployment, directory)


if __name__ == '__main__':
    main()
