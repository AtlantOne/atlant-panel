"""Package only management sources, public docs and a verified certificate agent."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import subprocess
import zipfile

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'management'))
from control.installation import check_agent, source_files


def licenses(agent,core_source=ROOT):
    result=subprocess.run(['go','version','-m',str(Path(agent).resolve())],cwd=core_source/'shared',capture_output=True,text=True,check=True,timeout=15)
    environment=subprocess.run(['go','env','-json','GOROOT','GOMODCACHE','GOVERSION'],cwd=core_source/'shared',capture_output=True,text=True,check=True,timeout=15)
    environment=json.loads(environment.stdout)
    if environment['GOVERSION'] not in result.stdout.splitlines()[0]:raise ValueError('Use the agent build toolchain to collect its Go license')
    files={Path('THIRD_PARTY_LICENSES/Go/LICENSE'):Path(environment['GOROOT'])/'LICENSE'}
    patents=Path(environment['GOROOT'])/'PATENTS'
    if patents.is_file():files[Path('THIRD_PARTY_LICENSES/Go/PATENTS')]=patents
    for line in result.stdout.splitlines():
        parts=line.split()
        if not parts or parts[0]!='dep':continue
        module,version=parts[1:3]
        if not module or version.startswith('(') or any(value in module for value in ('..','\\')):raise ValueError('Unresolved binary dependency')
        escaped=''.join('!'+char.lower() if char.isupper() else char for char in module)
        folder=Path(environment['GOMODCACHE'])/(escaped+'@'+version)
        found=[path for path in folder.iterdir() if path.is_file() and path.name.upper().startswith(('LICENSE','COPYING','NOTICE','PATENTS'))]
        if not found:raise ValueError('Dependency license files unavailable')
        for path in found:files[Path('THIRD_PARTY_LICENSES')/module/path.name]=path
    return files


def package(agent,digest,architecture,destination,core_source=ROOT):
    core_source=Path(core_source).resolve()
    if not (core_source/'shared/go.mod').is_file() or not (core_source/'LICENSE').is_file():
        raise ValueError('Use --core-source to select the matching atlant-core source checkout')
    check_agent(agent,digest,{'amd64':'x86_64','arm64':'aarch64'}[architecture])
    destination=Path(destination)
    if destination.exists():raise ValueError('Release destination already exists')
    files={Path('management')/relative:ROOT/'management'/relative for relative in source_files(ROOT/'management')}
    for name in ['LICENSE','THIRD_PARTY_NOTICES.md','docs/CONTROL_INSTALL_RU.md','docs/CERTIFICATE_AGENT_RU.md','docs/SERVICE_HELPER_RU.md','docs/ACME_SHARED_PORT_RU.md']:
        files[Path(name)]=ROOT/name
    files[Path('LICENSE')]=ROOT/'management/LICENSE'
    files[Path('CORE-APACHE-2.0-LICENSE')]=core_source/'LICENSE'
    files[Path('NOTICE')]=ROOT/'NOTICE'
    files[Path('LICENSING.md')]=ROOT/'LICENSING.md'
    files[Path('atlant-cert-agent')]=Path(agent)
    files.update(licenses(agent,core_source))
    manifest={str(name).replace('\\','/'):hashlib.sha256(path.read_bytes()).hexdigest() for name,path in files.items()}
    destination.parent.mkdir(parents=True,exist_ok=True)
    candidate=destination.with_suffix(destination.suffix+'.part')
    if candidate.exists():raise ValueError('A partial release already exists')
    try:
        with zipfile.ZipFile(candidate,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
            for name,path in sorted(files.items(),key=lambda pair:str(pair[0])):
                if path.is_symlink() or not path.is_file():raise ValueError('Linked or missing release input')
                info=zipfile.ZipInfo(str(name).replace('\\','/'))
                info.create_system=3;info.external_attr=(0o100755 if name==Path('atlant-cert-agent') else 0o100644)<<16
                archive.writestr(info,path.read_bytes(),compress_type=zipfile.ZIP_DEFLATED)
            archive.writestr('RELEASE-MANIFEST.json',json.dumps({'architecture':architecture,'files':manifest},indent=2))
        with zipfile.ZipFile(candidate) as archive:
            for name,digest in manifest.items():
                if hashlib.sha256(archive.read(name)).hexdigest()!=digest:raise ValueError('Packaged file digest mismatch')
        candidate.rename(destination)
    except BaseException:
        candidate.unlink(missing_ok=True)
        raise
    return {'archive':str(destination),'sha256':hashlib.sha256(destination.read_bytes()).hexdigest(),'files':len(files),
            'kind':'development-install-candidate','deployed':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent',required=True,type=Path)
    parser.add_argument('--sha256',required=True)
    parser.add_argument('--architecture',choices=('amd64','arm64'),required=True)
    parser.add_argument('--destination',required=True,type=Path)
    parser.add_argument('--core-source',type=Path,default=ROOT,help='Matching atlant-core checkout for agent licenses')
    args=parser.parse_args()
    print(json.dumps(package(args.agent,args.sha256,args.architecture,args.destination,args.core_source),indent=2))


if __name__=='__main__':main()
