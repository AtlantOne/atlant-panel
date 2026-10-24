"""Read-only discovery of the configuration actually used by an Atlant process."""
import ipaddress
import json
from pathlib import Path
import re
import hashlib
import shlex
import subprocess


VALUE_FLAGS={'c','config-file','config','sni','addr','transport','path','mode','cert','key','server-key','up-mbps','down-mbps','api-addr','api-secret','loglevel','cmd'}


def flags(argv):
    result={};index=1
    while index<len(argv):
        word=argv[index]
        if not word.startswith('-') or word in {'-','--'}:raise ValueError('Unexpected daemon arguments')
        name,equals,value=word.lstrip('-').partition('=')
        if name=='debug':
            if equals and value not in {'true','false','1','0','t','f','TRUE','FALSE','True','False','T','F'}:raise ValueError('Invalid debug flag')
        elif name in VALUE_FLAGS:
            if not equals:
                index+=1
                if index>=len(argv):raise ValueError('Missing daemon flag value')
                value=argv[index]
            result[name]=value
        else:raise ValueError('Unrecognized daemon flag')
        index+=1
    if result.get('config') or result.get('cmd'):raise ValueError('URL/one-shot configuration cannot be managed as a daemon file')
    return result


def derive(argv,cwd,executable):
    options=flags(argv)
    explicit=options.get('c') or options.get('config-file')
    if explicit:
        path=Path(explicit)
        config=path if path.is_absolute() else Path(cwd)/path
    else:
        candidates=[Path(directory)/name for directory in (cwd,Path(executable).parent) for name in ('config.json','server_config.json')]
        config=next((path for path in candidates if path.is_file()),None)
        if config is None:raise ValueError('No active configuration file discovered')
    if not config.is_file() or config.is_symlink():raise ValueError('Active configuration must be a regular non-linked file')
    overrides=[]
    for flag,key in [('sni','sni'),('up-mbps','up_mbps'),('down-mbps','down_mbps')]:
        value=options.get(flag,'')
        if flag.endswith('mbps'):
            if value and (not value.isascii() or not value.isdigit()):raise ValueError('Invalid speed override')
            value=int(value or 0)
        if value:overrides.append(key)
    return {'config':str(config.resolve()),'binary':str(Path(executable).resolve()),'cwd':str(Path(cwd).resolve()),'overridden_fields':overrides},options


def unit_definition(unit,run=subprocess.run):
    result=run(['/usr/bin/systemctl','cat',unit],capture_output=True,text=True,timeout=10,check=False)
    if result.returncode or not result.stdout or len(result.stdout.encode())>1024*1024:raise ValueError('Service definition unavailable or too large')
    return result.stdout,hashlib.sha256(result.stdout.encode()).hexdigest()


def definition_command(text):
    section='';commands=[];cwd='/'
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith(('#',';')):continue
        if line.startswith('[') and line.endswith(']'):section=line;continue
        if section!='[Service]':continue
        key,equals,value=line.partition('=')
        if not equals or key.strip() not in {'ExecStart','WorkingDirectory'}:continue
        value=value.strip()
        if any(char in value for char in ('\\','$','%')):raise ValueError('Expanded or continued service commands require explicit migration')
        if key.strip()=='WorkingDirectory':
            if not value.startswith('/'):raise ValueError('Literal service working directory required')
            cwd=value
        elif not value:commands=[]
        else:commands.append(shlex.split(value))
    if len(commands)!=1 or not commands[0] or not commands[0][0].startswith('/'):raise ValueError('A single literal native ExecStart is required')
    return commands[0],cwd


def inspect_unit(unit,run=subprocess.run,proc=Path('/proc')):
    if not isinstance(unit,str) or not re.fullmatch(r'atlant[-_A-Za-z0-9]*\.service',unit):raise ValueError('Only an Atlant unit can be inspected')
    definition,fingerprint=unit_definition(unit,run)
    declared,working_directory=definition_command(definition)
    status=run(['/usr/bin/systemctl','show',unit,'--property=MainPID','--value'],capture_output=True,text=True,timeout=10,check=False)
    if status.returncode or not status.stdout.strip().isdigit() or int(status.stdout.strip())<1:raise ValueError('Atlant must be running for verified discovery')
    pid=int(status.stdout.strip());process=proc/str(pid)
    before=(process/'stat').read_bytes()
    with (process/'cmdline').open('rb') as stream:raw=stream.read(65537)
    if len(raw)>65536:raise ValueError('Daemon command line too large')
    argv=raw.rstrip(b'\0').decode('utf-8').split('\0')
    cwd=(process/'cwd').resolve(strict=True);executable=(process/'exe').resolve(strict=True)
    if argv!=declared or cwd!=Path(working_directory).resolve() or executable!=Path(declared[0]).resolve():raise ValueError('Running process and service definition differ')
    result,options=derive(argv,cwd,executable)
    config=Path(result['config'])
    if config.stat().st_size>1024*1024:raise ValueError('Core configuration too large')
    data=json.loads(config.read_text(encoding='utf-8'))
    if not isinstance(data,dict):raise ValueError('Invalid core configuration')
    address=options.get('api-addr') or data.get('api_addr') or '127.0.0.1:8080'
    host,colon,port=address.rpartition(':')
    if not colon or not port.isascii() or not port.isdigit() or not 1<=int(port)<=65535 or not ipaddress.ip_address(host.strip('[]')).is_loopback:
        raise ValueError('Core API must use a literal loopback address')
    secret=options.get('api-secret') or data.get('api_secret')
    if not isinstance(secret,str) or not secret or len(secret)>4096:raise ValueError('Core API authentication is required')
    if (process/'stat').read_bytes().rsplit(b')',1)[-1].split()[19] != before.rsplit(b')',1)[-1].split()[19]:raise ValueError('Daemon restarted during inspection')
    if unit_definition(unit,run)[1]!=fingerprint:raise ValueError('Service definition changed during inspection')
    result.update(pid=pid,unit=unit,definition=fingerprint,api_url='http://'+address,api_key=secret)
    return result


def public_runtime(result):
    return {key:value for key,value in result.items() if key!='api_key'}
