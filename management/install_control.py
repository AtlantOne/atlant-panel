#!/usr/bin/python3 -I
"""Install Atlant Control separately; never restart or rewrite the existing VPN."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import argparse
import getpass
import json
import os

from control.installation import Installer
from atlantctl import AdminError
from control.i18n import language, message


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('plan','install'))
    parser.add_argument('--core-unit',default='atlant_vpn.service')
    parser.add_argument('--agent',required=True,help='Locally verified native Linux certificate-agent binary')
    parser.add_argument('--sha256',required=True,help='Expected SHA-256 from a trusted release')
    parser.add_argument('--port',type=int,default=9090)
    parser.add_argument('--lang',choices=('en','ru','zh'),default=language())
    args=parser.parse_args()
    if sys.platform!='linux' or os.geteuid()!=0:parser.error(message('install_root_required',args.lang))
    installer=Installer(Path(__file__).resolve().parent,args.agent,args.sha256,args.core_unit)
    try:
        plan=installer.preflight();print(json.dumps(installer.public_plan(plan),ensure_ascii=False,indent=2))
        if args.action=='plan':return
        if input(message('install_confirm',args.lang))!='yes':return
        login=input(message('login_prompt',args.lang,default='admin')).strip() or 'admin'
        password=getpass.getpass(message('new_password',args.lang)+': ')
        if password!=getpass.getpass(message('repeat_password',args.lang)+': '):parser.error(message('password_mismatch',args.lang))
        result=installer.install(plan,login,password,args.port,args.lang)
        password=None
        print(json.dumps(result,ensure_ascii=False,indent=2))
    except (AdminError,ValueError,OSError,RuntimeError):
        # Do not print configuration values, subprocess output or API credentials.
        parser.exit(1,message('install_failed',args.lang)+'\n')


if __name__=='__main__':main()
