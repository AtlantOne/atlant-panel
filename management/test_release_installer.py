import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ASSET=Path(os.environ.get('ATLANT_CORE_SOURCE',str(Path(__file__).resolve().parents[1])))/'client/remoteadmin/assets/install.py'
if not ASSET.is_file():raise unittest.SkipTest('Installer integration tests require an Atlant core checkout (ATLANT_CORE_SOURCE)')
spec=importlib.util.spec_from_file_location('release_installer',ASSET)
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)

class ReleaseInstallerTests(unittest.TestCase):
    def package(self,name='bin/atlant-server',content=b'ELF'):
        output=io.BytesIO()
        with zipfile.ZipFile(output,'w') as archive:archive.writestr(name,content)
        return output.getvalue()
    def scenario(self,content):
        name='atlant-core-linux-amd64.zip';base='https://github.com/AtlantOne/atlant-core/releases/download/v1/'
        checksum=hashlib.sha256(content).hexdigest()
        metadata={'tag_name':'v1','assets':[{'name':n,'browser_download_url':base+n} for n in (name,'SHA256SUMS')]}
        def fetch(url,limit):
            if url.endswith('/releases/latest'):return json.dumps(metadata).encode()
            if url.endswith('/SHA256SUMS'):return (checksum+'  '+name+'\n').encode()
            if url.endswith(name):return content
            self.fail('Unexpected source download: '+url)
        return fetch
    def test_release_download_checks_checksum_and_extracts_binary(self):
        package=self.package()
        with tempfile.TemporaryDirectory() as folder,patch.object(installer,'download',side_effect=self.scenario(package)):
            target=Path(folder)/'release'
            self.assertEqual('v1',installer.release('core','amd64',target))
            self.assertEqual(b'ELF',(target/'bin/atlant-server').read_bytes())
    def test_checksum_and_traversal_rejected(self):
        for malicious in (False,True):
            content=self.package('../escape' if malicious else 'bin/atlant-server')
            fetch=self.scenario(content)
            def corrupt(url,limit):return b'tampered' if not malicious and url.endswith('.zip') else fetch(url,limit)
            with tempfile.TemporaryDirectory() as folder,patch.object(installer,'download',side_effect=corrupt):
                with self.assertRaises(ValueError):installer.release('core','amd64',Path(folder)/'release')
    def test_cpu_detection_and_elf_validation(self):
        self.assertEqual('amd64',installer.architecture('x86_64'));self.assertEqual('arm64',installer.architecture('aarch64'))
        with self.assertRaises(ValueError):installer.architecture('riscv64')
        header=bytearray(20);header[:6]=b'\x7fELF\x02\x01';header[18:20]=(62).to_bytes(2,'little')
        with tempfile.TemporaryDirectory() as folder:
            binary=Path(folder)/'binary';binary.write_bytes(header)
            installer.verify_binary(binary,'amd64')
            with self.assertRaises(ValueError):installer.verify_binary(binary,'arm64')
    def test_install_never_invokes_compiler_or_docker_build(self):
        source=ASSET.read_text()
        self.assertNotIn("['docker','build'",source)
        self.assertNotIn("source('core'",source)
        args=installer.container_args(PurePosixPath('/data'), 'python:3.14-slim-bookworm',program=PurePosixPath('/release'))
        self.assertIn('--read-only',args);self.assertIn('0:0',args)
        self.assertEqual(['NET_BIND_SERVICE','SETUID','SETGID'],[args[i+1] for i,v in enumerate(args[:-1]) if v=='--cap-add'])
        self.assertIn('type=bind,src=/release/bin/atlant-server,dst=/usr/local/bin/atlant-server,readonly',args)
        self.assertNotIn('type=bind,src=/release/bin,dst=/usr/local/bin,readonly',args)

if __name__=='__main__':unittest.main()
