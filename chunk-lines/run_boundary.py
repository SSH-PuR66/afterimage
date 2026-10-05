"""Validate cached release identities and run small offline framing regressions.

No downloads occur here. Place the exact pinned wheels in the cache first.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

HERE=Path(__file__).resolve().parent


def run(cache):
    manifest=json.loads((HERE/'pinned-releases.json').read_text(encoding='utf-8'))
    versions=[]
    for release in manifest['releases']:
        wheel=Path(cache)/release['filename']
        if not wheel.is_file(): raise ValueError('Pinned wheel missing; see README.md')
        if wheel.stat().st_size!=release['size_bytes'] or hashlib.sha256(wheel.read_bytes()).hexdigest()!=release['sha256']:
            raise ValueError('Cached wheel identity mismatch')
        child=subprocess.run([sys.executable,'-I','-S','-B',str(HERE/'boundary_fixture.py'),
            '--wheel',str(wheel.resolve()),'--version',release['version']],
            capture_output=True,text=True,encoding='utf-8',timeout=10)
        if child.returncode: raise RuntimeError(child.stderr or child.stdout)
        versions.append(json.loads(child.stdout))
    sources=('boundary_fixture.py','run_boundary.py','pinned-releases.json','test_boundary.py')
    return {'schema_version':1,'title':'Afterimage / Chunk Lines','cve':manifest['cve'],
        'ghsa':'GHSA-vxq7-64xx-v4gw','classification':'known_cve_bounded_offline_regression',
        'verified_at_utc':datetime.now(timezone.utc).isoformat(),'advisory':manifest['advisory'],
        'upstream_fix':manifest['upstream_fix'],
        'attribution':{'coordinator':'pquentin','remediation_reviewer':'illia-v',
            'portfolio_work':'AI-assisted independent bounded offline regression and presentation'},
        'runtime':{'python':platform.python_version(),'platform':platform.system(),
            'isolated_subprocess':True,'site_packages_disabled':True,'socket_dns_audit_guard':True},
        'method':'Unmodified pinned wheels; real HTTPResponse.stream/read_chunked and http.client response over counted BytesIO files. Fixed fixture budget of 70,000 bytes; no server or network transport.',
        'cases_per_version':16,'total_cases_passed':sum(v['cases_passed'] for v in versions),
        'network_attempts_during_cases':sum(v['network_attempts'] for v in versions),
        'import_network_probes_blocked':sum(len(v['import_network_probes_blocked']) for v in versions),
        'maximum_fixture_input_bytes':max(v['maximum_input_bytes'] for v in versions),'versions':versions,
        'source_sha256':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in sources},
        'limits':['Known published CVE; no new discovery or assignment.',
            'Small in-memory regression of framing behavior, not a memory-exhaustion demonstration.',
            'No real server, network read-ahead, TLS, requests wrapper, decompression, or application exploitability tested.',
            '2.8.0 is fixed for this CVE; that is not a blanket security claim about a release.']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache',type=Path,default=HERE/'.cache'/'wheels')
    parser.add_argument('--output',type=Path,default=HERE/'results.json')
    args=parser.parse_args()
    report=run(args.cache)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'cases_passed':report['total_cases_passed'],
        'network_attempts':report['network_attempts_during_cases'],
        'maximum_fixture_input_bytes':report['maximum_fixture_input_bytes']}))


if __name__=='__main__': main()
