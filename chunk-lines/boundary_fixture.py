"""Bounded, socket-free regression of published urllib3 framing limits.

Uses fixed in-memory files and the unmodified wheel's HTTPResponse methods.
There is no server, stress loop, unbounded input source, or memory-exhaustion test.
"""
import argparse
import hashlib
import http.client
from io import BytesIO
import json
from pathlib import Path
import sys
import zipfile

LIMIT=65536
MAX_INPUT=70000
MAX_YIELDS=100
BLOCKED_EVENTS={'socket.__new__','socket.connect','socket.getaddrinfo',
                'socket.gethostbyname','socket.gethostbyaddr'}


def run(wheel,release):
    raw=Path(wheel).read_bytes()
    if len(raw)!=release['size_bytes'] or hashlib.sha256(raw).hexdigest()!=release['sha256']:
        raise ValueError('Wheel size/hash does not match the pinned release')
    with zipfile.ZipFile(wheel) as archive:
        module_hash=hashlib.sha256(archive.read('urllib3/response.py')).hexdigest()
    if module_hash!=release['response_py_sha256']: raise ValueError('Unexpected response module')
    attempts=[]
    def audit(event,args):
        if event in BLOCKED_EVENTS:
            attempts.append(event)
            raise RuntimeError('Network activity is disabled for this fixture')
    sys.addaudithook(audit)
    sys.path.insert(0,str(Path(wheel).resolve()))
    import urllib3
    from urllib3.exceptions import ProtocolError
    from urllib3.response import HTTPResponse
    if urllib3.__version__!=release['version']: raise ValueError('Imported version mismatch')
    if not Path(urllib3.__file__).as_posix().startswith(Path(wheel).resolve().as_posix()+'/'):
        raise ValueError('Imported module did not originate in the pinned wheel')
    # urllib3 checks IPv6 support during import. The guard blocks that socket
    # creation too; record it separately rather than hiding an import attempt.
    import_attempts=list(attempts)
    attempts.clear()
    fixed=release['version']=='2.8.0'

    class CountingFile(BytesIO):
        def __init__(self,data):
            super().__init__(data)
            self.lines=[]
            self.body_reads=[]
        def readline(self,size=-1):
            line=super().readline(size)
            self.lines.append({'requested':size,'returned':len(line)})
            return line
        def read(self,size=-1):
            data=super().read(size)
            self.body_reads.append({'requested':size,'returned':len(data)})
            return data

    class FileSocket:
        def __init__(self,file): self.file=file
        def makefile(self,*args,**kwargs): return self.file

    def sized_line(length):
        # A valid size and ignored extension; total framing length includes CRLF.
        return b'1;p='+b'x'*(length-6)+b'\r\n'

    cases=[
        ('ordinary',b'3\r\nabc\r\n0\r\n\r\n',b'abc',None,None,1),
        ('size_below',sized_line(LIMIT-1)+b'a\r\n0\r\n\r\n',b'a',LIMIT-1,None,1),
        ('size_at',sized_line(LIMIT)+b'a\r\n0\r\n\r\n',b'a',LIMIT,None,1),
        ('size_above',sized_line(LIMIT+1)+b'a\r\n0\r\n\r\n',b'a',LIMIT+1,'size',1),
        ('size_two_above',sized_line(LIMIT+2)+b'a\r\n0\r\n\r\n',b'a',LIMIT+2,'size',1),
        ('trailer_at',b'1\r\na\r\n0\r\nX:'+b'x'*(LIMIT-4)+b'\r\n\r\n',b'a',LIMIT,None,1),
        ('trailer_two_above',b'1\r\na\r\n0\r\nX:'+b'x'*(LIMIT-2)+b'\r\n\r\n',b'a',LIMIT+2,'trailer',1),
        ('body_above_line_limit',b'10001\r\n'+b'b'*(LIMIT+1)+b'\r\n0\r\n\r\n',b'b'*(LIMIT+1),None,None,1024),
    ]
    rows=[]
    for method in ('stream','read_chunked'):
        for name,data,expected,length,reject_kind,amt in cases:
            if len(data)>MAX_INPUT: raise AssertionError('Fixture exceeds fixed input budget')
            fp=CountingFile(data)
            original=http.client.HTTPResponse(FileSocket(fp),method='GET')
            original.chunked=True
            original.chunk_left=None
            original.length=None
            response=HTTPResponse(original,preload_content=False,
                decode_content=False,headers={'transfer-encoding':'chunked'},original_response=original)
            output=bytearray()
            error=None
            try:
                for index,piece in enumerate(getattr(response,method)(amt=amt,decode_content=False)):
                    if index>=MAX_YIELDS: raise AssertionError('Fixture yield budget exceeded')
                    output.extend(piece)
            except ProtocolError as caught:
                error=str(caught)
            should_reject=fixed and reject_kind is not None
            if should_reject:
                assert error is not None and f'chunk {reject_kind} line exceeded maximum allowed length' in error,(name,error)
                if reject_kind=='size':
                    assert output==b'' and fp.body_reads==[],(name,fp.body_reads)
                    assert fp.lines[0]=={'requested':LIMIT+1,'returned':LIMIT+1}
                else:
                    assert output==expected
                    assert fp.lines[-1]=={'requested':LIMIT+1,'returned':LIMIT+1}
                assert fp.closed and original.isclosed() and response.closed
            else:
                assert error is None,(name,error)
                assert output==expected,(name,len(output))
            # Requested body size never substitutes for a framing-line budget.
            assert fp.lines[0]['requested']==(LIMIT+1 if fixed else -1)
            if name.startswith('size_') and not should_reject:
                assert fp.lines[0]['returned']==length
            rows.append({'case':name,'api':method,'passed':True,'input_bytes':len(data),
                'body_read_request_bytes':amt,'framing_line_bytes':length,
                'outcome':'rejected' if error else 'accepted','rejection_kind':reject_kind if error else None,
                'body_bytes_yielded':len(output),'body_bytes_yielded_sha256':hashlib.sha256(output).hexdigest(),
                'first_line':fp.lines[0],'last_line':fp.lines[-1],
                'file_read_bytes_before_end':sum(row['returned'] for row in fp.body_reads),
                'file_closed':fp.closed,'response_closed':response.closed})
    if attempts: raise AssertionError('Fixture attempted network activity')
    return {'version':urllib3.__version__,'wheel_sha256':release['sha256'],
        'response_py_sha256':module_hash,'import_origin_verified':True,'cases_passed':len(rows),
        'network_attempts':len(attempts),'import_network_probes_blocked':import_attempts,
        'maximum_input_bytes':max(row['input_bytes'] for row in rows),
        'cases':rows}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel',type=Path,required=True)
    parser.add_argument('--version',choices=('2.7.0','2.8.0'),required=True)
    args=parser.parse_args()
    manifest=json.loads((Path(__file__).parent/'pinned-releases.json').read_text(encoding='utf-8'))
    release=next(item for item in manifest['releases'] if item['version']==args.version)
    print(json.dumps(run(args.wheel,release)))


if __name__=='__main__': main()
