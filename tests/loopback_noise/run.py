#!/usr/bin/env python3
"""Local TCP+RFC6455+Noise fixture, never a WhatsApp service or account."""
import argparse, base64, hashlib, json, os, re, socket, struct
import subprocess, tempfile, threading, time
from pathlib import Path
HERE = Path(__file__).resolve().parent
# Independent deterministic vectors from Mesa tests/whatsapp/connection.odin,
# pinned Baileys6.7.23/Node crypto transcript; these are public synthetic inputs.
REF = {
'hello':'12220a2007a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c',
'server':(
    '1a6c0a20883186b800b41d5cf0429695da9b3cc4f328ebcd184a6e482fa578c1'
    '03f06c7712305c99cd811daad2ae49577362c2af503eb36b54716c7e191e196f'
    '5da974163e0d243675d84f8e03ca39d132d2469772261a16f2adf7b37369f19e'
    '094e3d124227e1f7b467fe4812a0'
),
'finish':(
    '224b0a30c2946d59869cef656ad49144b22300176f2a8af4956368391c7ff70e'
    'a6407a9b1dc97abdf21e78b2b5cd2807973594661217ed5d546bad8951d6940e'
    '7751154157c3cd462cb2641256'
),
'from_server':'3fb459b295aaad45a12352039487bf812f2f0929a54798f45cdb9c',
'from_client':'82490f0a4517fedd40fca7298c342f667e38820ec7726cccb09fe9',
}
REF = {key:bytes.fromhex(value) for key,value in REF.items()}

def exact(peer, count):
    body = b''
    while len(body) < count:
        chunk = peer.recv(count-len(body))
        assert chunk, 'unexpected EOF'
        body += chunk
    return body

def read_frame(peer):
    first, second = exact(peer,2)
    count = second & 127
    if count == 126: count = struct.unpack('!H',exact(peer,2))[0]
    elif count == 127: count = struct.unpack('!Q',exact(peer,8))[0]
    assert first & 0x80 and first & 0x70 == 0
    assert second & 128 and count <= 4096
    mask = exact(peer,4)
    body = exact(peer,count)
    return first & 15, bytes(byte ^ mask[index%4] for index,byte in enumerate(body))

def frame(body):
    prefix = bytes([0x82,len(body)]) if len(body)<126 else b'\x82\x7e'+struct.pack('!H',len(body))
    return prefix + body

def peer_loop(listener, mode, result):
    try:
        peer,_ = listener.accept()
        with peer:
            peer.settimeout(3)
            header = b''
            while not header.endswith(b'\r\n\r\n'):
                assert len(header)<4096
                header += exact(peer,1)
            key = re.search(rb'Sec-WebSocket-Key: ([^\r]+)',header,re.I)[1]
            accept = base64.b64encode(hashlib.sha1(key+b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
            peer.sendall(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+accept+b'\r\n\r\n')
            opcode,hello = read_frame(peer)
            assert opcode==2 and hello[:7]==b'WA\x06\x03'+len(REF['hello']).to_bytes(3,'big')
            assert hello[7:]==REF['hello']
            wire = frame(len(REF['server']).to_bytes(3,'big')+REF['server'])
            if mode=='eof':
                partial = len(REF['server']).to_bytes(3,'big')+REF['server'][:2]
                peer.sendall(frame(partial)); return
            if mode=='timeout': peer.sendall(wire[:5]); time.sleep(.5); return
            for index in range(0,len(wire),5):
                peer.sendall(wire[index:index+5]); time.sleep(.001)
            opcode,finish = read_frame(peer)
            assert opcode==2 and finish[:3]==len(REF['finish']).to_bytes(3,'big')
            assert finish[3:]==REF['finish']
            message = REF['from_server']
            peer.sendall(frame(len(message).to_bytes(3,'big')+message))
            opcode,sent = read_frame(peer)
            assert opcode==2 and sent[:3]==len(REF['from_client']).to_bytes(3,'big')
            assert sent[3:]==REF['from_client']
            peer.sendall(b'\x88\x02\x03\xe8')
            read_frame(peer)
    except BaseException as error:
        result.append(repr(error))
    finally:
        listener.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--odin', type=Path, required=True)
    parser.add_argument('--shared-root', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--sanitize', choices=['address','thread','none'],default='address')
    args = parser.parse_args()
    sources = [HERE, args.shared_root/'whatsapp',args.shared_root/'surf',args.shared_root/'http',
               args.shared_root/'websocket',args.shared_root/'async']
    def snapshot():
        return {str(p):hashlib.sha256(p.read_bytes()).hexdigest()
                for source in sources for p in source.rglob('*')
                if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts}
    before = snapshot()
    report = dict(passed=False,source_before=before,modes=[],commands=[],
                  certificate_policy="explicit Baileys issuer-only compatibility; not strict qualification",
                  compiler_sha256=hashlib.sha256(args.odin.read_bytes()).hexdigest(),
                  compiler_version=subprocess.check_output([str(args.odin),'version'],text=True).strip(),
                  compiler_root=subprocess.check_output([str(args.odin),'root'],text=True).strip())
    try:
        with tempfile.TemporaryDirectory(prefix='wa-noise-loopback-') as tmp:
            binary = Path(tmp)/'client'
            command = [str(args.odin),'build',str(HERE),'-collection:shared='+str(args.shared_root),
                       '-out:'+str(binary),'-vet','-warnings-as-errors','-thread-count:1']
            if args.sanitize!='none': command.append('-sanitize:'+args.sanitize)
            compiled = subprocess.run(command,text=True,capture_output=True,timeout=120)
            report['commands'].append(dict(command=command,returncode=compiled.returncode,
                                          stdout=compiled.stdout,stderr=compiled.stderr))
            assert compiled.returncode==0, report['commands'][-1]
            report['binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
            for mode in ['normal','eof','timeout','normal']:
                listener=socket.socket(); listener.settimeout(5)
                listener.bind(('127.0.0.1',0)); listener.listen(1)
                errors=[]
                worker=threading.Thread(target=peer_loop,args=(listener,mode,errors))
                worker.start()
                result=subprocess.run([str(binary),str(listener.getsockname()[1]),mode],
                                      text=True,capture_output=True,timeout=5)
                worker.join(timeout=5); assert not worker.is_alive()
                row=dict(mode=mode,returncode=result.returncode,stdout=result.stdout,
                         stderr=result.stderr,peer_errors=errors)
                report['modes'].append(row)
                assert result.returncode==0 and not errors, row
                assert 'WA_OWNERSHIP retained_bytes=0 bad_frees=0' in result.stdout, row
            report['passed']=True
    finally:
        report['source_after']=snapshot()
        report['source_unchanged']=before==report['source_after']
        report['passed'] &= report['source_unchanged']
        args.report.write_text(json.dumps(report,indent=2)+'\n')
    assert report['passed'], 'source changed during qualification'
    print('WHATSAPP_LOOPBACK_PASS '+args.sanitize)
if __name__=='__main__': main()
