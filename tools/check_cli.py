"""Exercise the built binary against public vectors, fully offline."""
import argparse,json,subprocess,tempfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('binary');a=p.parse_args()
binary=str(Path(a.binary).resolve());root=Path(__file__).resolve().parents[1]
fixture=root/'cmd/aaesverify/testdata/sample-export.jsonl';key=root/'cmd/aaesverify/testdata/sample-pubkey.txt'
with tempfile.TemporaryDirectory() as tmp:
 temp=Path(tmp);raw=fixture.read_text();wrong=temp/'wrong.pub';wrong.write_text('00'*32+'\n')
 cases=[('clean',fixture,key,[],0),('wrong-key',fixture,wrong,[],1),('require-independent',fixture,key,['--require-independent'],1)]
 altered=temp/'tampered.jsonl';changed=raw.replace('"record_hash":"','"record_hash":"a',1);assert changed!=raw;altered.write_text(changed)
 cases.append(('tampered',altered,key,[],1))
 for schema in ('aaes.export/v0','aaes.export/v1'):
  path=temp/(schema.rsplit('/',1)[1]+'.jsonl');path.write_text(raw.replace('aaes.export/v2',schema,1));cases.append((schema,path,key,[],1))
 for name,path,pub,extra,expected in cases:
  done=subprocess.run([binary,'--export',str(path),'--pubkey',str(pub),'--json',*extra],capture_output=True,text=True,timeout=30)
  assert done.returncode==expected,(name,done.returncode,done.stderr)
  result=json.loads(done.stdout);assert result['ok']==(expected==0),(name,result)
  if name=='clean':
   assert result['schema']=='aaes.export/v2' and result['entry_count']==16
   assert all(result[k] for k in ('chain_ok','root_ok','signature_ok','anchors_ok'))
  if name=='wrong-key':assert not result['signature_ok']
  if name=='tampered':assert not result['chain_ok'] and not result['root_ok']
  if name.startswith('aaes.export/'):assert 'unsupported export schema' in ' '.join(result['errors'])
  print(name+': expected outcome confirmed')
