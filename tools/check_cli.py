"""Execute public v2/v3, record-binding and disclosure vectors, fully offline."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def generate_smoke(destination):
    """Write the synthetic disclosure vector with a fresh key; the private key is never saved."""
    source = Path(__file__).resolve().parents[1]
    env = {**os.environ, 'AAES_RELEASE_FIXTURE_OUT': str(destination)}
    subprocess.run(['go', 'test', '-count=1', '-run', '^TestReleaseSmokeFixture$', './internal/evaluation'],
                   cwd=source, env=env, check=True, capture_output=True, text=True, timeout=300)
    if not (destination / 'evidence/ledger.pub').is_file():
        raise AssertionError('smoke fixture was not generated')


def check(binary):
    binary = str(Path(binary).resolve())
    root = Path(__file__).resolve().parents[1] / 'cmd/aaesverify/testdata'
    checks = {}
    with tempfile.TemporaryDirectory() as tmp:
        temp = Path(tmp)
        smoke = temp / 'evaluation-smoke'
        generate_smoke(smoke)
        wrong = temp / 'wrong.pub'
        wrong.write_text('00' * 32 + '\n')

        def execute(name, args, success=False):
            done = subprocess.run([binary, *map(str, args), '--json'], capture_output=True, text=True, timeout=30)
            result = json.loads(done.stdout)
            if done.returncode != (0 if success else 1) or result.get('ok') is not success:
                raise AssertionError((name, done.returncode, done.stderr, result))
            checks[name] = True
            return result

        for label, source, key, version in (
            ('v2', root / 'sample-export.jsonl', root / 'sample-pubkey.txt', 'aaes.export/v2'),
            ('v3', smoke / 'evidence/export.jsonl', smoke / 'evidence/ledger.pub', 'aaes.export/v3'),
        ):
            base = ['--export', source, '--pubkey', key]
            result = execute(label + '_clean', base, True)
            assert result['schema'] == version
            assert all(result[k] for k in ('chain_ok', 'root_ok', 'signature_ok', 'anchors_ok'))
            assert result['entry_count'] == (16 if label == 'v2' else 1)
            execute(label + '_wrong_key_refused', ['--export', source, '--pubkey', wrong])
            execute(label + '_independence_refused', [*base, '--require-independent'])
            raw = source.read_text()
            changed = raw.replace('"record_hash":"', '"record_hash":"0', 1)
            assert changed != raw
            tampered = temp / (label + '-tampered.jsonl')
            tampered.write_text(changed)
            result = execute(label + '_tamper_refused', ['--export', tampered, '--pubkey', key])
            assert not result['chain_ok'] and not result['root_ok']
        raw = (root / 'sample-export.jsonl').read_text()
        for version in ('v0', 'v1', 'v999'):
            path = temp / (version + '.jsonl')
            path.write_text(raw.replace('aaes.export/v2', 'aaes.export/' + version, 1))
            result = execute(version + '_refused', ['--export', path, '--pubkey', root / 'sample-pubkey.txt'])
            assert 'unsupported export schema' in ' '.join(result['errors'])
        result = execute('records_clean', ['--export', smoke / 'evidence/export.jsonl', '--pubkey', smoke / 'evidence/ledger.pub', '--records', smoke / 'evidence/records.jsonl'], True)
        assert result['sealed_records_resealed'] is True and result['sealed_sidecar_binding_verified'] is True
        assert result['resealed_record_count'] == 1 and result['verdict'] == 'CONSISTENT'
        assert all(result['export'][k] for k in ('chain_ok', 'root_ok', 'signature_ok'))
        rows = [json.loads(line) for line in (smoke / 'evidence/records.jsonl').read_text().splitlines()]
        rows[1]['record']['decision']['allowed'] = False
        altered = temp / 'records.jsonl'
        altered.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        execute('records_mutation_refused', ['--export', smoke / 'evidence/export.jsonl', '--records', altered])
        result = execute('evaluation_clean', ['--evaluation', smoke], True)
        assert result['resealed_record_count'] == 1 and result['provider_metadata_consistent'] is True
        assert result['receipt_chain_verified'] is False and result['full_private_bundle_verified'] is False
        execute('evaluation_wrong_key_refused', ['--evaluation', smoke, '--pubkey', wrong])
        execute('evaluation_independence_refused', ['--evaluation', smoke, '--require-independent'])
        mutated = temp / 'evaluation'
        shutil.copytree(smoke, mutated)
        (mutated / 'configuration.json').write_text('{}\n')
        execute('evaluation_artifact_tamper_refused', ['--evaluation', mutated])
    return {'schema': 'aaes.public-cli-release-checks/1', 'ok': True, 'synthetic_reader_smoke_only': True, 'checks': checks}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary')
    print(json.dumps(check(parser.parse_args().binary), indent=2, sort_keys=True))
