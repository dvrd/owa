import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('triage', Path(__file__).with_name('triage.py'))
T = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(T)
ROOT = Path(__file__).resolve().parents[2]
TABLE_PATH = 'src/WABinary/constants.ts'


def upstream(values, suffix='export const OTHER = 4;'):
    return ('export const SINGLE_BYTE_TOKENS = [' + ','.join(json.dumps(v) for v in values) +
            '];\n' + suffix + '\n').encode()


def local(values):
    return ('package whatsapp\nSINGLE_BYTE_TOKENS := [236]string {\n' +
            ',\n'.join(json.dumps(v) for v in values) + ',\n}\n').encode()


def synthetic_contract(root,values,fixture=True):
    """Test-only reviewed-policy stand-in. It creates no real approval or receipt."""
    directory=root/'tools/protocol_watch/contracts'
    directory.mkdir(parents=True,exist_ok=True)
    requirement=directory/'synthetic-requirement.md'
    requirement.write_text('Synthetic independently selected fixture contract; preserve legacy default behavior.\n')
    record=lambda path:{'path':str(path.relative_to(root)),
        'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    contract={'schema':1,'source':'baileys','path':TABLE_PATH,
        'target_table_sha256':T.table_sha256(values),'requirement':record(requirement)}
    if fixture:
        target=root/'tests/synthetic-contract.json';target.parent.mkdir(exist_ok=True)
        target.write_text(json.dumps(values))
        contract['fixture']=record(target)
    path=directory/'synthetic-contract.json'
    path.write_text(json.dumps(contract))
    return str(path.relative_to(root))


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.values = ['token-' + str(n) for n in range(236)]
        for name in ['socket.odin', 'connection.odin', 'receive.odin', 'send.odin',
                     'pairing.odin', 'protobuf.odin', 'signal_session.odin', 'binary_node.odin']:
            (self.root / name).write_text('package whatsapp\n')
        (self.root / 'binary_tokens.odin').write_bytes(local(self.values))

    def assess(self, old, new, path='src/Socket/socket.ts', source='baileys', approved_contract=None):
        result = T.assess(source, path, old, new, self.root, approved_contract=approved_contract)
        self.assertEqual(result['schema'], 1)
        json.dumps(result, allow_nan=False)
        self.assertLess(len(json.dumps(result).encode()), 65536)
        return result

    def test_identical_known_bytes_are_no_action(self):
        self.assertEqual(self.assess(b'const x=1;\n', b'const x=1;\n')['kind'], 'NO_ACTION')

    def test_conservative_comment_and_horizontal_format_proof(self):
        for old, new in [(b'const x=1; // hello\n', b'const  x = 1; /* world */\n'),
                         (b'const x="a // b";\n', b'const x = "a // b";\n')]:
            self.assertEqual(self.assess(old, new)['reason'], 'LEXICALLY_EQUIVALENT')

    def test_newlines_asi_operators_and_literals_are_not_ignored(self):
        for old, new in [(b'return x\n', b'return\nx\n'),
                         (b'x + + y\n', b'x++y\n'),
                         (b'const x="one";\n', b'const x="two";\n'),
                         (b'const x=`a\nb`;\n', b'const x=`a b`;\n'),
                         (b'const x=1e2;\n', b'const x=1 e2;\n')]:
            self.assertEqual(self.assess(old, new)['kind'], 'SPIKE')

    def test_changed_directives_and_license_are_spikes(self):
        for old, new in [(b'// @ts-ignore\nx()\n', b'// @ts-check\nx()\n'),
                         (b'// Copyright A\nx()\n', b'// Copyright B\nx()\n'),
                         (b'/*#__PURE__*/ x()\n', b'/* note */ x()\n'),
                         (b'//go:build linux\nx()\n', b'//go:build darwin\nx()\n')]:
            self.assertEqual(self.assess(old, new)['kind'], 'SPIKE')

    def test_slash_and_syntax_uncertainty_refuse_equivalence(self):
        for old, new in [(b'const x=/foo/;\n', b'const x = /foo/;\n'),
                         (b'const x=a/2;\n', b'const x = a / 2;\n'),
                         (b'/* open', b'/* changed'),
                         (b'const x="open', b'const x = "open'),
                         (b'const x=1;\n', b'const x=\xff;\n')]:
            self.assertEqual(self.assess(old, new)['kind'], 'SPIKE')

    def test_json_semantics_and_duplicate_key_refusal(self):
        path='src/Defaults/baileys-version.json'
        self.assertEqual(self.assess(b'{"version":[1,2,3],"x":1}',
                                    b'{ "x": 1, "version": [1,2,3] }', path)['kind'], 'NO_ACTION')
        for new in [b'{"version":[1,2,4]}', b'{"x":1,"x":1}', b'{"x":NaN}']:
            self.assertEqual(self.assess(b'{"x":1}', new, path)['kind'], 'SPIKE')
        self.assertEqual(self.assess(b'{"x":true}', b'{"x":1}', path)['kind'], 'SPIKE')

    def test_binding_missing_targets_and_limits_fail_closed(self):
        for source, path in [('unknown','src/Socket/socket.ts'),
                             ({'name':'baileys','repository':'other/repo'}, 'src/Socket/socket.ts'),
                             ('baileys','../auth'),
                             ({'name':'baileys','repository':'WhiskeySockets/Baileys',
                               'reference_commit':'0'*40}, 'src/Socket/socket.ts')]:
            self.assertEqual(self.assess(b'x', b'x', path, source)['kind'], 'SPIKE')
        (self.root/'socket.odin').unlink()
        self.assertEqual(self.assess(b'x', b'x')['kind'], 'SPIKE')
        self.assertEqual(self.assess(None,b'x')['kind'],'SPIKE')
        self.assertEqual(self.assess(b'x',b'x'*(T.MAX_BYTES+1))['kind'],'SPIKE')

    def test_all_seventeen_paths_bind_existing_local_owners(self):
        manifest=json.loads((ROOT/'tools/protocol_watch/sources.json').read_bytes())
        count=0
        for source in manifest['sources']:
            for path in source['paths']:
                r=T.assess(source,path,b'x',b'y',ROOT); count+=1
                self.assertEqual(r['kind'],'SPIKE')
                self.assertTrue(r['local_targets'])
                self.assertTrue(r['checks']); self.assertTrue(r['acceptance'])
                for check in r['checks']: self.assertTrue((ROOT/check).exists(),check)
                self.assertTrue(r['evidence']['question'])
                for item in r['local_targets']:
                    self.assertTrue(item['path'].endswith('.odin'))
                    self.assertEqual(item['sha256'],hashlib.sha256((ROOT/item['path']).read_bytes()).hexdigest())
        self.assertEqual(count,17)

    def test_strict_local_parser_accepts_the_real_owned_odin_dictionary(self):
        values,_=T._table(T._lex((ROOT/'binary_tokens.odin').read_bytes(),'odin')[0],'odin')
        self.assertEqual(len(values),236)
        self.assertEqual(len(T.table_sha256(values)),64)

    def test_exact_dictionary_drift_is_relevant_but_unqualified_spike(self):
        changed=self.values.copy(); changed[5]='new-value'; changed[235]='other'
        r=self.assess(upstream(self.values),upstream(changed),TABLE_PATH)
        self.assertEqual((r['kind'],r['reason']),('SPIKE','LOCAL_DICTIONARY_CONTRACT_DRIFT'))
        self.assertEqual([x['index'] for x in r['evidence']['changes']],[5,235])
        self.assertEqual(r['evidence']['changes'][0]['old'],'token-5')
        self.assertTrue(any('236' in x for x in r['evidence']['proposed_fix_plan']))
        self.assertTrue(any('intentionally requires' in x for x in r['acceptance']))
        self.assertFalse(r['evidence']['server_compatibility_proven'])

    def test_already_implemented_dictionary_is_no_action(self):
        changed=self.values.copy(); changed[10]='done'
        (self.root/'binary_tokens.odin').write_bytes(local(changed))
        r=self.assess(upstream(self.values),upstream(changed),TABLE_PATH)
        self.assertEqual((r['kind'],r['reason']),('NO_ACTION','ALREADY_IMPLEMENTED'))

    def test_table_other_changes_unknown_local_baseline_and_counts_are_spikes(self):
        changed=self.values.copy(); changed[1]='different'
        for current in [upstream(changed,'export const OTHER = 5;'),upstream(changed[:-1]),
                        upstream(changed).replace(b'"different"',b'calculate()'),
                        upstream(changed).replace(b'"different"',b'`different`'),
                        upstream(changed)+b'export const SINGLE_BYTE_TOKENS=[];']:
            self.assertEqual(self.assess(upstream(self.values),current,TABLE_PATH)['kind'],'SPIKE')
        (self.root/'binary_tokens.odin').write_bytes(local(['unknown']*236))
        self.assertEqual(self.assess(upstream(self.values),upstream(changed),TABLE_PATH)['kind'],'SPIKE')

    def test_table_escaped_strings_and_bounded_evidence(self):
        changed=self.values.copy(); changed[2]='quote\" and \' slash \\'; changed[4]='z'*900
        r=self.assess(upstream(self.values),upstream(changed),TABLE_PATH)
        self.assertEqual(r['kind'],'SPIKE')
        self.assertLessEqual(len(r['evidence']['changes'][1]['new']),128)
        many=['change-'+str(n) for n in range(236)]
        r=self.assess(upstream(self.values),upstream(many),TABLE_PATH)
        self.assertEqual(len(r['evidence']['changes']),32)
        self.assertEqual(r['evidence']['changed_count'],236)
        self.assertEqual(r['evidence']['changed_indices'],list(range(236)))
        self.assertTrue(r['evidence']['changes_truncated'])

    def test_directive_position_and_indentation_are_not_harmless(self):
        for old,new in [(b'/*#__PURE__*/ f();g();\n',b'f();/*#__PURE__*/ g();\n'),
                        (b'//go:build linux\nx()\n',b' //go:build linux\nx()\n'),
                        (b'// MIT\nx()\n',b'// BSD\nx()\n'),
                        (b'/// <reference path="a"/>\nx()\n',b'/// <reference path="b"/>\nx()\n')]:
            self.assertEqual(self.assess(old,new)['kind'],'SPIKE')

    def test_template_expression_html_numeric_and_resource_ambiguity(self):
        for old,new in [(b'const x=`a ${`x`}`;\n',b'const x = `a ${`x`}`;\n'),
                        (b'<!-- x\ny();\n',b'< ! -- x\ny();\n'),
                        (b'const x=0x1p+2;\n',b'const x = 0x1p+2;\n'),
                        (b'const x=a?.3:0;\n',b'const x=a?. 3:0;\n'),
                        (b'x()',b'/*'+b'\n'*(T.MAX_TOKENS+1)+b'*/x()')]:
            self.assertEqual(self.assess(old,new)['kind'],'SPIKE')

    def test_go_raw_strings_and_go_or_proto_comments(self):
        for source,path,old,new in [
            ('whatsmeow','client.go',b'const x=`a//b`;\n',b'const x = `a//b`;\n'),
            ('whatsmeow','client.go',b'const x=4; // a\n',b'const  x=4; /* b */\n'),
            ('baileys','WAProto/WAProto.proto',b'syntax="proto3"; // a\n',
             b'syntax = "proto3"; /* b */\n')]:
            self.assertEqual(self.assess(old,new,path,source)['kind'],'NO_ACTION')
        self.assertEqual(self.assess(b'const x=`a  b`;\n',b'const x=`a b`;\n',
            'client.go','whatsmeow')['kind'],'SPIKE')

    def test_go_build_line_preamble_and_carriage_return_are_not_stripped(self):
        cases=[(b'// +build linux\npackage p\n',b'// +build windows\npackage p\n'),
               (b'/*line a.c:10*/ x()\n',b'/*line b.c:20*/ x()\n'),
               (b'/* int f(){return 1;} */\nimport "C"\n',
                b'/* int f(){return 2;} */\nimport "C"\n'),
               (b'// note\rpanic("synthetic")\n',b'// note\npanic("synthetic")\n'),
               (b'const x=1;\v',b'const x = 1; '),
               (b'const x=1;\f',b'const x = 1; ')]
        for old,new in cases:
            self.assertEqual(self.assess(old,new,'client.go','whatsmeow')['kind'],'SPIKE')
        self.assertEqual(self.assess(b'const x=1;\r\n',b'const x = 1;\n',
            'client.go','whatsmeow')['kind'],'NO_ACTION')

    def test_nested_tables_and_unsupported_escape_are_spikes(self):
        changed=self.values.copy();changed[4]='new'
        for old,new in [
            (b'function f(){'+upstream(self.values)+b'}',b'function f(){'+upstream(changed)+b'}'),
            (upstream(self.values),upstream(changed).replace(b'"new"',b"'\\x41'"))]:
            self.assertEqual(self.assess(old,new,TABLE_PATH)['kind'],'SPIKE')

    def test_explicit_reviewed_contract_enables_static_gap_fix(self):
        changed=self.values.copy();changed[9]='required-value'
        for with_fixture in (True,False):
            contract=synthetic_contract(self.root,changed,with_fixture)
            r=self.assess(upstream(self.values),upstream(changed),TABLE_PATH,
                          approved_contract=contract)
            self.assertEqual((r['kind'],r['reason']),('FIX','APPROVED_DICTIONARY_CONTRACT_GAP'))
            self.assertTrue(T.validate_approved_contract(r,self.root))
            proof=r['evidence']['approved_contract']
            self.assertEqual(proof['target_table_sha256'],T.table_sha256(changed))
            self.assertIn('trusted local policy',proof['trust_limit'])
            self.assertTrue(any('legacy/default' in a for a in r['acceptance']))
            # Selection is explicit: a contract merely existing in the checkout is not an opt-in.
            self.assertEqual(self.assess(upstream(self.values),upstream(changed),TABLE_PATH)['kind'],'SPIKE')

    def test_approved_contract_binding_path_symlink_and_weak_claims_fail_closed(self):
        changed=self.values.copy();changed[2]='required'
        contract=synthetic_contract(self.root,changed)
        original=(self.root/contract).read_bytes()
        def evaluate(path=contract):
            return self.assess(upstream(self.values),upstream(changed),TABLE_PATH,
                               approved_contract=path)
        for bad_path in ['/tmp/contract.json','../contract.json','tests/synthetic-contract.json']:
            self.assertEqual(evaluate(bad_path)['kind'],'SPIKE')
        manifest=json.loads(original)
        for key,value in [('source','whatsmeow'),('target_table_sha256','0'*64),
                          ('approved',True),('schema',True)]:
            bad=dict(manifest);bad[key]=value;(self.root/contract).write_text(json.dumps(bad))
            self.assertEqual(evaluate()['kind'],'SPIKE')
        (self.root/contract).write_text(json.dumps({'schema':1,'latest_table_sha256':T.table_sha256(changed),
            'baseline':'PASS','current':'FAIL','approved':True}))
        self.assertEqual(evaluate()['kind'],'SPIKE')
        (self.root/contract).write_bytes(original)
        requirement=self.root/manifest['requirement']['path']
        content=requirement.read_bytes();requirement.write_bytes(content+b' changed')
        self.assertEqual(evaluate()['kind'],'SPIKE')
        requirement.write_bytes(content)
        fixture=self.root/manifest['fixture']['path']; content=fixture.read_bytes()
        fixture.write_bytes(content+b' changed');self.assertEqual(evaluate()['kind'],'SPIKE')
        fixture.write_bytes(content)
        requirement.unlink();requirement.symlink_to(fixture)
        self.assertEqual(evaluate()['kind'],'SPIKE')

    def test_new_fix_proof_revalidation_detects_stale_owners_and_forged_metadata(self):
        changed=self.values.copy();changed[2]='required'
        contract=synthetic_contract(self.root,changed)
        r=self.assess(upstream(self.values),upstream(changed),TABLE_PATH,approved_contract=contract)
        self.assertTrue(T.validate_approved_contract(r,self.root))
        r['evidence']['approved_contract']['sha256']='0'*64
        self.assertFalse(T.validate_approved_contract(r,self.root))
        r=self.assess(upstream(self.values),upstream(changed),TABLE_PATH,approved_contract=contract)
        (self.root/'binary_tokens.odin').write_bytes(local(changed))
        self.assertFalse(T.validate_approved_contract(r,self.root))
        # An implemented table is a no-action observation, not an eternal failing contract monitor.
        self.assertEqual(self.assess(upstream(self.values),upstream(changed),TABLE_PATH)['reason'],
                         'ALREADY_IMPLEMENTED')

    def test_table_sensitive_comment_change_is_not_a_fix(self):
        changed=self.values.copy();changed[3]='new'
        self.assertEqual(self.assess(b'// Copyright A\n'+upstream(self.values),
                                    b'// Copyright B\n'+upstream(changed),TABLE_PATH)['kind'],'SPIKE')


if __name__=='__main__': unittest.main()
