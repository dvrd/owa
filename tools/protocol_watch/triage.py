"""Bounded offline triage of supplied public bytes; never fetches or executes code.

Lexical equivalence is deliberately incomplete. Unknown behavior is a SPIKE, not
proof of a compatibility bug. FIX is limited to a locally bound dictionary edit.
"""
import hashlib
import json
from pathlib import Path
import re

MAX_BYTES = 4 * 1024 * 1024
MAX_TOKENS = 100000
MAX_CHANGES = 32
TABLE_COUNT = 236
REPOSITORIES = {'baileys': 'WhiskeySockets/Baileys', 'whatsmeow': 'tulir/whatsmeow'}
REFERENCES = {'baileys': 'e05b16b4aa0d7d3eb2594677e015454af1225b75',
              'whatsmeow': 'c88388f983b4bc43dfd0bcc2b46969fcde82d61f'}
# Each mapping names existing runtime owners and specific offline test targets.
OWNERS = {
 ('baileys', 'src/Socket/socket.ts'): (('socket.odin', 'connection.odin', 'auth.odin', 'pairing.odin'),
    ('tests/internal/socket_certificate_verifier_test.odin', 'tests/loopback_noise',
     'tests/internal/prekey_lifecycle_policy_test.odin', 'tests/internal/pairing_qr_profile_test.odin'),
    'Does the changed socket lifecycle require a different admission, shutdown or certificate decision?'),
 ('baileys', 'src/Socket/messages-send.ts'): (('send.odin', 'signal.odin'),
    ('tests/internal/send_id_test.odin', 'tests/encrypted_recovery'),
    'Does the send change alter IDs, encryption envelopes or durable retry ownership?'),
 ('baileys', 'src/Socket/messages-recv.ts'): (('receive.odin', 'socket.odin', 'addressing.odin'),
    ('tests/internal/acknowledgement_routing_test.odin', 'tests/internal/protocol_ack_test.odin', 'tests/internal/negative_ack_test.odin',
     'tests/internal/unsupported_encryption_test.odin', 'tests/internal/inbound_alias_test.odin'),
    'Does the receive change alter ACKs, durable completion, sender alias authority or pinned session selection?'),
 ('baileys', 'src/Utils/validate-connection.ts'): (('pairing.odin', 'connection.odin', 'auth.odin', 'protobuf.odin'),
    ('tests/internal/socket_certificate_verifier_test.odin', 'tests/internal/certificate_policy_test.odin',
     'tests/internal/pairing_domains_test.odin', 'tests/internal/pairing_qr_profile_test.odin'),
    'Which connection validation predicate changed, and is the same predicate owned locally?'),
 ('baileys', 'src/Utils/noise-handler.ts'): (('connection.odin', 'socket.odin'),
    ('tests/loopback_noise', 'tests/internal/certificate_policy_test.odin'),
    'Does the Noise transcript, frame boundary or certificate authentication contract change?'),
 ('baileys', 'src/Defaults/baileys-version.json'): (('pairing.odin', 'connection.odin'),
    ('tools/live_qualification/tests/internal/offline_test.odin',),
    'Does this advertised version require a payload change, or only a separately qualified version choice?'),
 ('baileys', 'src/WABinary/constants.ts'): (('binary_tokens.odin', 'binary_node.odin'),
    ('tests/internal/protocol_ack_test.odin', 'tests/encrypted_recovery'),
    'Which token positions or binary framing contracts differ from the locally bound dictionary?'),
 ('baileys', 'WAProto/WAProto.proto'): (('protobuf.odin', 'receive.odin', 'send.odin'),
    ('tests/encrypted_recovery', 'tests/internal/protocol_ack_test.odin'),
    'Which changed field numbers, wire types or defaults are consumed by the local codec?'),
 ('whatsmeow', 'client.go'): (('socket.odin', 'connection.odin'),
    ('tests/loopback_noise', 'tests/encrypted_recovery'),
    'Does the client lifecycle change affect locally owned admission or recovery state?'),
 ('whatsmeow', 'connectionevents.go'): (('connection.odin', 'receive.odin'),
    ('tests/internal/negative_ack_test.odin', 'tests/internal/status_ack_test.odin'),
    'Which disconnect, notification or ACK state transition changes locally?'),
 ('whatsmeow', 'handshake.go'): (('connection.odin', 'protobuf.odin'),
    ('tests/internal/certificate_policy_test.odin', 'tests/loopback_noise'),
    'Does the authenticated handshake transcript or certificate predicate change?'),
 ('whatsmeow', 'pair.go'): (('pairing.odin', 'protobuf.odin', 'auth.odin'),
    ('tools/live_qualification/tests/internal/offline_test.odin', 'tests/internal/pairing_domains_test.odin',
     'tests/internal/pairing_qr_profile_test.odin'),
    'Which pairing payload or signature predicate changes, and is it used by this implementation?'),
 ('whatsmeow', 'send.go'): (('send.odin', 'signal.odin'),
    ('tests/internal/send_id_test.odin', 'tests/encrypted_recovery'),
    'Does the send envelope or ID ownership differ on an independently reproduced synthetic case?'),
 ('whatsmeow', 'retry.go'): (('receive.odin', 'send.odin', 'signal.odin'),
    ('tests/internal/negative_ack_test.odin', 'tests/encrypted_recovery'),
    'Does the retry transition change identity reuse, durable completion or the stop-on-negative-ACK policy?'),
 ('whatsmeow', 'store/clientpayload.go'): (('pairing.odin', 'protobuf.odin'),
    ('tools/live_qualification/tests/internal/offline_test.odin',),
    'Which advertised client payload field changed, and does the local encoder emit it?'),
 ('whatsmeow', 'binary/token/token.go'): (('binary_tokens.odin', 'binary_node.odin'),
    ('tests/internal/protocol_ack_test.odin', 'tests/encrypted_recovery'),
    'Which dictionary index or token-encoding contract changes versus local tables?'),
 ('whatsmeow', 'proto/waE2E/WAWebProtobufsE2E.proto'): (('protobuf.odin', 'receive.odin', 'send.odin'),
    ('tests/encrypted_recovery',),
    'Which field number, wire type or default changes a locally consumed message?'),
}
REASONS = frozenset({'SOURCE_BINDING_UNKNOWN', 'INPUT_UNAVAILABLE', 'LOCAL_OWNER_UNAVAILABLE',
    'BYTE_IDENTICAL', 'LEXICALLY_EQUIVALENT', 'JSON_NORMALIZED_EQUIVALENT',
    'LEXICAL_PROOF_UNAVAILABLE', 'DIRECTIVE_OR_LICENSE_CHANGED', 'BEHAVIOR_CHANGE_UNRESOLVED',
    'TABLE_PROOF_UNAVAILABLE', 'TABLE_OUTSIDE_CHANGE', 'LOCAL_BASELINE_UNKNOWN',
    'ALREADY_IMPLEMENTED', 'LOCAL_DICTIONARY_CONTRACT_DRIFT',
    'APPROVED_DICTIONARY_CONTRACT_GAP', 'APPROVED_CONTRACT_UNAVAILABLE'})
SENSITIVE = re.compile(r'copyright|license|\bspdx\b|[@#!]|\bgo:|eslint|tslint|prettier|'
    r'istanbul|coverage|sourceMappingURL|sourceURL|<reference|<amd-|\b(?:lint|c8|MIT|BSD|Apache|GPL|MPL|ISC|Unlicense|export)\b|all rights reserved|//\s*line\s+|/\*line\b|//\s*\+build\b', re.I)
IDENT = re.compile(r'[A-Za-z_$][A-Za-z0-9_$]*')
NUMBER = re.compile(r'(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+|'
    r'(?:[0-9][0-9_]*(?:\.[0-9_]*)?|\.[0-9][0-9_]*)(?:[eE][+-]?[0-9_]+)?n?)')
OPERATORS = sorted({'>>>=', '===', '!==', '**=', '>>>', '<<=', '>>=', '&&=', '||=', '??=',
    '...', '=>', '++', '--', '==', '!=', '<=', '>=', '&&', '||', '??', '?.', '**',
    '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<', '>>', '<-', ':=', '::', '&^=', '&^'},
    key=lambda value: (-len(value), value))


class Uncertain(ValueError):
    pass


def _digest(data):
    return {'present': data is not None, 'bytes': len(data) if isinstance(data, bytes) else 0,
            'sha256': hashlib.sha256(data).hexdigest()
            if isinstance(data, bytes) and len(data) <= MAX_BYTES else None}


def _lex(data, language):
    """Return (kind, exact text) tokens, preserving newline/quoted/raw boundaries."""
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise Uncertain('INPUT_LIMIT')
    text = data.decode('utf-8', errors='strict')
    if language=='go' and ('\r' in text.replace('\r\n','') or '\v' in text or '\f' in text):
        raise Uncertain('GO_WHITESPACE_AMBIGUITY')
    if '\u2028' in text or '\u2029' in text or '\x00' in text:
        raise Uncertain('UNSUPPORTED_LINE_CHARACTER')
    tokens, sensitive, stack = [], [], []
    i = 0
    while i < len(text):
        if len(tokens) >= MAX_TOKENS:
            raise Uncertain('TOKEN_LIMIT')
        c = text[i]
        if c in ' \t\v\f':
            i += 1; continue
        if c in '\r\n':
            i += 2 if text.startswith('\r\n', i) else 1
            tokens.append(('newline', '\n')); continue
        if text.startswith('//', i) or text.startswith('/*', i):
            start = i
            if text.startswith('//', i):
                while i < len(text) and text[i] not in '\r\n': i += 1
            else:
                end = text.find('*/', i + 2)
                if end == -1: raise Uncertain('UNCLOSED_COMMENT')
                i = end + 2
            comment = text[start:i]
            if SENSITIVE.search(comment):
                if len(sensitive)>=64: raise Uncertain('DIRECTIVE_LIMIT')
                column=start-max(text.rfind('\n',0,start),text.rfind('\r',0,start))-1
                sensitive.append((len(tokens),column,comment))
            newlines = comment.replace('\r\n', '\n').replace('\r', '\n').count('\n')
            if len(tokens)+newlines > MAX_TOKENS: raise Uncertain('TOKEN_LIMIT')
            tokens.extend(('newline', '\n') for _ in range(newlines))
            continue
        if c in '\'"`':
            start, quote = i, c
            i += 1
            while i < len(text):
                if text[i] == quote:
                    i += 1; break
                if quote != '`' and text[i] in '\r\n': raise Uncertain('STRING_NEWLINE')
                if text[i] == '\\' and (quote != '`' or language == 'ts'):
                    i += 2
                else: i += 1
            else: raise Uncertain('UNCLOSED_STRING')
            literal = text[start:i]
            if quote == '`' and language == 'ts' and '${' in literal:
                raise Uncertain('TEMPLATE_EXPRESSION')
            tokens.append(('raw' if quote == '`' else 'string', literal)); continue
        match = IDENT.match(text, i)
        if match:
            tokens.append(('identifier', match.group())); i = match.end(); continue
        match = NUMBER.match(text, i)
        if match:
            i = match.end()
            if i < len(text) and (text[i].isalnum() or text[i] in '_$'):
                raise Uncertain('NUMBER_BOUNDARY')
            tokens.append(('number', match.group())); continue
        if language=='ts' and (c=='/' or text.startswith('<!--',i) or text.startswith('-->',i)):
            raise Uncertain('SLASH_OR_HTML_AMBIGUITY')
        if language=='ts' and text.startswith('?.',i) and i+2<len(text) and text[i+2].isdigit():
            raise Uncertain('OPTIONAL_CHAIN_DECIMAL_AMBIGUITY')
        op = next((value for value in OPERATORS if text.startswith(value, i)), None)
        if op:
            tokens.append(('operator', op)); i += len(op); continue
        if c not in '{}[]();,.:?~!+-*%&|^<>=/@': raise Uncertain('UNSUPPORTED_CHARACTER')
        if c in '({[': stack.append(c)
        elif c in ')}]':
            if not stack or stack.pop() != {')':'(', ']':'[', '}':'{'}[c]:
                raise Uncertain('DELIMITER_AMBIGUITY')
        tokens.append(('punctuation', c)); i += 1
    if stack: raise Uncertain('UNCLOSED_DELIMITER')
    if language=='go' and any((kind=='string' and _string((kind,value))=='C') or
                              (kind=='raw' and value=='`C`') for kind,value in tokens):
        raise Uncertain('CGO_PREAMBLE_AMBIGUITY')
    return tokens, sensitive


def _string(token):
    kind, text = token
    if kind != 'string' or len(text) < 2: raise Uncertain('STRING_LITERAL_REQUIRED')
    out, i = [], 1
    escapes = {'n':'\n', 'r':'\r', 't':'\t', 'b':'\b', 'f':'\f', '\\':'\\', '"':'"', "'":"'", '/':'/'}
    while i < len(text)-1:
        c = text[i]; i += 1
        if ord(c) < 32: raise Uncertain('STRING_CONTROL')
        if c == '\\':
            if i >= len(text)-1: raise Uncertain('STRING_ESCAPE')
            c = text[i]; i += 1
            if c == 'u':
                value = text[i:i+4]
                if len(value)!=4 or not re.fullmatch('[0-9A-Fa-f]{4}', value):
                    raise Uncertain('STRING_ESCAPE')
                out.append(chr(int(value,16))); i += 4
            elif c in escapes: out.append(escapes[c])
            else: raise Uncertain('STRING_ESCAPE')
        else: out.append(c)
    value = ''.join(out)
    # Combine paired JSON/JS UTF-16 escapes; reject lone surrogates.
    value = value.encode('utf-16', 'surrogatepass').decode('utf-16', 'strict')
    if len(value.encode('utf-8')) > 1024: raise Uncertain('TABLE_STRING_LIMIT')
    return value


def _table(tokens, language):
    # Newlines matter outside the array, but not between its literal elements.
    significant = [(i,t) for i,t in enumerate(tokens) if t[0] != 'newline']
    candidates = []
    depth = 0
    for j, (_, token) in enumerate(significant):
        if token[1] in ('(', '[', '{'): depth += 1
        elif token[1] in (')', ']', '}'): depth -= 1
        if token != ('identifier', 'SINGLE_BYTE_TOKENS'): continue
        if language == 'ts':
            if j < 1 or significant[j-1][1] != ('identifier','const'): continue
            if depth != 0: raise Uncertain('NESTED_TABLE')
            pattern = ['=', '[']; offset = j+1; close=']'
        else:
            if depth != 0: raise Uncertain('NESTED_TABLE')
            pattern = [':=', '[', '236', ']', 'string', '{']; offset=j+1; close='}'
        if [t[1] for _,t in significant[offset:offset+len(pattern)]] != pattern:
            raise Uncertain('TABLE_DECLARATION')
        start = offset+len(pattern)-1
        values=[]; k=start+1
        if k>=len(significant): raise Uncertain('TABLE_END')
        while significant[k][1][1] != close:
            if language=='odin' and not significant[k][1][1].startswith('"'):
                raise Uncertain('ODIN_STRING_LITERAL_REQUIRED')
            values.append(_string(significant[k][1])); k+=1
            if len(values)>TABLE_COUNT: raise Uncertain('TABLE_COUNT')
            if k>=len(significant): raise Uncertain('TABLE_END')
            if significant[k][1][1] == close: break
            if significant[k][1][1] != ',': raise Uncertain('TABLE_EXPRESSION')
            k+=1
            if k>=len(significant): raise Uncertain('TABLE_END')
        if len(values)!=TABLE_COUNT: raise Uncertain('TABLE_COUNT')
        first, last = significant[start][0], significant[k][0]
        candidates.append((values, tokens[:first]+[('table','SINGLE_BYTE_TOKENS')]+tokens[last+1:]))
    if len(candidates)!=1: raise Uncertain('TABLE_DECLARATION_COUNT')
    return candidates[0]


def _json(data):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result: raise Uncertain('DUPLICATE_JSON_KEY')
            result[key]=value
        return result
    value=json.loads(data, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(Uncertain('NONFINITE_JSON')))
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(',',':'))


def _excerpt(value):
    return ''.join(c if 32<=ord(c)<127 else '?' for c in value[:128])


CONTRACT_PREFIX = 'tools/protocol_watch/contracts/'
HEX = re.compile(r'[0-9a-f]{64}')


def table_sha256(values):
    """Canonical array identity; it never denotes server compatibility."""
    return hashlib.sha256(json.dumps(values, ensure_ascii=True,
        separators=(',', ':'), allow_nan=False).encode('utf-8')).hexdigest()


def _owned_bytes(root, relative, prefix, suffix=None):
    if (not isinstance(relative,str) or not relative.startswith(prefix) or
            not re.fullmatch(r'[A-Za-z0-9_./-]+',relative) or
            any(part in ('','.', '..') for part in relative.split('/')) or
            (suffix is not None and not relative.endswith(suffix))):
        raise Uncertain('CONTRACT_PATH')
    target=root
    for part in relative.split('/'):
        target=target/part
        if target.is_symlink(): raise Uncertain('CONTRACT_SYMLINK')
    target.resolve().relative_to(root)
    if not target.is_file(): raise Uncertain('CONTRACT_FILE')
    with target.open('rb') as stream: data=stream.read(256*1024+1)
    if len(data)>256*1024: raise Uncertain('CONTRACT_FILE_LIMIT')
    return data


def _bound_record(root,record,prefix,suffix=None):
    if not isinstance(record,dict) or set(record)!={'path','sha256'}:
        raise Uncertain('CONTRACT_RECORD')
    if not isinstance(record['sha256'],str) or not HEX.fullmatch(record['sha256']):
        raise Uncertain('CONTRACT_SHA')
    if hashlib.sha256(_owned_bytes(root,record['path'],prefix,suffix)).hexdigest()!=record['sha256']:
        raise Uncertain('CONTRACT_STALE')
    return dict(record)


def _approved_metadata(assessment,root,path):
    """Verify a caller-selected reviewed requirement, not its human authenticity.

    The explicit local contract is trusted policy input. File hashes and the
    indexed counterexample are checked; review independence/authority is not
    derivable from public upstream bytes or a self-declared approval boolean.
    """
    root=Path(root).resolve()
    raw=_owned_bytes(root,path,CONTRACT_PREFIX,'.json')
    contract=json.loads(_json(raw))
    required={'schema','source','path','target_table_sha256','requirement'}
    if (not isinstance(contract,dict) or not required<=set(contract) or
            set(contract)-required-{'fixture'} or type(contract['schema']) is not int or
            contract['schema']!=1 or contract['source']!='baileys' or
            contract['path']!='src/WABinary/constants.ts' or
            assessment.get('source')!=contract['source'] or assessment.get('path')!=contract['path']):
        raise Uncertain('CONTRACT_BINDING')
    evidence=assessment['evidence']
    expected=contract['target_table_sha256']
    if (not isinstance(expected,str) or not HEX.fullmatch(expected) or
            expected!=evidence['target_table_sha256'] or
            expected==evidence['reference_table_sha256'] or
            evidence['static_regression']!='indexed_table_comparison' or
            evidence['local_table_sha256']!=evidence['reference_table_sha256'] or
            evidence['local_table_matches']!='reference' or
            evidence['table_count']!=236 or evidence['outside_tokens_equal'] is not True):
        raise Uncertain('CONTRACT_COUNTEREXAMPLE')
    indices=evidence['changed_indices']
    if (not isinstance(indices,list) or not indices or
            any(type(i) is not int or not 0<=i<236 for i in indices) or
            indices!=sorted(set(indices)) or len(indices)!=evidence['changed_count']):
        raise Uncertain('CONTRACT_INDICES')
    expected_owners=OWNERS[('baileys','src/WABinary/constants.ts')][0]
    owners=assessment['local_targets']
    if [item['path'] for item in owners]!=list(expected_owners):
        raise Uncertain('CONTRACT_OWNERS')
    for item in owners:
        current=_owned_bytes(root,item['path'],'','.odin')
        if hashlib.sha256(current).hexdigest()!=item['sha256']:
            raise Uncertain('CONTRACT_OWNER_STALE')
        if item['path']=='binary_tokens.odin':
            local,_=_table(_lex(current,'odin')[0],'odin')
            if table_sha256(local)!=evidence['reference_table_sha256']:
                raise Uncertain('CONTRACT_LOCAL_TABLE')
    metadata={'path':path,'sha256':hashlib.sha256(raw).hexdigest(),
        'target_table_sha256':expected,
        'requirement':_bound_record(root,contract['requirement'],CONTRACT_PREFIX,'.md'),
        'basis':'explicit_reviewed_requirement_and_owned_indexed_comparison',
        'trust_limit':'Requirement review authority/independence is trusted local policy, not authenticated by this verifier.'}
    if 'fixture' in contract:
        metadata['fixture']=_bound_record(root,contract['fixture'],'tests/')
    return metadata


def validate_approved_contract(assessment,local_root):
    """Revalidate a new FIX against local files; False on any missing/stale proof.

    This is not a lifetime monitor for historical completed work and does not
    authenticate a human review, server requirement or execution receipt.
    """
    try:
        if (not isinstance(assessment,dict) or type(assessment.get('schema')) is not int or
                assessment.get('schema')!=1 or assessment.get('kind')!='FIX' or
                assessment.get('reason')!='APPROVED_DICTIONARY_CONTRACT_GAP'):
            return False
        actual=assessment['evidence']['approved_contract']
        return actual==_approved_metadata(assessment,local_root,actual['path'])
    except (OSError,ValueError,TypeError,KeyError,AttributeError,RecursionError):
        return False


def assess(source, path, reference_bytes, current_bytes, local_root, approved_contract=None):
    """Pure offline assessment. Missing/uncertain evidence yields a specific SPIKE."""
    name = source if isinstance(source,str) else source.get('name') if isinstance(source,dict) else None
    bound = isinstance(name,str) and (name,path) in OWNERS if isinstance(path,str) else False
    if bound and isinstance(source,dict):
        bound = source.get('repository') == REPOSITORIES[name] and (
            'reference_commit' not in source or source['reference_commit']==REFERENCES[name])
    evidence={'reference':_digest(reference_bytes),'current':_digest(current_bytes),
              'server_compatibility_proven':False}
    result={'schema':1,'kind':'SPIKE','reason':'SOURCE_BINDING_UNKNOWN',
        'summary':'The supplied source/path cannot be bound to a monitored local owner.',
        'source':name if bound else 'unknown','path':path if bound else 'unknown',
        'local_targets':[],'checks':[],'acceptance':[], 'evidence':evidence}
    def finish(kind,reason,summary):
        result.update(kind=kind,reason=reason,summary=summary)
        return result
    if not bound:
        evidence['question']='Which allowlisted source and monitored path does this observation describe?'
        return result
    owners, checks, question=OWNERS[(name,path)]
    evidence['question']=question
    result['checks']=list(checks)
    result['acceptance']=[question,'Reproduce the changed contract in owned synthetic fixtures before editing Odin.',
        'Preserve durable completion, negative-ACK stop, original identities and no replay.',
        'Run focused native/ASan and recovery/consumer checks; no live-account compatibility claim.']
    try:
        root=Path(local_root).resolve()
        for owner in owners:
            target=root/owner
            if target.is_symlink() or not target.is_file(): raise Uncertain('LOCAL_OWNER')
            target.resolve().relative_to(root)
            with target.open('rb') as stream: data=stream.read(MAX_BYTES+1)
            if len(data)>MAX_BYTES: raise Uncertain('LOCAL_OWNER_LIMIT')
            result['local_targets'].append({'path':owner,'sha256':hashlib.sha256(data).hexdigest()})
    except (OSError,ValueError,TypeError):
        return finish('SPIKE','LOCAL_OWNER_UNAVAILABLE','The local Odin owner cannot be safely read and source-bound.')
    if any(not isinstance(value,bytes) or len(value)>MAX_BYTES for value in (reference_bytes,current_bytes)):
        return finish('SPIKE','INPUT_UNAVAILABLE','A missing, unsupported or oversized file prevents bounded comparison.')
    if reference_bytes==current_bytes:
        return finish('NO_ACTION','BYTE_IDENTICAL','The monitored file bytes are unchanged; compatibility is not inferred.')
    if path.endswith('.json'):
        try:
            if _json(reference_bytes)==_json(current_bytes):
                return finish('NO_ACTION','JSON_NORMALIZED_EQUIVALENT','Unique-key finite JSON values are unchanged after normalization.')
        except (ValueError,UnicodeError,TypeError,RecursionError):
            return finish('SPIKE','LEXICAL_PROOF_UNAVAILABLE','JSON normalization failed; duplicate keys and unsupported values require investigation.')
        return finish('SPIKE','BEHAVIOR_CHANGE_UNRESOLVED','The advertised JSON value changed; qualify the specific local payload decision.')
    language='ts' if path.endswith('.ts') else 'go' if path.endswith('.go') else 'proto'
    try:
        old,old_sensitive=_lex(reference_bytes,language)
        new,new_sensitive=_lex(current_bytes,language)
    except (ValueError,UnicodeError):
        return finish('SPIKE','LEXICAL_PROOF_UNAVAILABLE','Syntax, slash or literal ambiguity prevents a safe lexical equivalence proof.')
    if old_sensitive != new_sensitive:
        return finish('SPIKE','DIRECTIVE_OR_LICENSE_CHANGED','A directive or license-bearing comment changed and must not be stripped as formatting.')
    if old==new:
        return finish('NO_ACTION','LEXICALLY_EQUIVALENT','Exact tokens, newlines and literals are unchanged; only safely ignored formatting/comments differ.')
    if (name,path)!=('baileys','src/WABinary/constants.ts'):
        return finish('SPIKE','BEHAVIOR_CHANGE_UNRESOLVED','Tokens changed; resolve the named local contract question with a synthetic regression.')
    try:
        reference,outside_old=_table(old,'ts'); current,outside_new=_table(new,'ts')
        with (root/'binary_tokens.odin').open('rb') as stream: local_data=stream.read(MAX_BYTES+1)
        if hashlib.sha256(local_data).hexdigest()!=result['local_targets'][0]['sha256']:
            raise Uncertain('LOCAL_OWNER_CHANGED')
        local_values,_=_table(_lex(local_data,'odin')[0],'odin')
    except (OSError,ValueError,UnicodeError):
        return finish('SPIKE','TABLE_PROOF_UNAVAILABLE','Only one strict 236-string constant array per source and a bound local array can prove this edit.')
    if outside_old!=outside_new:
        return finish('SPIKE','TABLE_OUTSIDE_CHANGE','Tokens outside the dictionary changed; table drift alone cannot classify this observation.')
    if reference==current:
        return finish('NO_ACTION','LEXICALLY_EQUIVALENT','The strict table values and outside tokens are unchanged.')
    if local_values==current:
        evidence['local_table_matches']='current'
        return finish('NO_ACTION','ALREADY_IMPLEMENTED','The local 236-entry dictionary already matches the supplied current table.')
    if local_values!=reference:
        return finish('SPIKE','LOCAL_BASELINE_UNKNOWN','The local table matches neither supplied reference nor current; establish its source before a fix.')
    changes=[{'index':i,'old':_excerpt(a),'new':_excerpt(b),
              'old_sha256':hashlib.sha256(a.encode()).hexdigest(),
              'new_sha256':hashlib.sha256(b.encode()).hexdigest()}
             for i,(a,b) in enumerate(zip(reference,current)) if a!=b]
    evidence.update(static_regression='indexed_table_comparison',
                    reference_table_sha256=table_sha256(reference),
                    target_table_sha256=table_sha256(current),
                    local_table_sha256=table_sha256(local_values),table_count=TABLE_COUNT,outside_tokens_equal=True,local_table_matches='reference',
                    changed_count=len(changes),changed_indices=[change['index'] for change in changes],
                    changes=changes[:MAX_CHANGES],
                    changes_truncated=len(changes)>MAX_CHANGES)
    result['acceptance']=[
        'Implement every index in evidence.changed_indices (not only sampled excerpts) in binary_tokens.odin; preserve all 236 positions.',
        'Preserve the approved legacy/default-version behavior; do not blindly replace a pinned dictionary.',
        'Add per-changed-index encoder/decoder roundtrip and exact byte-index regression fixtures.',
        'Verify unchanged token indices, unknown-token behavior and binary framing with owned synthetic tests.',
        'Run focused native/ASan plus encrypted recovery/consumer checks without altering durable ACK/replay policy.',
        'A matching public dictionary is not server compatibility proof; keep that qualification explicitly separate.']
    proposed_plan=result['acceptance']
    evidence['proposed_fix_plan']=proposed_plan
    result['acceptance']=[
        'Determine whether the pinned legacy/default-version contract intentionally requires the existing table.',
        'Obtain an independently reviewed requirement naming the exact target table hash, or record why no update is required.',
        'Only after that requirement demonstrates a local gap, execute the conditional proposed_fix_plan with owned regressions.']
    if approved_contract is None:
        return finish('SPIKE','LOCAL_DICTIONARY_CONTRACT_DRIFT',
            'Exact dictionary drift is relevant, but updateworthiness is unproven; obtain an independently reviewed target requirement before implementation.')
    try:
        evidence['approved_contract']=_approved_metadata(result,root,approved_contract)
    except (ValueError,OSError,TypeError,KeyError,RecursionError):
        return finish('SPIKE','APPROVED_CONTRACT_UNAVAILABLE',
            'The explicit reviewed target contract could not be bound to this static counterexample and current local owners.')
    result['acceptance']=proposed_plan
    return finish('FIX','APPROVED_DICTIONARY_CONTRACT_GAP',
        'An explicit reviewed requirement names this exact target table; the owned indexed comparison demonstrates a local contract gap, not server compatibility.')
