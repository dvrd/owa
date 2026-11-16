import copy,hashlib,importlib.util,json,uuid
from pathlib import Path
import unittest
from unittest import mock
SPEC=importlib.util.spec_from_file_location('linear_review',(Path(__file__).resolve().parents[1] / ('linear_review.py')))
L=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(L)
RUN='https://github.com/dvrd/owa/actions/runs/123'

def report(baileys=1,whatsmeow=0,revision='b'):
    sources=[]
    for source in L.watch.manifest_read(L.HERE/'sources.json')['sources']:
        actual={k:source[k] for k in ('name','repository','reference_commit')}
        actual.update(head_commit='1'*40,files=[])
        for index,path in enumerate(source['paths']):
            ref={'present':True,'bytes':10,'sha256':'a'*64}
            n=baileys if source['name']=='baileys' else whatsmeow
            cur={**ref,'sha256':revision*64} if index<n else dict(ref)
            actual['files'].append(dict(path=path,reference=ref,current=cur,changed_from_reference=cur!=ref))
        sources.append(actual)
    return dict(status='REVIEW_REQUIRED' if baileys or whatsmeow else 'NO_MONITORED_DRIFT',
                compatibility_approved=False,runtime_version_changed=False,observation={'sources':sources})

def issue(payload,number=123):
    return dict(id=payload['id'],identifier='OKAMI-'+str(number),url='https://linear.app/devoured/issue/OKAMI-'+str(number)+'/review',
                title=payload['title'],description=payload['description'],archivedAt=None,state={'type':'backlog'},project={'id':L.PROJECT})

def legacy(value):
    fp,changed=L.snapshot(value)
    ident=str(uuid.UUID(bytes=hashlib.sha256((L.PROJECT+'/owa-protocol-review/v1/'+fp).encode()).digest()[:16],version=4))
    lines=['Review public upstream protocol changes detected by OWA. No automated agent or fix was run.','','Evidence: '+RUN,'','## Monitored differences from reference','']
    for source,item in changed:
        repo,path=source['repository'],item['path']
        lines += [f"- {source['name']}: `{path}`",f"  - [reference](https://github.com/{repo}/blob/{source['reference_commit']}/{path}) / [observed](https://github.com/{repo}/blob/{source['head_commit']}/{path})",f"  - SHA256: `{item['reference']['sha256']}` → `{item['current']['sha256']}`"]
    lines += ['','## Human review and follow-up','','1. Human review remains open.','','Snapshot fingerprint: `'+fp+'`','','owa-protocol-drift:v1:'+fp]
    return issue(dict(id=ident,title='OWA: review upstream protocol changes ('+fp[:12]+')',description='\n'.join(lines)))

def classified(value,kind='NO_ACTION',reason='LEXICALLY_EQUIVALENT'):
    item=value['observation']['sources'][0]['files'][0]
    item['assessment']=dict(schema=1,kind=kind,reason=reason,summary='Fixed synthetic classification.',source='baileys',path=item['path'],
        local_targets=[{'path':p,'sha256':'d'*64} for p in L.triage.OWNERS[('baileys',item['path'])][0]],checks=['Owned synthetic check.'],acceptance=['Record the exact contract.'],
        evidence=dict(reference=item['reference'],current=item['current'],server_compatibility_proven=False))
    return value

class API:
    def __init__(self):
        self.items={};self.comments={};self.creates=[];self.comment_creates=[];self.calls=[]
        self.page_size=50;self.comment_page_size=20;self.lose_create=False;self.lose_comment=False
        self.commit_create=True;self.commit_comment=True;self.fresh_hook=None
    def add(self,item):self.items[item['id']]=copy.deepcopy(item)
    def page(self,nodes,after,size):
        start=int(after or 0);part=nodes[start:start+size];end=start+len(part)
        return dict(nodes=copy.deepcopy(part),pageInfo=dict(hasNextPage=end<len(nodes),endCursor=str(end)))
    def __call__(self,query,variables):
        self.calls.append((query,copy.deepcopy(variables)))
        if query==L.SCAN:return {'issues':self.page(list(self.items.values()),variables['after'],self.page_size)}
        if query==L.COMMENTS:
            i=self.items[variables['id']];nodes=[dict(id=c['id'],body=c['body']) for c in self.comments.values() if c['issue']['id']==i['id']]
            return {'issue':dict(id=i['id'],project=i['project'],comments=self.page(nodes,variables['after'],self.comment_page_size))}
        if query==L.LOOKUP:
            if self.fresh_hook:self.fresh_hook(self,variables)
            return {'issues':dict(nodes=[copy.deepcopy(self.items[i]) for i in variables['ids'] if i in self.items])}
        if query==L.COMMENT_LOOKUP:return {'comments':{'nodes':[copy.deepcopy(self.comments[variables['id']])] if variables['id'] in self.comments else []}}
        if query==L.CREATE:
            payload=variables['input'];self.creates.append(copy.deepcopy(payload))
            if self.commit_create:self.add(issue(payload,123+len(self.items)))
            if self.lose_create:raise L.ReviewError('LINEAR_REQUEST_FAILED')
            return {'issueCreate':{'success':True}}
        if query==L.COMMENT_CREATE:
            payload=variables['input'];self.comment_creates.append(copy.deepcopy(payload))
            if self.commit_comment:self.comments[payload['id']]=dict(id=payload['id'],body=payload['body'],issue={'id':payload['issueId'],'project':{'id':L.PROJECT}})
            if self.lose_comment:raise L.ReviewError('LINEAR_REQUEST_FAILED')
            return {'commentCreate':{'success':True}}
        raise AssertionError('Unexpected API operation')

class Tests(unittest.TestCase):
    def test_three_snapshot_overlap_does_not_repeat_seven_baileys_files(self):
        api=API();first=report(7,0);second=report(7,1);third=report(7,1)
        third['observation']['sources'][1]['files'][0]['current']['sha256']='c'*64
        self.assertEqual(L.track(first,RUN,api)['status'],'CREATED')
        self.assertEqual(L.track(second,RUN,api)['status'],'CREATED')
        self.assertEqual(L.track(third,RUN,api)['status'],'UPDATED')
        self.assertEqual((len(api.creates),len(api.comment_creates)),(2,1))
        self.assertEqual(len(L.v2_coverage(api.creates[0]['description'])),7)
        self.assertEqual(len(L.v2_coverage(api.creates[1]['description'])),1)
        section=api.comment_creates[0]['body'];self.assertNotIn('WhiskeySockets',section)
        self.assertEqual(len(L.v2_coverage(section)),1)
        self.assertEqual(L.track(third,RUN,api)['status'],'EXISTING');self.assertEqual(len(api.comment_creates),1)
    def test_legacy_seven_files_are_covered_when_whatsmeow_changes(self):
        api=API();api.add(legacy(report(7,0)));L.track(report(7,1),RUN,api)
        self.assertEqual(len(api.creates),1);self.assertIn('whatsmeow',api.creates[0]['title'])
        self.assertNotIn('WhiskeySockets',api.creates[0]['description'])
    def test_identity_ignores_heads_runs_unrelated_files_and_size(self):
        a=report();b=copy.deepcopy(a);b['observation']['sources'][1]['files'][0]['current']['sha256']='c'*64;b['observation']['sources'][1]['files'][0]['changed_from_reference']=True
        b['observation']['sources'][0]['head_commit']='2'*40;b['observation']['checked_at_unix']=123
        self.assertEqual(L.findings(a)[0]['id'],L.findings(b)[0]['id'])
        x=L.findings(a)[0];self.assertEqual(x['id'],L.change_identity(x['repository'],x['path'],{**x['reference'],'bytes':999},{**x['current'],'bytes':999}))
        self.assertEqual(L.ticket(a,RUN)[0],L.ticket(a,'https://github.com/dvrd/owa/actions/runs/456')[0])
    def test_new_revision_reuses_same_open_source_spike(self):
        api=API();L.track(report(),RUN,api);L.track(report(revision='c'),RUN,api)
        self.assertEqual((len(api.creates),len(api.comment_creates)),(1,1))
    def test_same_source_new_path_reuses_one_spike(self):
        api=API();L.track(report(1),RUN,api);L.track(report(2),RUN,api)
        self.assertEqual((len(api.creates),len(api.comment_creates)),(1,1))
    def test_closed_and_archived_description_coverage_never_reopens(self):
        for archived in [False,True]:
            api=API();L.track(report(),RUN,api)
            old=next(iter(api.items.values()));old['state']['type']='completed';old['archivedAt']='2026-01-01' if archived else None
            self.assertEqual(L.track(report(),RUN,api)['status'],'EXISTING')
            L.track(report(revision='c'),RUN,api);self.assertEqual(len(api.creates),2);self.assertFalse(api.comment_creates)
    def test_closed_comment_coverage_survives_without_reopening(self):
        api=API();L.track(report(),RUN,api);L.track(report(revision='c'),RUN,api)
        next(iter(api.items.values()))['state']['type']='completed'
        self.assertEqual(L.track(report(revision='c'),RUN,api)['status'],'EXISTING');self.assertEqual(len(api.creates),1)
    def test_all_no_action_and_clean_scan_have_no_linear_calls(self):
        def forbidden(*args):raise AssertionError('no API')
        self.assertEqual(L.track(classified(report()),RUN,forbidden)['status'],'NO_REVIEW_NEEDED')
        self.assertEqual(L.track(report(0,0),RUN,forbidden)['status'],'NO_REVIEW_NEEDED')
    def test_all_covered_makes_no_comment(self):
        api=API();L.track(report(),RUN,api);L.track(report(),RUN,api)
        self.assertEqual(len(api.creates),1);self.assertFalse(api.comment_creates)
    def test_project_and_comment_pagination_scan_all_pages(self):
        api=API();api.page_size=1;api.comment_page_size=1
        for revision in ['b','c']:
            p=L.payload_for(L.findings(report(revision=revision)),RUN);item=issue(p,123+len(api.items));item['state']['type']='completed';api.add(item)
        old=next(iter(api.items.values()));api.comments['human']=dict(id='human',body='human note',issue={'id':old['id'],'project':{'id':L.PROJECT}})
        f=L.findings(report(revision='d'));cid=L.comment_identity(old['id'],f);api.comments[cid]=dict(id=cid,body=L.machine_section(f,RUN),issue={'id':old['id'],'project':{'id':L.PROJECT}})
        self.assertEqual(L.track(report(revision='d'),RUN,api)['status'],'EXISTING');self.assertFalse(api.creates)
        self.assertGreater(sum(q==L.SCAN for q,_ in api.calls),1);self.assertGreater(sum(q==L.COMMENTS for q,_ in api.calls),2)
    def test_pagination_cycle_fails_before_mutation(self):
        api=API()
        def bad(q,v):
            if q==L.SCAN:return {'issues':dict(nodes=[],pageInfo=dict(hasNextPage=True,endCursor='same'))}
            return api(q,v)
        with self.assertRaisesRegex(L.ReviewError,'PAGINATION'):L.track(report(),RUN,bad)
        self.assertFalse(api.creates)
    def test_scan_error_and_bound_never_create(self):
        def fail(*args):raise L.ReviewError('LINEAR_REQUEST_FAILED')
        with self.assertRaises(L.ReviewError):L.track(report(),RUN,fail)
        api=API();api.add(legacy(report()));api.items[next(iter(api.items))]['description']='x'*L.watch.MAX_REPORT
        with self.assertRaisesRegex(L.ReviewError,'SCAN_BOUND'):L.track(report(),RUN,api)
        self.assertFalse(api.creates)
    def test_malformed_legacy_manual_or_foreign_claims_do_not_cover(self):
        for change in ['id','foreign','path','hash','ref','partial']:
            item=legacy(report())
            if change=='id':item['id']=str(uuid.uuid4())
            if change=='foreign':item['description']=item['description'].replace('WhiskeySockets/Baileys','foreign/Repo')
            if change=='path':item['description']=item['description'].replace('src/Socket/socket.ts','evil.ts')
            if change=='hash':item['description']=item['description'].replace('b'*64,'not-a-hash')
            if change=='ref':item['description']=item['description'].replace('e05b16b4aa0d7d3eb2594677e015454af1225b75','9'*40)
            if change=='partial':item['description']+='\nowa-protocol-drift:v1:'+'f'*64
            self.assertFalse(L.legacy_coverage(item),change)
            api=API();api.add(item);L.track(report(),RUN,api);self.assertEqual(len(api.creates),1)
    def test_manual_v2_marker_without_valid_machine_record_does_not_cover(self):
        p=L.payload_for(L.findings(report()),RUN);item=issue(p);item['id']=str(uuid.uuid4());item['description']='owa-protocol-change:v2:'+L.findings(report())[0]['id']
        api=API();api.add(item);L.track(report(),RUN,api);self.assertEqual(len(api.creates),1)
    def test_wrong_v2_identity_or_foreign_repo_is_not_coverage(self):
        for key,value in [('id','f'*64),('repository','foreign/Repo'),('path','foreign.ts')]:
            f=L.findings(report());f[0][key]=value
            with self.assertRaisesRegex(L.ReviewError,'V2_INVALID'):L.v2_coverage(L.machine_section(f,RUN))
    def test_append_preserves_human_body_and_prior_sections(self):
        api=API();L.track(report(),RUN,api);old=next(iter(api.items.values()));body=old['description'];human='\nHuman plan: preserve my work.'
        def edit(api,variables):
            if old['id'] in variables['ids']:old['description']=body+human
        api.fresh_hook=edit;L.track(report(revision='c'),RUN,api)
        self.assertEqual(old['description'],body+human);self.assertEqual(len(api.comment_creates),1)
        self.assertTrue(api.comment_creates[0]['doNotSubscribeToIssue'])
    def test_concurrent_human_comment_never_overwritten(self):
        api=API();L.track(report(),RUN,api);old=next(iter(api.items.values()))
        def edit(api,variables):api.comments.setdefault('human',dict(id='human',body='Keep this note.',issue={'id':old['id'],'project':{'id':L.PROJECT}}))
        api.fresh_hook=edit;L.track(report(revision='c'),RUN,api);self.assertEqual(api.comments['human']['body'],'Keep this note.')
    def test_close_race_does_not_comment_or_reopen_closed_issue(self):
        api=API();L.track(report(),RUN,api);old=next(iter(api.items.values()))
        def close(api,variables):old['state']['type']='completed'
        api.fresh_hook=close;L.track(report(revision='c'),RUN,api);self.assertFalse(api.comment_creates);self.assertEqual(len(api.creates),2)
    def test_deterministic_uuid4_only_new_findings(self):
        p=L.payload_for(L.findings(report()),RUN);self.assertEqual(uuid.UUID(p['id']).version,4)
        self.assertEqual(p['id'],L.payload_for(L.findings(report()),'https://github.com/dvrd/owa/actions/runs/456')['id'])
    def test_lost_create_is_queried_once_not_replayed(self):
        api=API();api.lose_create=True
        self.assertEqual(L.track(report(),RUN,api)['status'],'EXISTING');self.assertEqual(len(api.creates),1)
        self.assertEqual(sum(q==L.LOOKUP for q,_ in api.calls),2)
    def test_unknown_uncommitted_create_is_not_retried(self):
        api=API();api.lose_create=True;api.commit_create=False
        with self.assertRaisesRegex(L.ReviewError,'CREATE_OUTCOME_UNKNOWN'):L.track(report(),RUN,api)
        self.assertEqual(len(api.creates),1)
        ident=api.creates[0]['id'];api.lose_create=False;api.commit_create=True;L.track(report(),RUN,api);self.assertEqual(ident,api.creates[1]['id'])
    def test_lost_comment_is_queried_once_not_replayed(self):
        api=API();L.track(report(),RUN,api);api.calls=[];api.lose_comment=True
        self.assertEqual(L.track(report(revision='c'),RUN,api)['status'],'UPDATED');self.assertEqual(len(api.comment_creates),1)
        self.assertEqual(sum(q==L.COMMENT_LOOKUP for q,_ in api.calls),2)
    def test_unknown_comment_is_not_retried(self):
        api=API();L.track(report(),RUN,api);api.lose_comment=True;api.commit_comment=False
        with self.assertRaisesRegex(L.ReviewError,'COMMENT_OUTCOME_UNKNOWN'):L.track(report(revision='c'),RUN,api)
        self.assertEqual(len(api.comment_creates),1)
    def test_known_rejection_not_replayed(self):
        api=API()
        def reject(q,v):
            if q==L.CREATE:raise L.ReviewError('LINEAR_API_REJECTED')
            return api(q,v)
        with self.assertRaisesRegex(L.ReviewError,'^LINEAR_API_REJECTED$'):L.track(report(),RUN,reject)
        self.assertEqual(sum(q==L.LOOKUP for q,_ in api.calls),2)
    def test_unsupported_assessment_and_fix_without_proof_fail_before_api(self):
        for kind,reason in [('PATCH','LEXICALLY_EQUIVALENT'),('FIX','BEHAVIOR_CHANGE_UNRESOLVED'),('NO_ACTION','UNSUPPORTED'),('FIX','APPROVED_DICTIONARY_CONTRACT_GAP')]:
            value=classified(report(),kind,reason)
            with self.assertRaises(L.ReviewError):L.track(value,RUN,lambda *args:self.fail('no API'))
    def test_stale_assessment_evidence_fails_before_api(self):
        value=classified(report());value['observation']['sources'][0]['files'][0]['assessment']['evidence']['current']={'wrong':True}
        with self.assertRaises(L.ReviewError):L.track(value,RUN,lambda *args:self.fail('no API'))
    def test_invalid_scan_bindings_and_clean_status_fail_before_api(self):
        for mutation in ['status','path','policy','digest']:
            value=report()
            if mutation=='status':value['status']='NO_MONITORED_DRIFT'
            if mutation=='path':value['observation']['sources'][0]['files'][0]['path']='injected\npath'
            if mutation=='policy':value['compatibility_approved']=True
            if mutation=='digest':value['observation']['sources'][0]['files'][0]['current']['sha256']='bad'
            with self.assertRaises(L.ReviewError):L.track(value,RUN,lambda *args:self.fail('no API'))
    def test_run_url_is_exact_owa(self):
        with self.assertRaisesRegex(L.ReviewError,'RUN_URL_INVALID'):L.track(report(),'https://example.com/run',API())
    def test_network_client_redaction_redirect_and_bound(self):
        response=mock.MagicMock();response.__enter__.return_value.read.return_value=json.dumps({'errors':[{'message':'private-server-error'}]}).encode()
        opener=mock.Mock();opener.open.return_value=response
        with mock.patch.dict(L.os.environ,{'LINEAR_API':'private-test-key'}),mock.patch.object(L.urllib.request,'build_opener',return_value=opener):
            with self.assertRaisesRegex(L.ReviewError,'^LINEAR_API_REJECTED$'):L.request(L.SCAN,{'after':None})
            response.__enter__.return_value.read.return_value=b'x'*(L.watch.MAX_REPORT+1)
            with self.assertRaisesRegex(L.ReviewError,'^LINEAR_REQUEST_FAILED$'):L.request(L.SCAN,{'after':None})
        self.assertIsNone(L.NoRedirect().redirect_request(None,None,None,None,None,None))



def dictionary_report(change_count=2,approved=False,root=None):
    import tempfile
    if root is None:
        with tempfile.TemporaryDirectory() as folder:return dictionary_report(change_count,approved,Path(folder))
    values=['token-'+str(i) for i in range(236)]
    new=[('updated-'+v if i<change_count else v) for i,v in enumerate(values)]
    def upstream(table):return ('export const SINGLE_BYTE_TOKENS = ['+','.join(json.dumps(v) for v in table)+'];\nexport const OTHER = 4;\n').encode()
    old_bytes,new_bytes=upstream(values),upstream(new)
    for name in L.triage.OWNERS[('baileys','src/WABinary/constants.ts')][0]+L.triage.OWNERS[('baileys','src/WABinary/constants.ts')][1]:
        p=root/name;p.parent.mkdir(exist_ok=True,parents=True);p.write_text('package fixture\n')
    (root/'binary_tokens.odin').write_text('package fixture\nSINGLE_BYTE_TOKENS := [236]string {\n'+',\n'.join(json.dumps(v) for v in values)+',\n}\n')
    contract_path=None
    if approved:
        prefix=root/'tools/protocol_watch/contracts';prefix.mkdir(parents=True,exist_ok=True)
        requirement=prefix/'synthetic-requirement.md'
        requirement.write_text('Synthetic trusted-policy fixture: require the named target dictionary while preserving the legacy default. This test does not authenticate a real review or server requirement.\n')
        fixture=root/'tests/synthetic-table-contract.json';fixture.parent.mkdir(exist_ok=True);fixture.write_text(json.dumps({'required_indices':list(range(change_count))}))
        bind=lambda p:{'path':str(p.relative_to(root)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
        contract=dict(schema=1,source='baileys',path='src/WABinary/constants.ts',target_table_sha256=L.triage.table_sha256(new),requirement=bind(requirement),fixture=bind(fixture))
        target=prefix/'synthetic-target.json';target.write_text(json.dumps(contract));contract_path=str(target.relative_to(root))
    a=L.triage.assess('baileys','src/WABinary/constants.ts',old_bytes,new_bytes,root,approved_contract=contract_path)
    assert a['kind']==('FIX' if approved else 'SPIKE'),a
    value=report(0,0);value['status']='REVIEW_REQUIRED'
    item=next(x for x in value['observation']['sources'][0]['files'] if x['path']=='src/WABinary/constants.ts')
    item.update(reference=L.watch.file_digest(old_bytes),current=L.watch.file_digest(new_bytes),changed_from_reference=True,assessment=a)
    return value


class ApprovedFixture:
    def __init__(self,count=2):self.count=count
    def __enter__(self):
        import tempfile
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.patch=mock.patch.object(L,'LOCAL_ROOT',self.root);self.patch.__enter__()
        return dictionary_report(self.count,approved=True,root=self.root)
    def __exit__(self,*args):self.patch.__exit__(*args);self.tmp.cleanup()


class AdditionalControls(unittest.TestCase):
    def test_real_classifier_fix_produces_ready_implementation_issue(self):
        with ApprovedFixture(40) as value:
            api=API();L.track(value,RUN,api)
        self.assertEqual(len(api.creates),1);p=api.creates[0]
        self.assertTrue(p['title'].startswith('OWA: FIX'));self.assertEqual(p['stateId'],L.READY);self.assertEqual(p['priority'],2)
        self.assertIn('Complete changed indices (40)',p['description']);self.assertIn('truncated: true',p['description'])
        self.assertIn('binary_tokens.odin',p['description']);self.assertIn('Immutable observed:',p['description'])
        self.assertEqual(len(L.v2_coverage(p['description'])),1)
    def test_open_spike_same_change_promotes_once_in_place(self):
        fixture=ApprovedFixture();fixed=fixture.__enter__();self.addCleanup(fixture.__exit__,None,None,None);unknown=copy.deepcopy(fixed)
        for source in unknown['observation']['sources']:
            for item in source['files']:item.pop('assessment',None)
        api=API();L.track(unknown,RUN,api);old=next(iter(api.items.values()));saved=copy.deepcopy(old)
        identity=L.findings(fixed)[0]['id'];self.assertEqual(identity,L.findings(unknown)[0]['id'])
        self.assertEqual(L.track(fixed,RUN,api)['status'],'UPDATED')
        self.assertEqual((len(api.creates),len(api.comment_creates)),(1,1));self.assertEqual(old,saved)
        self.assertIn('FIX readiness',api.comment_creates[0]['body'])
        self.assertEqual(L.track(fixed,RUN,api)['status'],'EXISTING');self.assertEqual(len(api.comment_creates),1)
    def test_closed_spike_same_change_does_not_promote(self):
        fixture=ApprovedFixture();fixed=fixture.__enter__();self.addCleanup(fixture.__exit__,None,None,None);unknown=copy.deepcopy(fixed)
        for s in unknown['observation']['sources']:
            for item in s['files']:item.pop('assessment',None)
        api=API();L.track(unknown,RUN,api);next(iter(api.items.values()))['state']['type']='completed'
        self.assertEqual(L.track(fixed,RUN,api)['status'],'EXISTING');self.assertFalse(api.comment_creates)
    def test_fix_complete_indices_and_proof_invalid_fail_closed(self):
        for key,bad in [('changed_indices',[2,1]),('changes_truncated',True),('outside_tokens_equal',False),('table_count',235),('server_compatibility_proven',True)]:
            fixture=ApprovedFixture();value=fixture.__enter__();self.addCleanup(fixture.__exit__,None,None,None);item=next(x for x in value['observation']['sources'][0]['files'] if x.get('assessment'))
            item['assessment']['evidence'][key]=bad
            with self.assertRaises(L.ReviewError):L.track(value,RUN,lambda *args:self.fail('no API'))
    def test_human_title_rename_keeps_legacy_and_v2_coverage(self):
        for old in [legacy(report()),issue(L.payload_for(L.findings(report()),RUN))]:
            old['title']='Human renamed this investigation';api=API();api.add(old)
            self.assertEqual(L.track(report(),RUN,api)['status'],'EXISTING');self.assertFalse(api.creates)
            L.track(report(revision='c'),RUN,api);self.assertEqual(len(api.comment_creates),1);self.assertEqual(old['title'],'Human renamed this investigation')
        self.assertIn('description:{contains:"owa-protocol-drift:v1:"}',L.SCAN)
        self.assertIn('description:{contains:"owa-protocol-review:v2"}',L.SCAN)
    def test_normalized_legacy_markdown_has_exact_same_coverage(self):
        original=legacy(report(7));normal=copy.deepcopy(original)
        body=normal['description'].replace('\n- ','\n* ').replace('\n  - ','\n  * ')
        body=L.re.sub(r'\((https://github\.com/[^\s)]+)\)',r'(<\1>)',body)
        body=body.replace('Evidence: '+RUN,'Evidence: ['+RUN+'](<'+RUN+'>)')
        normal['description']=body
        self.assertEqual(L.legacy_coverage(original),L.legacy_coverage(normal));self.assertEqual(len(L.legacy_coverage(normal)),7)
    def test_duplicate_legacy_path_or_conflicting_evidence_is_not_coverage(self):
        old=legacy(report());lines=old['description'].splitlines();block='\n'.join(lines[6:9]);old['description']=old['description'].replace(block,block+'\n'+block)
        self.assertFalse(L.legacy_coverage(old))
        old=legacy(report());old['description']=old['description'].replace('Evidence: '+RUN,'Evidence: ['+RUN+'](<https://github.com/dvrd/owa/actions/runs/456>)')
        self.assertFalse(L.legacy_coverage(old))
    def test_lookalike_spike_title_without_binding_never_selected_for_append(self):
        old=issue(dict(id=str(uuid.uuid4()),title='OWA: SPIKE investigate baileys',description='A human task without machine provenance.'))
        api=API();api.add(old);L.track(report(),RUN,api);self.assertFalse(api.comment_creates);self.assertEqual(len(api.creates),1)
    def test_truncated_page_error_prevents_mutation(self):
        api=API()
        def bad(q,v):
            if q==L.SCAN:return {'issues':{'nodes':[]}}
            return api(q,v)
        with self.assertRaisesRegex(L.ReviewError,'PAGINATION_INVALID'):L.track(report(),RUN,bad)
        self.assertFalse(api.creates)
    def test_duplicate_json_and_nonfinite_are_rejected(self):
        for raw in [b'{"schema":2,"schema":2}',b'{"x":NaN}']:
            with self.assertRaises(ValueError):L.decode(raw)
        value=classified(report());value['observation']['sources'][0]['files'][0]['assessment']['evidence']['extra']=float('nan')
        with self.assertRaises(L.ReviewError):L.track(value,RUN,lambda *args:self.fail('no API'))
    def test_invalid_assessment_on_clean_file_is_not_skipped(self):
        value=classified(report(0,0));value['observation']['sources'][0]['files'][0]['assessment']['schema']=2
        with self.assertRaises(L.ReviewError):L.track(value,RUN,lambda *args:self.fail('no API'))
    def test_scan_call_budget_fails_before_mutation(self):
        api=API();api.add(legacy(report()))
        with mock.patch.object(L,'MAX_CALLS',1):
            with self.assertRaisesRegex(L.ReviewError,'SCAN_BOUND'):L.track(report(),RUN,api)
        self.assertFalse(api.creates)

class BoundaryControls(unittest.TestCase):
    def test_duplicate_state_is_terminal_not_an_append_target(self):
        api=API();L.track(report(),RUN,api);next(iter(api.items.values()))['state']['type']='duplicate'
        self.assertEqual(L.track(report(),RUN,api)['status'],'EXISTING')
        L.track(report(revision='c'),RUN,api);self.assertFalse(api.comment_creates);self.assertEqual(len(api.creates),2)
    def test_comment_only_discovery_after_human_title_and_body_change(self):
        api=API();L.track(report(),RUN,api);L.track(report(revision='c'),RUN,api)
        old=next(iter(api.items.values()));old.update(title='Human investigation',description='Keep this human body.')
        base_call=api.__call__
        def filtered(q,v):
            if q==L.SCAN:
                # Provider relation filter matters once neither title nor description match.
                visible=[i for i in api.items.values() if 'OWA:' in i['title'] or 'owa-protocol-' in i['description'] or
                         ('comments:{some:' in q and any(c['issue']['id']==i['id'] and L.BEGIN in c['body'] for c in api.comments.values()))]
                return {'issues':api.page(visible,v['after'],10)}
            return base_call(q,v)
        self.assertEqual(L.track(report(revision='c'),RUN,filtered)['status'],'EXISTING')
        self.assertEqual(len(api.creates),1);L.track(report(revision='d'),RUN,filtered)
        self.assertEqual(len(api.creates),1);self.assertEqual(len(api.comment_creates),2)
    def test_human_prefix_note_keeps_legacy_binding(self):
        old=legacy(report(7));old['description']='Human review notes before machine text.\n\n'+old['description']
        self.assertEqual(len(L.legacy_coverage(old)),7)
    def test_recognized_malformed_v2_fails_instead_of_duplicate_create(self):
        api=API();p=L.payload_for(L.findings(report()),RUN);old=issue(p);old['description']=old['description'].replace('"schema":2','"schema":99');api.add(old)
        with self.assertRaisesRegex(L.ReviewError,'V2_INVALID'):L.track(report(),RUN,api)
        self.assertFalse(api.creates)
        with self.assertRaisesRegex(L.ReviewError,'V2_INVALID'):L.v2_coverage(L.BEGIN+'\npartial')
    def test_byte_identical_denial_with_changed_digests_is_invalid(self):
        with self.assertRaises(L.ReviewError):L.track(classified(report(),reason='BYTE_IDENTICAL'),RUN,lambda *args:self.fail('no API'))
    def test_already_implemented_without_bound_current_table_is_invalid(self):
        for value in [classified(report(),reason='ALREADY_IMPLEMENTED')]:
            with self.assertRaises(L.ReviewError):L.track(value,RUN,lambda *args:self.fail('no API'))
    def test_comment_lookup_never_confirms_two_empty_coverages(self):
        api=API()
        with self.assertRaisesRegex(L.ReviewError,'COMMENT_BINDING_MISMATCH'):
            L.lookup_comment(api,str(uuid.uuid4()),str(uuid.uuid4()),'Malformed body')
        self.assertFalse(api.calls)
    def test_comment_full_body_is_bounded_before_mutation(self):
        api=API();L.track(report(),RUN,api);old=next(iter(api.items.values()))
        with mock.patch.object(L,'machine_section',return_value='x'*L.watch.MAX_REPORT):
            with self.assertRaisesRegex(L.ReviewError,'PAYLOAD_BOUND'):L.append_findings(L.BoundedAPI(api),old,L.findings(report(revision='c')),RUN)
        self.assertFalse(api.comment_creates)
    def test_bool_assessment_schema_is_invalid(self):
        value=classified(report());value['observation']['sources'][0]['files'][0]['assessment']['schema']=True
        with self.assertRaises(L.ReviewError):L.track(value,RUN,lambda *args:self.fail('no API'))

class ProvenanceControls(unittest.TestCase):
    def test_full_v2_manual_claim_on_unbound_issue_fails_closed(self):
        old=issue(L.payload_for(L.findings(report()),RUN));old['id']=str(uuid.uuid4());api=API();api.add(old)
        with self.assertRaisesRegex(L.ReviewError,'V2_BINDING_MISMATCH'):L.track(report(),RUN,api)
        self.assertFalse(api.creates)
    def test_full_v2_manual_comment_on_wrong_id_fails_closed(self):
        api=API();L.track(report(),RUN,api);old=next(iter(api.items.values()));f=L.findings(report(revision='c'))
        cid=str(uuid.uuid4());api.comments[cid]=dict(id=cid,body=L.machine_section(f,RUN),issue={'id':old['id'],'project':{'id':L.PROJECT}})
        with self.assertRaisesRegex(L.ReviewError,'V2_BINDING_MISMATCH'):L.track(report(revision='c'),RUN,api)
        self.assertEqual(len(api.creates),1)
    def test_expired_scan_budget_never_performs_api_call(self):
        api=API()
        with mock.patch.object(L.time,'monotonic',side_effect=[0,121]):
            with self.assertRaisesRegex(L.ReviewError,'SCAN_BUDGET'):L.track(report(),RUN,api)
        self.assertFalse(api.calls)



class ContractGateControls(unittest.TestCase):
    def test_unapproved_table_difference_is_investigation_not_runtime_fix(self):
        value=dictionary_report(40);api=API();L.track(value,RUN,api)
        self.assertEqual(api.creates[0]['stateId'],L.BACKLOG);self.assertEqual(api.creates[0]['priority'],3)
        self.assertTrue(api.creates[0]['title'].startswith('OWA: SPIKE'))
        self.assertIn('Complete changed indices (40)',api.creates[0]['description'])
    def test_source_owned_requirement_is_revalidated_not_boolean_trusted(self):
        with ApprovedFixture() as value:
            item=next(x for x in value['observation']['sources'][0]['files'] if x.get('assessment'))
            proof=item['assessment']['evidence']['approved_contract']
            (L.LOCAL_ROOT/proof['requirement']['path']).write_text('Changed synthetic requirement.')
            with self.assertRaisesRegex(L.ReviewError,'FIX_CONTRACT_INVALID'):L.track(value,RUN,lambda *args:self.fail('no API'))
    def test_owner_source_changed_rejects_new_fix(self):
        with ApprovedFixture() as value:
            (L.LOCAL_ROOT/'binary_node.odin').write_text('package changed_fixture')
            with self.assertRaisesRegex(L.ReviewError,'FIX_CONTRACT_INVALID'):L.track(value,RUN,lambda *args:self.fail('no API'))
    def test_shallow_approval_flag_never_authorizes_fix(self):
        with ApprovedFixture() as value:
            item=next(x for x in value['observation']['sources'][0]['files'] if x.get('assessment'))
            item['assessment']['evidence']['approved_contract']={'approved':True}
            with self.assertRaisesRegex(L.ReviewError,'FIX_CONTRACT_REQUIRED'):L.track(value,RUN,lambda *args:self.fail('no API'))
    def test_contract_target_binding_mismatch_rejects_new_fix(self):
        with ApprovedFixture() as value:
            item=next(x for x in value['observation']['sources'][0]['files'] if x.get('assessment'))
            item['assessment']['evidence']['approved_contract']['target_table_sha256']='f'*64
            with self.assertRaisesRegex(L.ReviewError,'FIX_CONTRACT_REQUIRED'):L.track(value,RUN,lambda *args:self.fail('no API'))
    def test_historical_completed_fix_does_not_monitor_current_source_forever(self):
        api=API()
        with ApprovedFixture() as value:
            L.track(value,RUN,api)
            current=copy.deepcopy(value)
            for source in current['observation']['sources']:
                for item in source['files']:item.pop('assessment',None)
        next(iter(api.items.values()))['state']['type']='completed'
        self.assertEqual(L.track(current,RUN,api)['status'],'EXISTING');self.assertEqual(len(api.creates),1)
    def test_updates_render_readable_investigation_and_immutable_links(self):
        api=API();L.track(report(),RUN,api);L.track(report(revision='c'),RUN,api)
        body=api.comment_creates[0]['body']
        for text in ['Question:','Check:','Accept:','Immutable reference:','Immutable observed:']:
            self.assertIn(text,body)
    def test_approved_fix_promotion_keeps_ready_proof_human_readable(self):
        with ApprovedFixture() as value:
            unknown=dictionary_report(root=L.LOCAL_ROOT);api=API();L.track(unknown,RUN,api)
            result=L.track(value,RUN,api);self.assertEqual(result['status'],'UPDATED')
            body=api.comment_creates[0]['body']
            for text in ['FIX readiness','Complete changed indices','Local target:','Accept:','Immutable observed:']:
                self.assertIn(text,body)
            self.assertEqual(len(api.creates),1)
            self.assertTrue(result['issues'][0]['ready_findings'])
            self.assertEqual(L.track(value,RUN,api)['status'],'EXISTING')



class RoutingScopeControls(unittest.TestCase):
    def scoped_legacy(self):
        api=API();baileys=legacy(report(7,0));baileys['state']['type']='completed'
        mixed=legacy(report(7,1));mixed['identifier']='OKAMI-422';mixed['url']='https://linear.app/devoured/issue/OKAMI-422/review'
        api.add(baileys);api.add(mixed)
        api.comments['scope']=dict(id='scope',body=L.SCOPE_PREFIX+'whatsmeow',issue={'id':mixed['id'],'project':{'id':L.PROJECT}})
        return api,mixed
    def test_new_baileys_delta_does_not_append_to_mixed_whatsmeow_review(self):
        api,mixed=self.scoped_legacy();value=report(7,1)
        value['observation']['sources'][0]['files'][0]['current']['sha256']='c'*64
        L.track(value,RUN,api)
        self.assertEqual(len(api.creates),1);self.assertIn('baileys',api.creates[0]['title']);self.assertFalse(api.comment_creates)
        self.assertEqual(api.items[mixed['id']]['description'],mixed['description'])
    def test_new_whatsmeow_delta_appends_to_scoped_mixed_review(self):
        api,mixed=self.scoped_legacy();value=report(7,1)
        value['observation']['sources'][1]['files'][0]['current']['sha256']='c'*64
        self.assertEqual(L.track(value,RUN,api)['status'],'UPDATED')
        self.assertFalse(api.creates);self.assertEqual(len(api.comment_creates),1)
        self.assertEqual(api.comment_creates[0]['issueId'],mixed['id']);self.assertNotIn('WhiskeySockets',api.comment_creates[0]['body'])
    def test_scope_marker_keeps_all_legacy_coverage_unchanged(self):
        api,mixed=self.scoped_legacy();before=L.legacy_coverage(mixed)
        issues,covered=L.scan(L.BoundedAPI(api));scoped=next(i for i in issues if i['id']==mixed['id'])
        self.assertEqual(scoped['_review_scope'],'whatsmeow');self.assertEqual(scoped['_coverage'],before)
        self.assertEqual(len(covered),8);self.assertEqual(L.track(report(7,1),RUN,api)['status'],'EXISTING')
        self.assertFalse(api.creates);self.assertFalse(api.comment_creates)
    def test_conflicting_scopes_fail_before_any_mutation(self):
        api,mixed=self.scoped_legacy();api.comments['conflict']=dict(id='conflict',body=L.SCOPE_PREFIX+'baileys',issue={'id':mixed['id'],'project':{'id':L.PROJECT}})
        with self.assertRaisesRegex(L.ReviewError,'SCOPE_CONFLICT'):L.track(report(7,1,revision='c'),RUN,api)
        self.assertFalse(api.creates);self.assertFalse(api.comment_creates)
    def test_unknown_scope_value_is_not_a_routing_authority(self):
        api,mixed=self.scoped_legacy();api.comments['scope']['body']=L.SCOPE_PREFIX+'foreign'
        with self.assertRaisesRegex(L.ReviewError,'SCOPE_INVALID'):L.track(report(7,1,revision='c'),RUN,api)
        self.assertFalse(api.creates);self.assertFalse(api.comment_creates)
    def test_fresh_append_rechecks_scope_changed_after_initial_scan(self):
        api=API();L.track(report(),RUN,api);old=next(iter(api.items.values()))
        def changed(api,variables):
            if old['id'] in variables['ids']:
                api.comments['scope']=dict(id='scope',body=L.SCOPE_PREFIX+'whatsmeow',issue={'id':old['id'],'project':{'id':L.PROJECT}})
        api.fresh_hook=changed;L.track(report(revision='c'),RUN,api)
        self.assertEqual(len(api.creates),2);self.assertFalse(api.comment_creates)
    def test_scope_alone_does_not_cover_change_or_authorize_fix(self):
        api=API();old=issue(dict(id=str(uuid.uuid4()),title='OWA: SPIKE human task',description='Unbound human task.'));api.add(old)
        api.comments['scope']=dict(id='scope',body=L.SCOPE_PREFIX+'baileys',issue={'id':old['id'],'project':{'id':L.PROJECT}})
        L.track(report(),RUN,api);self.assertEqual(len(api.creates),1);self.assertEqual(api.creates[0]['stateId'],L.BACKLOG);self.assertFalse(api.comment_creates)

if __name__=='__main__':unittest.main()
