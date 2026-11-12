import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('linear_review', Path(__file__).with_name('linear_review.py'))
L = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(L)
RUN = 'https://github.com/dvrd/owa/actions/runs/123'


def report(changed=True):
    sources = []
    for source in L.watch.manifest_read(L.HERE/'sources.json')['sources']:
        actual = {k: source[k] for k in ('name', 'repository', 'reference_commit')}
        actual.update(head_commit='1'*40, files=[])
        for index, path in enumerate(source['paths']):
            reference = {'present': True, 'bytes': 10, 'sha256': 'a'*64}
            current = {**reference, 'sha256': 'b'*64} if changed and index == 0 else dict(reference)
            actual['files'].append({'path': path, 'reference': reference, 'current': current,
                                    'changed_from_reference': current != reference})
        sources.append(actual)
    return {'status': 'REVIEW_REQUIRED' if changed else 'NO_MONITORED_DRIFT',
            'compatibility_approved': False, 'runtime_version_changed': False,
            'observation': {'sources': sources}}


class API:
    def __init__(self): self.items = {}; self.creates = []; self.lose_reply = False
    def __call__(self, query, variables):
        if query == L.LOOKUP:
            return {'issues': {'nodes': [self.items[i] for i in variables['ids'] if i in self.items]}}
        if query != L.CREATE: raise AssertionError('Unexpected mutation')
        value = variables['input']; self.creates.append(copy.deepcopy(value))
        self.items[value['id']] = {'id': value['id'], 'project': {'id': value['projectId']},
            'description': value['description'], 'identifier': 'OKAMI-123',
            'url': 'https://linear.app/devoured/issue/OKAMI-123/review'}
        if self.lose_reply: raise L.ReviewError('LINEAR_REQUEST_FAILED')
        return {'issueCreate': {'success': True}}


class Tests(unittest.TestCase):
    def test_create_then_repeat_uses_one_backlog_issue(self):
        api = API()
        first = L.track(report(), RUN, api); second = L.track(report(), RUN, api)
        self.assertEqual((first['status'], second['status']), ('CREATED', 'EXISTING'))
        self.assertEqual(len(api.creates), 1)
        self.assertEqual(api.creates[0]['stateId'], L.BACKLOG)
        self.assertEqual(api.creates[0]['projectId'], L.PROJECT)
        self.assertIn('Create scoped Webtools fix issues', api.creates[0]['description'])

    def test_unrelated_heads_and_observation_times_do_not_make_new_issue(self):
        first = report(); second = copy.deepcopy(first)
        second['observation']['sources'][0]['head_commit'] = '2'*40
        second['observation']['checked_at_unix'] = 999
        self.assertEqual(L.ticket(first, RUN)[0], L.ticket(second, RUN)[0])

    def test_new_monitored_content_makes_new_issue(self):
        first = report(); second = copy.deepcopy(first)
        second['observation']['sources'][0]['files'][0]['current']['sha256'] = 'c'*64
        self.assertNotEqual(L.ticket(first, RUN)[0], L.ticket(second, RUN)[0])

    def test_closed_archived_issue_is_reused_without_reopening(self):
        api = API(); L.track(report(), RUN, api)
        for item in api.items.values(): item['state'] = {'type': 'completed'}
        self.assertEqual(L.track(report(), RUN, api)['status'], 'EXISTING')
        self.assertEqual(len(api.creates), 1)

    def test_lost_mutation_response_queries_without_duplicate_create(self):
        api = API(); api.lose_reply = True
        self.assertEqual(L.track(report(), RUN, api)['status'], 'EXISTING')
        self.assertEqual(len(api.creates), 1)

    def test_uncertain_uncommitted_write_not_retried_in_invocation(self):
        api = API(); creates = []
        def lost(query, variables):
            if query == L.CREATE:
                creates.append(variables['input']['id']); raise L.ReviewError('network')
            return api(query, variables)
        with self.assertRaisesRegex(L.ReviewError, 'OUTCOME_UNKNOWN'): L.track(report(), RUN, lost)
        self.assertEqual(len(creates), 1)
        L.track(report(), RUN, api)
        self.assertEqual(creates[0], api.creates[0]['id'])

    def test_lookup_network_failure_never_creates(self):
        def fail(*_): raise L.ReviewError('LINEAR_REQUEST_FAILED')
        with self.assertRaises(L.ReviewError): L.track(report(), RUN, fail)

    def test_wrong_project_or_marker_fails_closed(self):
        for field in ('project', 'description'):
            api = API(); L.track(report(), RUN, api)
            for item in api.items.values(): item[field] = {'id': 'wrong'} if field == 'project' else 'wrong'
            with self.assertRaisesRegex(L.ReviewError, 'BINDING_MISMATCH'): L.track(report(), RUN, api)
            self.assertEqual(len(api.creates), 1)

    def test_clean_scan_does_not_call_linear(self):
        def fail(*_): raise AssertionError('Linear must not be called')
        self.assertEqual(L.track(report(False), RUN, fail)['status'], 'NO_REVIEW_NEEDED')

    def test_failed_scan_and_injected_paths_never_call_linear(self):
        def fail(*_): raise AssertionError('Linear must not be called')
        for mutation in ('failed', 'path', 'approve', 'bad_digest'):
            value = report()
            if mutation == 'failed': value['status'] = 'FAILED'
            if mutation == 'path': value['observation']['sources'][0]['files'][0]['path'] = 'injected)\ntext'
            if mutation == 'approve': value['compatibility_approved'] = True
            if mutation == 'bad_digest': value['observation']['sources'][0]['files'][0]['current']['sha256'] = 'invalid'
            with self.assertRaises(L.ReviewError): L.track(value, RUN, fail)

    def test_run_url_is_pinned_to_owa(self):
        with self.assertRaisesRegex(L.ReviewError, 'RUN_URL_INVALID'):
            L.ticket(report(), 'https://example.com/injected')

    def test_inconsistent_clean_status_fails_before_linear(self):
        value = report(); value['status'] = 'NO_MONITORED_DRIFT'
        with self.assertRaisesRegex(L.ReviewError, 'STATUS_INVALID'): L.track(value, RUN)

    def test_network_client_redacts_api_errors_and_refuses_redirects(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({
            'errors': [{'message': 'private-key-from-response'}]}).encode()
        opener = mock.Mock(); opener.open.return_value = response
        with mock.patch.dict(L.os.environ, {'LINEAR_API': 'private-test-key'}):
            with mock.patch.object(L.urllib.request, 'build_opener', return_value=opener):
                with self.assertRaisesRegex(L.ReviewError, '^LINEAR_REQUEST_FAILED$'):
                    L.request(L.LOOKUP, {'ids': []})
        req = opener.open.call_args.args[0]
        self.assertEqual(req.full_url, 'https://api.linear.app/graphql')
        self.assertIsNone(L.NoRedirect().redirect_request(None, None, None, None, None, None))


if __name__ == '__main__': unittest.main()
