import io
import json
import stat
import unittest
import zipfile
from aegis.engine import collect, run_review, safe_name, MAX_FILES
GOOD = {'session': {'cookieSecure': True, 'cookieHttpOnly': True, 'idleTimeoutMinutes': 30}, 'transport': {'httpsOnly': True}, 'headers': {'nosniff': True}, 'runtime': {'debug': False}, 'logging': {'auditEnabled': True}}
def review(value):
    return run_review('security.config.json', json.dumps(value).encode())
def zipped(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as z:
        for name, data in entries:
            z.writestr(name, data)
    return stream.getvalue()
class ReviewTests(unittest.TestCase):
    def test_matching_policy_and_six_specialists(self):
        result = review(GOOD)
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['coverage']['passed'], 7)
        self.assertEqual(len(result['reports']), 6)
        self.assertFalse(result['llm_connected'])
    def test_mismatch_patch_and_no_sensitive_value(self):
        config = json.loads(json.dumps(GOOD))
        config['runtime']['debug'] = True
        config['secret'] = 'never-export-this-secret'
        result = review(config)
        finding, = result['findings']
        self.assertEqual(finding['proposed_patch'], {'op':'replace','path':'/runtime/debug','value':False})
        self.assertEqual(finding['judgment'], 'policy_mismatch')
        self.assertNotIn('never-export-this-secret', json.dumps(result))
        self.assertTrue(config['runtime']['debug'])
    def test_missing_settings_are_not_confirmed_findings(self):
        result = review({})
        self.assertEqual(result['coverage']['unknown'], 7)
        self.assertTrue(all(f['judgment'] == 'needs_context' and f['proposed_patch'] is None for f in result['findings']))
    def test_wrong_type_is_unknown(self):
        config = json.loads(json.dumps(GOOD))
        config['runtime']['debug'] = 'false'
        self.assertEqual(review(config)['findings'][0]['judgment'], 'needs_context')
    def test_timeout_boolean_is_unknown(self):
        config = json.loads(json.dumps(GOOD))
        config['session']['idleTimeoutMinutes'] = True
        self.assertEqual(review(config)['coverage']['unknown'], 1)
    def test_source_is_inventory_only(self):
        result = run_review('main.py', b'raise RuntimeError("must never execute")')
        self.assertEqual(result['coverage']['checks'], 0)
        self.assertEqual(len(result['skipped']), 1)
    def test_paths_rejected(self):
        for path in ['../x', '/x', 'C:/x', 'a\\x', 'a\nx']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                safe_name(path)
    def test_zip_traversal_rejected(self):
        with self.assertRaises(ValueError):
            collect('project.zip', zipped([('../outside', 'x')]))
    def test_zip_symlink_rejected(self):
        entry = zipfile.ZipInfo('link')
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaises(ValueError):
            collect('project.zip', zipped([(entry, 'target')]))
    def test_zip_entry_limit(self):
        with self.assertRaises(ValueError):
            collect('project.zip', zipped([(f'{i}.txt', '') for i in range(MAX_FILES + 1)]))
    def test_zip_file_size_limit(self):
        with self.assertRaises(ValueError):
            collect('project.zip', zipped([('huge.txt', 'x' * (512 * 1024 + 1))]))
    def test_nested_config(self):
        result = run_review('project.zip', zipped([('app/security.config.json', json.dumps(GOOD)), ('app/index.js', 'console.log(1)')]))
        self.assertEqual(result['coverage']['passed'], 7)
        self.assertEqual(len(result['skipped']), 1)
    def test_invalid_json_skipped(self):
        result = run_review('security.config.json', b'{broken')
        self.assertEqual(result['coverage']['config_files'], 0)
        self.assertEqual(len(result['skipped']), 1)
    def test_sarif_unverified_and_redacted(self):
        doc = {'version':'2.1.0','runs':[{'results':[{'ruleId':'R1','level':'warning','message':{'text':'sensitive snippet'}}]}]}
        result = run_review('results.sarif', json.dumps(doc).encode())
        self.assertEqual(result['findings'][0]['judgment'], 'external_unverified')
        self.assertNotIn('sensitive snippet', json.dumps(result))
    def test_invalid_sarif_skipped(self):
        result = run_review('bad.sarif', b'{"version":"2.1.0","runs":false}')
        self.assertEqual(len(result['skipped']), 1)
    def test_ids_stable(self):
        self.assertEqual([f['id'] for f in review({})['findings']], [f['id'] for f in review({})['findings']])
