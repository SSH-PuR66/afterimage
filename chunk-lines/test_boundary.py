"""Check evidence freshness, exact wheel identity, and bounded behavior."""
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest
from urllib.parse import urlsplit
import zipfile

from run_boundary import HERE,run


class Links(HTMLParser):
    def __init__(self,text):
        super().__init__()
        self.ids=[]
        self.hrefs=[]
        self.feed(text)
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if 'id' in attrs: self.ids.append(attrs['id'])
        if 'href' in attrs: self.hrefs.append(attrs['href'])


class BoundaryChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.saved=json.loads((HERE/'results.json').read_text(encoding='utf-8'))
        cls.fresh=run(HERE/'.cache'/'wheels')
        cls.pins=json.loads((HERE/'pinned-releases.json').read_text(encoding='utf-8'))
    def cases(self,version):
        row=next(v for v in self.fresh['versions'] if v['version']==version)
        return {(case['api'],case['case']):case for case in row['cases']}

    def test_fresh_run_matches_published_observations(self):
        for key in ('cve','ghsa','classification','source_sha256','cases_per_version',
                    'total_cases_passed','maximum_fixture_input_bytes'):
            self.assertEqual(self.saved[key],self.fresh[key],key)
        for version in self.saved['versions']:
            fresh=next(v for v in self.fresh['versions'] if v['version']==version['version'])
            self.assertEqual(version['cases'],fresh['cases'])

    def test_source_hashes_are_current(self):
        for name,digest in self.saved['source_sha256'].items():
            self.assertEqual(hashlib.sha256((HERE/name).read_bytes()).hexdigest(),digest,name)

    def test_exact_wheel_and_module_identities(self):
        for release in self.pins['releases']:
            wheel=HERE/'.cache'/'wheels'/release['filename']
            self.assertEqual(wheel.stat().st_size,release['size_bytes'])
            self.assertEqual(hashlib.sha256(wheel.read_bytes()).hexdigest(),release['sha256'])
            with zipfile.ZipFile(wheel) as archive:
                self.assertEqual(hashlib.sha256(archive.read('urllib3/response.py')).hexdigest(),release['response_py_sha256'])
            row=next(v for v in self.fresh['versions'] if v['version']==release['version'])
            self.assertTrue(row['import_origin_verified'])

    def test_tampered_wheel_is_rejected_before_execution(self):
        with TemporaryDirectory() as directory:
            release=self.pins['releases'][0]
            original=HERE/'.cache'/'wheels'/release['filename']
            corrupted=bytearray(original.read_bytes())
            corrupted[0]^=1
            (Path(directory)/release['filename']).write_bytes(corrupted)
            with self.assertRaisesRegex(ValueError,'identity mismatch'): run(directory)

    def test_both_public_apis_exercise_accepted_boundary(self):
        for method in ('stream','read_chunked'):
            for version in ('2.7.0','2.8.0'):
                cases=self.cases(version)
                for name in ('ordinary','size_below','size_at','trailer_at'):
                    self.assertEqual(cases[method,name]['outcome'],'accepted')

    def test_size_rejection_precedes_any_body_read(self):
        old=self.cases('2.7.0'); fixed=self.cases('2.8.0')
        for method in ('stream','read_chunked'):
            for name in ('size_above','size_two_above'):
                self.assertEqual(old[method,name]['outcome'],'accepted')
                case=fixed[method,name]
                self.assertEqual(case['outcome'],'rejected')
                self.assertEqual(case['first_line'],{'requested':65537,'returned':65537})
                self.assertEqual(case['body_bytes_yielded'],0)
                self.assertEqual(case['file_read_bytes_before_end'],0)
                self.assertTrue(case['file_closed'] and case['response_closed'])

    def test_trailer_rejection_occurs_after_body_delivery(self):
        old=self.cases('2.7.0'); fixed=self.cases('2.8.0')
        for method in ('stream','read_chunked'):
            self.assertEqual(old[method,'trailer_two_above']['outcome'],'accepted')
            case=fixed[method,'trailer_two_above']
            self.assertEqual(case['outcome'],'rejected')
            self.assertEqual(case['body_bytes_yielded'],1)
            self.assertEqual(case['last_line'],{'requested':65537,'returned':65537})
            self.assertTrue(case['response_closed'])

    def test_body_size_has_an_independent_budget(self):
        for version in ('2.7.0','2.8.0'):
            for method in ('stream','read_chunked'):
                case=self.cases(version)[method,'body_above_line_limit']
                self.assertEqual(case['outcome'],'accepted')
                self.assertEqual(case['body_bytes_yielded'],65537)
                self.assertEqual(case['body_read_request_bytes'],1024)

    def test_network_guard_and_fixed_input_budget(self):
        self.assertEqual(self.fresh['network_attempts_during_cases'],0)
        self.assertLessEqual(self.fresh['maximum_fixture_input_bytes'],70000)
        for version in self.fresh['versions']:
            self.assertEqual(version['network_attempts'],0)
            self.assertTrue(all(event=='socket.__new__' for event in version['import_network_probes_blocked']))

    def test_public_summary_does_not_overclaim_impact(self):
        review=json.loads((HERE/'source-review.json').read_text(encoding='utf-8'))
        self.assertTrue(review['verification']['successful_runtime_regression'])
        self.assertFalse(review['verification']['memory_exhaustion_demonstrated'])
        self.assertFalse(review['verification']['application_exploitability_established'])
        self.assertFalse(review['verification']['new_discovery_claimed'])
        self.assertEqual(review['runtime_evidence']['total_cases_passed'],self.fresh['total_cases_passed'])

    def test_public_page_links_and_table_semantics(self):
        html=(HERE/'index.html').read_text(encoding='utf-8')
        parsed=Links(html)
        self.assertEqual(len(parsed.ids),len(set(parsed.ids)))
        for href in parsed.hrefs:
            if href.startswith('#'): self.assertIn(href[1:],parsed.ids)
            elif not urlsplit(href).scheme and not href.startswith('/'):
                self.assertTrue((HERE/href).exists(),href)
        self.assertIn('<caption>',html)
        self.assertIn('scope="col"',html)
        self.assertIn('Afterimage / Chunk Lines',html)
        self.assertNotIn('Runtime reproduction unverified',html)

    def test_public_evidence_contains_no_workstation_paths(self):
        for name in ('results.json','source-review.json','pinned-releases.json'):
            text=(HERE/name).read_text(encoding='utf-8')
            self.assertNotRegex(text,r'(?i)[A-Z]:[\\/](?:Users|Documents and Settings)[\\/]')


if __name__=='__main__': unittest.main()
