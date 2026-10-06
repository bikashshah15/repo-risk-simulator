#!/usr/bin/env python3
"""Offline regression checks; no packages, network, or repository execution."""
import sys
sys.dont_write_bytecode = True  # keep the installed skill folder free of __pycache__
import argparse
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib import error
import demo
import risk


class RiskTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)
        self.state, self.analysis = demo.make_demo(self.out)

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_demo(self):
        state, analysis = risk.validated(self.out)
        self.assertEqual(len(analysis['scenarios']), 3)
        self.assertTrue(state['demo'])

    def test_purl_identity(self):
        q, reason = risk.package_query('pkg:maven/org.example/demo@1.2.3', '1.2.3')
        self.assertIsNone(reason)
        self.assertEqual(q['package']['name'], 'org.example:demo')
        q, _ = risk.package_query('pkg:npm/%40scope/demo@1.2.3', None)
        self.assertEqual(q['package']['name'], '@scope/demo')
        q, _ = risk.package_query('pkg:pypi/test@1.2.3', '1.2.4')
        self.assertIsNone(q)
        for purl, version in [('pkg:pypi/test', '>=1.0'), ('pkg:github/a/b@abc', None),
                              ('pkg:pypi/test@1.0?foo=bar', None), ('pkg:pypi/test', None), (None, '1.0')]:
            self.assertIsNone(risk.package_query(purl, version)[0])

    def test_repo_and_paths(self):
        self.assertEqual(risk.repo_name('https://github.com/owner/repo.git'), 'owner/repo')
        for name in ['https://evil.test/a/b','owner/repo/extra','https://github.com/a/b?token=secret']:
            with self.assertRaises(ValueError): risk.repo_name(name)
        for name in ['../a','/etc/passwd','a/../b','a\\b']:
            with self.assertRaises(ValueError): risk.path_ok(name)

    def test_alias_union_bridge(self):
        groups=risk.alias_groups([{'id':'A','aliases':['X']},{'id':'B','aliases':['Y']},{'id':'C','aliases':['X','Y']}])
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0][1]), 3)

    def test_batch_pagination(self):
        replies=[(200,{'results':[{'vulns':[{'id':'A'}],'next_page_token':'NEXT'},{'vulns':[{'id':'B'}]}]}),
                 (200,{'results':[{'vulns':[{'id':'C'}]}]})]
        with patch.object(risk,'api',side_effect=replies) as api:
            result=risk.batch_matches([{'version':'1','package':{'name':'a'}},{'version':'2','package':{'name':'b'}}])
            self.assertEqual(result,[['A','C'],['B']])
            self.assertEqual(api.call_args_list[1].args[1]['queries'][0]['page_token'],'NEXT')
            self.assertEqual(len(api.call_args_list[1].args[1]['queries']),1)

    def test_batch_bad_count(self):
        with patch.object(risk,'api',return_value=(200,{'results':[]})):
            with self.assertRaises(risk.APIError):risk.batch_matches([{'version':'1'}])

    def test_query_errors_are_visible(self):
        with patch.object(risk,'api',side_effect=risk.APIError('HTTP 503')):
            risk.lookup(argparse.Namespace(run=str(self.out),refresh=True))
        state=risk.read(self.out/'run.json')
        self.assertTrue(all(p['status']=='error' for p in state['packages']))
        self.assertEqual(state['findings'],[])

    def test_withdrawn_and_alias_records(self):
        records={'A':{'id':'A','aliases':['CVE-SYNTHETIC'],'summary':'A'},
                 'B':{'id':'B','aliases':['CVE-SYNTHETIC'],'summary':'B'},
                 'C':{'id':'C','withdrawn':'2026-01-01'}}
        def api(url,payload=None):
            if url.endswith('querybatch'):return 200,{'results':[{'vulns':[{'id':k} for k in records]} for _ in payload['queries']]}
            return 200,records[url.rsplit('/',1)[1]]
        with patch.object(risk,'api',side_effect=api):risk.lookup(argparse.Namespace(run=str(self.out),refresh=True))
        state=risk.read(self.out/'run.json')
        self.assertEqual(len(state['findings']),3)
        self.assertEqual(state['findings'][0]['advisory_ids'],['A','B'])
        self.assertEqual(state['packages'][0]['withdrawn_ids'],['C'])

    def test_fetch_pending_then_ready(self):
        state=copy.deepcopy(self.state)
        state.update(sbom_status='pending',sbom_fetch_url='https://api.github.com/repos/synthetic/training-fixture/dependency-graph/sbom/fetch-report/job')
        replies=[(202,None),(200,risk.read(self.out/'sbom.json')),(200,{'sha':state['repository']['source_commit']})]
        with patch.object(risk,'api',side_effect=replies),patch.object(risk.time,'sleep'):
            risk.fetch_run(self.out,state,2)
        self.assertEqual(state['sbom_status'],'ready')
        self.assertEqual(state['repository']['alignment'],'unverified')

    def test_bad_references_rejected(self):
        self.analysis['scenarios'][0]['evidence_ids'].append('FAKE')
        risk.save(self.out/'analysis.json',self.analysis)
        with self.assertRaises(ValueError):risk.validated(self.out)

    def test_assumption_cannot_start_true(self):
        self.analysis['scenarios'][0]['prerequisites'][1]['initial']='true'
        risk.save(self.out/'analysis.json',self.analysis)
        with self.assertRaises(ValueError):risk.validated(self.out)

    def test_observed_requires_evidence(self):
        self.analysis['scenarios'][0]['prerequisites'][0]['evidence_ids']=[]
        risk.save(self.out/'analysis.json',self.analysis)
        with self.assertRaises(ValueError):risk.validated(self.out)

    def test_source_tampering_detected(self):
        self.state['evidence'][-1]['excerpt']='fabricated'
        risk.save(self.out/'run.json',self.state)
        with self.assertRaises(ValueError):risk.validated(self.out)

    def test_three_scenario_cap_and_distinct_findings(self):
        self.analysis['scenarios'].append(copy.deepcopy(self.analysis['scenarios'][0]))
        risk.save(self.out/'analysis.json',self.analysis)
        with self.assertRaises(ValueError):risk.validated(self.out)

    def test_outcome_truth_table(self):
        controls=[{'id':'exposed','required_value':True},{'id':'mitigated','required_value':False}]
        for values,result in [({'exposed':'unknown','mitigated':'unknown'},'unknown'),
                              ({'exposed':'true','mitigated':'false'},'satisfied'),
                              ({'exposed':'true','mitigated':'true'},'blocked'),
                              ({'exposed':'false','mitigated':'unknown'},'blocked')]:
            self.assertEqual(risk.evaluate(controls,values),result)

    def test_html_injection_is_escaped(self):
        self.analysis['selection_notes']='</script><img src="https://evil.test/x" onerror="alert(1)">'
        risk.save(self.out/'analysis.json',self.analysis)
        risk.render(argparse.Namespace(run=str(self.out)))
        text=(self.out/'report.html').read_text()
        self.assertNotIn('</script><img',text)
        self.assertIn('\\u003c/script\\u003e',text)
        self.assertIn("connect-src 'none'",text)
        self.assertNotIn('innerHTML',text)

    def test_zero_scenarios_allowed(self):
        self.analysis['scenarios']=[]
        risk.save(self.out/'analysis.json',self.analysis)
        risk.render(argparse.Namespace(run=str(self.out)))
        self.assertTrue((self.out/'report.html').exists())

    def test_analysis_init_preserves_existing(self):
        with self.assertRaises(ValueError):risk.init_analysis(argparse.Namespace(run=str(self.out)))

    def test_strict_schema(self):
        for change in [{'schema_version':True}, {'unexpected':'value'}]:
            analysis=copy.deepcopy(self.analysis)
            analysis.update(change)
            risk.save(self.out/'analysis.json',analysis)
            with self.assertRaises(ValueError):risk.validated(self.out)

    def test_canonical_repository_case(self):
        def api(url,payload=None):
            if url.endswith('/repos/PSF/Requests'):
                return 200,{'full_name':'psf/requests','default_branch':'main'}
            if '/commits/' in url:
                return 200,{'sha':'a'*40}
            if url.endswith('/generate-report'):
                return 201,{'sbom_url':'https://api.github.com/repos/psf/requests/dependency-graph/sbom/fetch-report/job'}
            if '/fetch-report/' in url:
                return 200,risk.read(self.out/'sbom.json')
            raise AssertionError(url)
        args=argparse.Namespace(repo='https://github.com/PSF/Requests',out=str(self.out/'case-run'),ref=None,sbom=None,polls=1)
        with patch.object(risk,'api',side_effect=api):risk.collect(args)
        self.assertEqual(risk.read(self.out/'case-run/run.json')['repository']['name'],'psf/requests')


    # --- v1.1.0 regression tests ---
    def root_sbom(self, extra=()):
        packages=[{'SPDXID':'SPDXRef-root','name':'com.github.o/r','versionInfo':'main','externalRefs':[
            {'referenceType':'purl','referenceLocator':'pkg:github/o/r@main'}]}]+list(extra)
        return {'spdxVersion':'SPDX-2.3','SPDXID':'SPDXRef-DOCUMENT','packages':packages,
                'relationships':[{'spdxElementId':'SPDXRef-DOCUMENT','relatedSpdxElement':'SPDXRef-root','relationshipType':'DESCRIBES'}]}

    def test_root_package_is_not_a_dependency(self):
        dep={'SPDXID':'SPDXRef-dep','name':'left-pad','versionInfo':'1.3.0','externalRefs':[
            {'referenceType':'purl','referenceLocator':'pkg:npm/left-pad@1.3.0'}]}
        _,packages,_=risk.normalize(self.root_sbom([dep]))
        self.assertEqual([p['status'] for p in packages],['root','pending'])
        self.assertIsNone(packages[0]['query'])

    def test_zero_dependency_warning(self):
        state={'warnings':[]}
        risk.store_sbom(self.out/'zero',state,self.root_sbom())
        self.assertTrue(any('lists no dependencies' in w for w in state['warnings']))
        risk.store_sbom(self.out/'zero',state,self.root_sbom())
        self.assertEqual(sum('lists no dependencies' in w for w in state['warnings']),1)

    def test_lookup_with_nothing_queryable_records_zero_queries(self):
        state=risk.read(self.out/'run.json')
        _,packages,evidence=risk.normalize(self.root_sbom())
        state.update(packages=packages,evidence=evidence,findings=[])
        risk.save(self.out/'run.json',state)
        with patch.object(risk,'api',side_effect=AssertionError('no network expected')):
            risk.lookup(argparse.Namespace(run=str(self.out),refresh=False))
        osv=risk.read(self.out/'run.json')['osv']
        self.assertEqual((osv['queryable_packages'],osv['queries_attempted']),(0,0))

    def test_lookup_counts_queries_and_errors(self):
        with patch.object(risk,'api',side_effect=risk.APIError('HTTP 503')):
            risk.lookup(argparse.Namespace(run=str(self.out),refresh=True))
        osv=risk.read(self.out/'run.json')['osv']
        self.assertEqual((osv['queries_attempted'],osv['query_errors']),(3,3))

    def test_context_notes_validated(self):
        sid=next(e['id'] for e in self.state['evidence'] if e['kind']=='source')
        self.analysis['context_notes']=[{'text':'Unversioned dependency declared in documentation.','evidence_ids':[sid]}]
        risk.save(self.out/'analysis.json',self.analysis)
        risk.validated(self.out)
        for bad in [[{'text':'x','evidence_ids':['FAKE']}],[{'text':'x','evidence_ids':[]}],[{'text':'x','evidence_ids':[sid],'extra':1}]]:
            self.analysis['context_notes']=bad
            risk.save(self.out/'analysis.json',self.analysis)
            with self.assertRaises(ValueError):risk.validated(self.out)

    def test_supplied_sbom_provenance_and_head_check(self):
        sbom_path=self.out/'supplied.json'
        risk.save(sbom_path,{'sbom':self.root_sbom()})
        def api(url,payload=None):
            if url.endswith('/repos/o/r'):return 200,{'full_name':'o/r','default_branch':'main'}
            if '/commits/' in url:return 200,{'sha':'b'*40}
            raise AssertionError(url)
        args=argparse.Namespace(repo='o/r',out=str(self.out/'supplied-run'),ref=None,sbom=str(sbom_path),polls=1,
                                sbom_source='GitHub synchronous SBOM endpoint',sbom_retrieved_at='2026-10-06T14:45:13Z')
        with patch.object(risk,'api',side_effect=api):risk.collect(args)
        state=risk.read(self.out/'supplied-run/run.json')
        self.assertEqual(state['sbom_provenance']['source'],'GitHub synchronous SBOM endpoint')
        self.assertEqual(state['sbom_provenance']['retrieved_at'],'2026-10-06T14:45:13Z')
        self.assertEqual(state['repository']['head_after_export'],'b'*40)
        self.assertEqual(state['packages'][0]['status'],'root')

    def test_proxy_refusal_message(self):
        msg=risk.network_message('api.osv.dev',error.URLError(OSError('Tunnel connection failed: 403 Forbidden')))
        self.assertIn('egress allowlist',msg)
        self.assertIn('api.osv.dev',msg)
        self.assertNotIn('Tunnel',msg)

    def test_probe_distinguishes_http_from_network_failure(self):
        class Opener:
            def __init__(self,exc):self.exc=exc
            def open(self,*a,**k):raise self.exc
        http404=error.HTTPError('https://api.osv.dev/x',404,'nf',{},None)
        with patch.object(risk.request,'build_opener',return_value=Opener(http404)):
            self.assertTrue(risk.probe('https://api.osv.dev/x')['reachable'])
        with patch.object(risk.request,'build_opener',return_value=Opener(error.URLError(OSError('Tunnel connection failed: 403')))):
            result=risk.probe('https://api.osv.dev/x')
            self.assertFalse(result['reachable'])
            self.assertIn('egress',result['error'])

    def test_report_shows_evidence_index_and_context_notes(self):
        sid=next(e['id'] for e in self.state['evidence'] if e['kind']=='source')
        self.analysis['context_notes']=[{'text':'Context only.','evidence_ids':[sid]}]
        risk.save(self.out/'analysis.json',self.analysis)
        risk.render(argparse.Namespace(run=str(self.out)))
        text=(self.out/'report.html').read_text()
        self.assertIn('id="evidenceIndex"',text)
        self.assertIn('Context notes (not advisory findings)',text)
        self.assertIn('value="root"',text)


if __name__=='__main__':unittest.main(verbosity=2)
