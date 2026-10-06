#!/usr/bin/env python3
"""Create clearly labeled synthetic fixtures for an offline demonstration."""
import argparse
import sys
from pathlib import Path
sys.dont_write_bytecode = True  # keep the installed skill folder free of __pycache__
import risk


def make_demo(out):
    out = Path(out)
    if (out / 'run.json').exists():
        raise ValueError('Demo output already exists; choose a new directory.')
    names = ['training-parser', 'training-token', 'training-extractor']
    sbom = {'spdxVersion':'SPDX-2.3','SPDXID':'SPDXRef-DOCUMENT','name':'SYNTHETIC TRAINING FIXTURE',
        'creationInfo':{'created':risk.now()},'packages':[
        {'SPDXID':'SPDXRef-'+str(i),'name':n,'versionInfo':'1.0.0','externalRefs':[
            {'referenceType':'purl','referenceLocator':'pkg:pypi/'+n+'@1.0.0'}]} for i,n in enumerate(names)]}
    sbom, packages, evidence = risk.normalize(sbom)
    text = '\n'.join(['# SYNTHETIC TRAINING FIXTURE: illustrative calls, never executed.',
        'result = training_parser.parse(user_input)',
        'claims = training_token.verify(user_token)',
        'training_extractor.unpack(user_archive)'])+'\n'
    commit = '0'*40
    state = {'schema_version':1,'tool_version':risk.VERSION,'demo':True,'collected_at':risk.now(),
        'lookup_at':risk.now(),'repository':{'name':'synthetic/training-fixture','url':'https://github.com/synthetic/training-fixture',
        'default_branch':'main','requested_ref':'main','source_commit':commit,'private':False,'alignment':'unverified'},
        'sbom_status':'ready','packages':packages,'findings':[],'evidence':evidence,
        'warnings':['All packages, advisories, and source evidence are synthetic. No live scan was performed.',
                    'Source/SBOM correspondence is unverified.'],'sbom_sha256':risk.digest(sbom)}
    labels = ['Parser input boundary','Token verification boundary','Archive destination boundary']
    impacts = ['The modeled parser operation could consume excessive resources.',
               'The modeled verifier could accept an invalid token under the stated assumptions.',
               'The modeled extraction operation could write outside its intended directory.']
    scenarios, assessments, cache = [], [], {}
    source_hash=risk.digest(text.encode())
    for i,p in enumerate(packages):
        vid='SIM-ADVISORY-'+str(i+1)
        record={'id':vid,'summary':'SYNTHETIC advisory for '+p['name'],
                'details':'Invented teaching fixture. Assumes an affected operation and a documented mitigation; no real package or CVE is asserted.',
                'aliases':[],'affected':[],'severity':[]}
        cache[vid]={'retrieved_at':risk.now(),'record':record}
        p.update(status='matched',advisory_ids=[vid],queried_at=risk.now(),query_sha256=risk.digest(p['query']),reason=None,withdrawn_ids=[],record_errors=[])
        aid='ADV-'+vid;sid='SRC-DEMO-'+str(i+1);fid='F-DEMO-'+str(i+1)
        state['evidence'].append({'id':aid,'kind':'advisory','advisory_id':vid,'location':'synthetic fixture '+vid,'excerpt':record['details'],'sha256':risk.digest(record)})
        state['evidence'].append({'id':sid,'kind':'source','location':'synthetic/app.py','start':i+2,'end':i+2,
                                 'commit':commit,'sha256':source_hash,'excerpt':text.splitlines()[i+1]})
        refs=[p['evidence_id'],aid];allrefs=refs+[sid]
        state['findings'].append({'id':fid,'package_id':p['id'],'advisory_ids':[vid],'aliases':[vid],
                                 'summary':record['summary'],'severity':[],'evidence_ids':refs,'records_complete':True})
        assessments.append({'finding_id':fid,'status':'unknown','rationale':'Synthetic source illustrates a call; exposure and deployment are unknown.',
                            'evidence_ids':allrefs,'limitations':['Invented demonstration, not a real vulnerability assessment.']})
        scenarios.append({'id':'S'+str(i+1),'finding_id':fid,'title':labels[i],'evidence_ids':allrefs,
            'facts':[{'text':'The synthetic inventory lists '+p['name']+' at 1.0.0.','evidence_ids':[p['evidence_id']]},
                     {'text':'The illustrative source contains a conceptual dependency call.','evidence_ids':[sid]}],
            'assumptions':['Assume the advisory-described operation is used in a deployed application.'],
            'unknowns':['Deployment exposure and the mitigation state are unknown.'],
            'application_evidence_gap':'Synthetic source is illustrative. There is no deployed application or runtime evidence.',
            'prerequisites':[
                {'id':'affected','label':'Affected package condition present','required_value':True,'initial':'true','basis':'observed',
                 'explanation':'Observed only inside the invented teaching fixture.','evidence_ids':refs},
                {'id':'reachable','label':'External input reaches affected functionality','required_value':True,'initial':'unknown','basis':'assumption',
                 'explanation':'Set a what-if assumption about input reachability.','evidence_ids':[sid]},
                {'id':'mitigated','label':'Documented mitigation enabled','required_value':False,'initial':'unknown','basis':'assumption',
                 'explanation':'Assume the fixture mitigation blocks this particular modeled path.','evidence_ids':[aid]}],
            'steps':[{'text':'Hypothetically, external input reaches the application entry point.','evidence_ids':[]},
                     {'text':'The application invokes the advisory-described operation if the stated conditions hold.','evidence_ids':[sid,aid]},
                     {'text':'An enabled mitigation interrupts this modeled path; otherwise the hypothetical impact may follow.','evidence_ids':[aid]}],
            'hypothetical_impact':impacts[i],'limitations':['All input is synthetic; no exploit was attempted or validated.',
                'The model covers only these explicit prerequisites.']})
    analysis={'schema_version':1,'selection_notes':'Three synthetic scenarios demonstrate prerequisite controls, evidence inspection, and modeled mitigations.',
              'limitations':['Synthetic data only. No live security conclusions can be drawn.'],'assessments':assessments,'scenarios':scenarios}
    for name,data in [('sbom.json',sbom),('run.json',state),('analysis.json',analysis),('osv_cache.json',cache),
                      ('source.json',{'synthetic/app.py':{'commit':commit,'sha256':source_hash,'text':text}})]:risk.save(out/name,data)
    return state,analysis


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',required=True);args=parser.parse_args()
    make_demo(args.out)
    print('Synthetic demo created at '+str(Path(args.out).resolve())+'; render with risk.py render --run PATH.')
