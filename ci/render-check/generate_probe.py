#!/usr/bin/env python3
"""Generate exact source-body mock probes. No shader/game assets and no source edits.
The particle mock records typed payload width instead of making an invalid read.
The shadow mock tests dispatch/order and a three-ray depth model, not GPU output.
"""
import argparse, hashlib, json
from pathlib import Path

def extract(text, signature):
    if text.count(signature) != 1: raise ValueError('Function signature is missing or ambiguous')
    start=text.index(signature); opening=text.index('{',start); depth=1; end=opening+1
    while depth:
        depth += (text[end]=='{')-(text[end]=='}'); end+=1
    return text[start:end]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--case',choices=['particle','shadow'],required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    support=json.loads(Path(__file__).with_name('probe_support.json').read_text())
    if a.case=='particle':
        path='src/moho/particles/BeamRenderHelpers.cpp'
        text=(a.source/path).read_text()
        body=extract(text,'void SParticleRenderBucket::SelectTechnique() const')
    else:
        path='src/moho/render/Shadow.cpp'
        text=(a.source/path).read_text()
        body=extract(text,'  void Shadow::RenderShadowMap(')+'\n'+extract(text,'  void Shadow::RenderFrameShadows(')
    a.output.write_text(support[a.case+'_prefix']+'\n'+body+'\n'+support[a.case+'_suffix'])
    print(f'Extracted unchanged {a.case} function body SHA256={hashlib.sha256(body.encode()).hexdigest()} from {path}. Mock, not GPU test.')

if __name__=='__main__': main()
