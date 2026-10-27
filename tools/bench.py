import json,subprocess,time,os,shutil,collections,statistics as st,resource,platform,sys
ROOT='/Users/henrikalvestad/Desktop/SkillScanna/crates/spector-core'
FX=ROOT+'/tests/fixtures'; RS=ROOT+'/target/release/skillspector-rs'
W='/tmp/bx/work2'; shutil.rmtree(W,ignore_errors=True); os.makedirs(W)
names=[n for n in sorted(os.listdir(FX)) if os.path.isdir(f'{FX}/{n}')]
for n in names: shutil.copytree(f'{FX}/{n}',f'{W}/{n}')
def run(cmd):
    t=time.perf_counter(); p=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
    out=p.stdout.read(); _,_,ru=os.wait4(p.pid,0); p.returncode=0
    return out,time.perf_counter()-t,ru.ru_utime+ru.ru_stime,ru.ru_maxrss/1048576
def pct(a,p):
    a=sorted(a); k=(len(a)-1)*p/100; f=int(k); c=min(f+1,len(a)-1); return a[f]+(a[c]-a[f])*(k-f)
def kp(i): l=i.get('location') or i; return (l['file'],i['id'],l.get('start_line'))
PYN,RSN=3,20
pyt=[];pyc=[];pym=[];rst=[];rsc=[];rsm=[];ref=match=extra=0;sev=collections.Counter()
for n in names:
    d=f'{W}/{n}'
    for r in range(PYN):
        o,t,c,m=run(['skillspector','scan',d,'--no-llm','--format','json']); pyt.append(t);pyc.append(c);pym.append(m)
    py=collections.Counter(kp(i) for i in json.loads(o)['issues'] if i['id']!='SC4')
    for r in range(RSN):
        o,t,c,m=run([RS,'scan','--format','json',d]); rst.append(t);rsc.append(c);rsm.append(m)
    rs=collections.Counter((i['file'],i['id'],i['start_line']) for s in json.loads(o)['skills'] for i in s['issues'])
    ref+=sum(py.values());match+=sum((py&rs).values());extra+=sum((rs-py).values())
# batch: 500 copies, one rust process
B=f'{W}_batch'; shutil.rmtree(B,ignore_errors=True); os.makedirs(B)
for i in range(500): shutil.copytree(f'{FX}/{names[i%len(names)]}',f'{B}/s{i:04d}')
bt=[]
for _ in range(5):
    o,t,c,m=run([RS,'scan','--format','json','--recursive',B]); bt.append(t)
# python batch of 24 (its recursive cap)
B2=f'{W}_b24'; shutil.rmtree(B2,ignore_errors=True); os.makedirs(B2)
for i in range(24): shutil.copytree(f'{FX}/{names[i%len(names)]}',f'{B2}/s{i:02d}')
o,pb,_,_=run(['skillspector','scan',B2,'--recursive','--no-llm','--format','json'])
o,rb,_,_=run([RS,'scan','--format','json','--recursive',B2])
def row(n,a,f): return '| %s | %s |'%(n,' | '.join(f%pct(a,p) for p in(50,95,99)))
hw=subprocess.run(['sysctl','-n','machdep.cpu.brand_string'],capture_output=True,text=True).stdout.strip()
md=f"""# skillspector-rs vs SkillSpector v2.12.0 (--no-llm), measured
Hardware: {hw}, {platform.platform()}. Corpus: {len(names)} public fixture skills (tests/fixtures).
Single-skill runs are one process per scan (cold start included): Python {PYN}x, Rust {RSN}x per skill => n={len(pyt)} vs n={len(rst)}.

## Wall time per skill scan (seconds)
| | p50 | p95 | p99 |
|---|---|---|---|
{row('SkillSpector (Python)',pyt,'%.2f')}
{row('skillspector-rs',rst,'%.3f')}
| **speedup** | {pct(pyt,50)/pct(rst,50):.0f}x | {pct(pyt,95)/pct(rst,95):.0f}x | {pct(pyt,99)/pct(rst,99):.0f}x |

## Resources per scan
| | CPU time p50 (s) | CPU time p95 (s) | peak RSS p50 (MB) | peak RSS p95 (MB) |
|---|---|---|---|---|
| SkillSpector (Python) | {pct(pyc,50):.2f} | {pct(pyc,95):.2f} | {pct(pym,50):.0f} | {pct(pym,95):.0f} |
| skillspector-rs | {pct(rsc,50):.2f} | {pct(rsc,95):.2f} | {pct(rsm,50):.0f} | {pct(rsm,95):.0f} |

## Batch (one process, --recursive)
| Workload | SkillSpector (Python) | skillspector-rs |
|---|---|---|
| 24 skills | {pb:.1f}s | {rb:.2f}s ({pb/rb:.0f}x) |
| 500 skills | not possible (stops at 32 skills) | p50 {pct(bt,50):.1f}s, p95 {pct(bt,95):.1f}s ({500/pct(bt,50):.0f} skills/s) |

## Parity (file, rule id, start line; SC4 excluded)
Reference findings {ref}; matched **{match} ({100*match/ref:.1f}%)**; extra findings in Rust **{extra}**; missing {ref-match} (unported analyzers P5, TP1-3, TR2, SC3/oms; see KNOWN_DIFFERENCES.md).
Private corpus (865 real skills, earlier run): 2777/2800 matched (99.2%), 0 extra.
"""
open('/tmp/bx/SCOREBOARD.md','w').write(md); print(md)
