#!/usr/bin/env python3
import os,sys,argparse,gzip,base64,json,subprocess,asyncio,random,re,time
import aiohttp
P=None
def allowed_octets():
    bad={0,10,127,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255}
    return [a for a in range(1,224) if a not in bad]
async def probe(sess,hits,sem,ip,port):
    async with sem:
        try:
            async with sess.get(f"https://{ip}:{port}/",ssl=False,timeout=aiohttp.ClientTimeout(total=7)) as r:
                body=(await r.text(errors='ignore'))[:8000]
                hdr=str(r.headers)
                hay=(hdr+' '+body).lower()
                for k in ('vmanage','viptela','sd-wan','catalyst sd-wan','/dataservice/'):
                    if k in hay:
                        title=''
                        m=re.search(r'<title[^>]*>(.*?)</title>',body,re.S|re.I)
                        if m: title=re.sub(r'\s+',' ',m.group(1)).strip()[:80]
                        hits.append(f"{ip}:{port} {r.status} sig={k} title={title}")
                        break
        except Exception:
            pass
async def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--slice',type=int,required=True)
    ap.add_argument('--of',type=int,default=24)
    ap.add_argument('--rate',default='150000')
    ap.add_argument('--test',default='')
    a=ap.parse_args()
    octs=allowed_octets()
    mine=[str(o) for i,o in enumerate(octs) if i%a.of==a.slice]
    cidrs=','.join(f"{o}.0.0.0/8" for o in mine)
    print(f"slice={a.slice}/{a.of} ranges={len(mine)} rate={a.rate}",flush=True)
    cmd=['sudo','masscan','-p443,8443','--rate',a.rate,'--wait','5','-oL','/tmp/m.txt',cidrs]
    subprocess.run(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=9000)
    opens=[]
    for line in open('/tmp/m.txt',errors='ignore'):
        p=line.split()
        if len(p)>=4 and p[0]=='open': opens.append((p[3],p[2]))
    print("opens",len(opens),flush=True)
    hits=[]
    conn=aiohttp.TCPConnector(limit=500,ssl=False)
    async with aiohttp.ClientSession(connector=conn,headers={'User-Agent':'curl/8'}) as sess:
        sem=asyncio.Semaphore(500)
        await asyncio.gather(*[probe(sess,hits,sem,ip,pt) for ip,pt in opens])
    txt="\n".join(hits)
    blob=base64.b64encode(gzip.compress(txt.encode())).decode()
    tok=os.environ.get('GH_TOKEN',''); repo=os.environ.get('REPO','')
    if tok and repo:
        import urllib.request
        api=f"https://api.github.com/repos/{repo}/contents/hits/{a.slice:02d}.b64"
        body=json.dumps({"message":"sync","content":blob}).encode()
        req=urllib.request.Request(api,data=body,method='PUT',
            headers={'Authorization':f'token {tok}','Accept':'application/vnd.github+json','User-Agent':'w'})
        try:
            urllib.request.urlopen(req,timeout=60); print("committed",flush=True)
        except Exception as e:
            print("commit_err",str(e)[:100],flush=True)
    print("hits",len(hits),flush=True)
asyncio.run(main())
