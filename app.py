import streamlit as st
import pandas as pd, hashlib, json, uuid
from pathlib import Path
from datetime import datetime, timezone

ROOT=Path(__file__).parent
DATA=ROOT/"data"; DATA.mkdir(exist_ok=True)
INC=DATA/"incidents.json"; LED=DATA/"ledger.json"
st.set_page_config(page_title="SentinelChain",page_icon="🛡️",layout="wide")

def read(path, default):
    try: return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default
    except Exception: return default
def write(path,obj): path.write_text(json.dumps(obj,indent=2,ensure_ascii=False),encoding="utf-8")
def digest(s): return hashlib.sha256(s.encode()).hexdigest()
def payload(e): return json.dumps({k:v for k,v in e.items() if k!="hash"},sort_keys=True,separators=(",",":"))
def ledger_add(incident):
    records=read(LED,[])
    item={"ledger_id":len(records)+1,"timestamp":datetime.now(timezone.utc).isoformat(),
          "incident_id":incident["incident_id"],"event":"INCIDENT_CREATED",
          "incident_snapshot":incident,"previous_hash":records[-1]["hash"] if records else "GENESIS"}
    item["hash"]=digest(payload(item)); records.append(item); write(LED,records)
def verify():
    records=read(LED,[]); prev="GENESIS"
    for n,e in enumerate(records,1):
        if e.get("ledger_id")!=n or e.get("previous_hash")!=prev or e.get("hash")!=digest(payload(e)):
            return False,f"Integrity check failed at record {n}"
        prev=e["hash"]
    return True,f"Verified {len(records)} ledger record(s)."
def detect(row):
    score=0; why=[]
    label=str(row.get("Label",row.get("label",""))).strip().lower()
    if label and label not in ("benign","normal","0","none","nan"):
        score+=85; why.append("Dataset label: "+label)
    for col in ("failed_logins","failed_login_count","login_failures"):
        if col in row.index:
            try:
                if float(row[col])>=5: score+=35; why.append("Repeated failed logins")
            except: pass
            break
    for col,limit,reason in [("flow_packets/s",1000,"Unusually high packet rate"),("flow_bytes/s",1000000,"Unusually high byte rate")]:
        if col in row.index:
            try:
                if float(row[col])>limit: score+=20; why.append(reason)
            except: pass
    if "url" in row.index and str(row["url"]).strip() and not str(row["url"]).lower().startswith(("http://","https://")):
        score+=15; why.append("URL missing http/https scheme")
    score=min(score,100); severity="High" if score>=70 else "Medium" if score>=35 else "Low"
    return score,severity,"; ".join(why) if why else "No configured suspicious pattern matched"
def analyse(df):
    out=df.copy()
vals=out.apply(detect,axis=1,result_type="expand")
    out["risk_score"]=vals[0]; out["severity"]=vals[1]; out["reason"]=vals[2]
    out.insert(0,"row_number",range(1,len(out)+1))
    return out
def create_incident(row):
    item={"incident_id":"SC-"+uuid.uuid4().hex[:8].upper(),"created_at":datetime.now(timezone.utc).isoformat(),
          "severity":str(row["severity"]),"risk_score":int(row["risk_score"]),"status":"Open",
          "description":str(row["reason"]),"source_data":{str(k):str(v) for k,v in row.items()}}
    incidents=read(INC,[]); incidents.insert(0,item); write(INC,incidents); ledger_add(item); return item

st.title("🛡️ SentinelChain")
st.caption("Cybersecurity Threat Analysis & Secure Incident Management")
st.warning("Demo prototype: detection is rule-based, not a trained ML model. Ledger is a local SHA-256 hash-chain, not a decentralized blockchain. Never upload passwords, secrets, or confidential production logs.")
page=st.sidebar.radio("Navigation",["Dashboard","Analyse Data","Incidents","Ledger Verification","About"])

if page=="Dashboard":
    incidents=read(INC,[]); ledger=read(LED,[])
    a,b,c=st.columns(3); a.metric("Total incidents",len(incidents)); b.metric("Open incidents",sum(x["status"]=="Open" for x in incidents)); c.metric("Ledger records",len(ledger))
    st.subheader("Workflow")
    st.write("Upload CSV → Analyse security events → Review risk score → Create incident → Verify hash-linked ledger.")
    if incidents: st.dataframe(pd.DataFrame(incidents)[["incident_id","created_at","severity","risk_score","status","description"]],use_container_width=True)
    else: st.info("No incidents yet. Open Analyse Data and load the sample CSV.")

    st.divider()
    with st.expander("⚠️ Reset Demo / Clear All Data"):
        st.warning("This permanently clears all saved incidents and ledger records from this app's local data files. It cannot be undone.")
        confirm_reset = st.checkbox("I understand — delete all incidents and ledger records.")
        if st.button("🗑️ Reset All Data", type="primary", disabled=not confirm_reset):
            write(INC, [])
            write(LED, [])
            for key in ("df", "result"):
                st.session_state.pop(key, None)
            st.success("All demo data has been cleared.")
            st.rerun()
elif page=="Analyse Data":
    st.subheader("Analyse security data")
    sample=ROOT/"sample_data"/"sample_security_events.csv"
    col1,col2=st.columns(2); uploaded=col1.file_uploader("Upload CSV",type=["csv"])
    if col2.button("Load sample CSV"): st.session_state.df=pd.read_csv(sample)
    if uploaded:
        try: st.session_state.df=pd.read_csv(uploaded,low_memory=False)
        except Exception as ex: st.error(f"CSV error: {ex}")
    if "df" in st.session_state:
        df=st.session_state.df
        st.write(f"{len(df):,} rows • {len(df.columns)} columns")
        st.dataframe(df.head(15),use_container_width=True)
        if st.button("Run threat analysis",type="primary"): st.session_state.result=analyse(df)
        if "result" in st.session_state:
            result=st.session_state.result
            x,y,z=st.columns(3); x.metric("Rows analysed",len(result)); y.metric("High risk",(result.severity=="High").sum()); z.metric("Medium risk",(result.severity=="Medium").sum())
            st.dataframe(result,use_container_width=True)
            st.download_button("Download analysis CSV",result.to_csv(index=False).encode(),"sentinelchain_analysis.csv","text/csv")
            candidates=result[result.risk_score>0]
            if len(candidates):
                selected=st.selectbox("Choose row for incident",candidates.row_number.tolist())
                if st.button("Create incident"):
                    item=create_incident(result[result.row_number==selected].iloc[0]); st.success("Created "+item["incident_id"])
    else: st.info("Load the sample CSV or upload your own CSV.")
elif page=="Incidents":
    items=read(INC,[])
    st.subheader("Incident management")
    if not items: st.info("No incidents created yet.")
    else:
        st.dataframe(pd.DataFrame(items)[["incident_id","created_at","severity","risk_score","status","description"]],use_container_width=True)
        ident=st.selectbox("Select incident", [x["incident_id"] for x in items])
        current=next(x for x in items if x["incident_id"]==ident)
        status=st.selectbox("Status",["Open","Investigating","Resolved"],index=["Open","Investigating","Resolved"].index(current["status"]))
        if st.button("Update status"):
            for x in items:
                if x["incident_id"]==ident: x["status"]=status; x["updated_at"]=datetime.now(timezone.utc).isoformat()
            write(INC,items); st.success("Status updated."); st.rerun()
        st.download_button("Download incidents JSON",json.dumps(items,indent=2).encode(),"incidents.json","application/json")
elif page=="Ledger Verification":
    st.subheader("SHA-256 hash-chain verification")
    ok,msg=verify()
    (st.success if ok else st.error)(msg)
    records=read(LED,[])
    if records:
        st.dataframe(pd.DataFrame(records)[["ledger_id","timestamp","incident_id","event","previous_hash","hash"]],use_container_width=True)
        st.download_button("Download ledger JSON",json.dumps(records,indent=2).encode(),"ledger.json","application/json")
    else: st.info("Ledger empty. Create an incident first.")
else:
    st.subheader("About")
    st.markdown(""" - **Python:** application logic - **Streamlit:** browser-based interface - **Pandas:** CSV reading and processing - **Rule-based heuristics:** demo risk scoring - **SHA-256 + JSON:** local hash-linked incident ledger CICIDS2017 contains network-flow features and traffic labels (e.g. BENIGN and attack categories), not employee passwords. This app can read its CSV after upload; the included sample is synthetic. This build does not train an ML model, capture live packets, automatically block attackers, or run a distributed blockchain. """)
