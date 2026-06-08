package main

// webUIHTML is the complete single-page FlatScan web GUI. It is fully
// self-contained: all CSS and JavaScript are inlined and there are no external
// CDN, font, or package dependencies. The constant is a Go raw string literal,
// so it must never contain a backtick — the embedded JavaScript therefore uses
// string concatenation instead of template literals.
const webUIHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FlatScan</title>
<style>
:root{
  --bg:#0d0d0d; --surface:#111111; --surface2:#161616; --border:#252525;
  --red:#e05252; --amber:#e8a020; --teal:#2dd4bf; --green:#39d353;
  --blue:#4a9eff; --purple:#b389ff; --text:#e0e0e0; --muted:#888888;
  --ui:'Inter','Helvetica Neue',Arial,sans-serif;
  --mono:'JetBrains Mono','Fira Code','SFMono-Regular',Consolas,monospace;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;height:100%}
body{background:var(--bg);color:var(--text);font-family:var(--ui);font-size:13px;line-height:1.5}
#app{display:flex;height:100vh;overflow:hidden}
a{color:var(--blue);text-decoration:none}
.mono{font-family:var(--mono)}
.muted{color:var(--muted)}
.trunc{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* ---- sidebar ---- */
#sidebar{width:240px;min-width:240px;background:var(--surface);border-right:1px solid var(--border);
  display:flex;flex-direction:column;overflow-y:auto;padding:14px 12px;gap:14px}
.brand{display:flex;align-items:baseline;gap:8px;padding-bottom:4px}
.brand .logo{font-family:var(--mono);font-weight:700;font-size:16px;color:var(--teal)}
.brand .ver{font-size:10px;color:var(--muted)}
.section-label{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}

#drop{border:1.5px dashed var(--border);border-radius:6px;padding:18px 10px;text-align:center;
  color:var(--muted);cursor:pointer;transition:border-color .15s,background .15s;font-size:12px}
#drop.hover{border-color:var(--teal);background:rgba(45,212,191,.06);color:var(--teal)}
#drop.error{border-color:var(--red);background:rgba(224,82,82,.08)}
#filebox{display:none;border:1px solid var(--border);border-radius:6px;padding:10px;background:var(--surface2)}
#filebox.show{display:block}
#filebox .fn{font-family:var(--mono);font-size:12px;color:var(--teal);word-break:break-all}
#filebox .meta{font-size:11px;color:var(--muted);margin-top:3px}
#filebox .clear{float:right;cursor:pointer;color:var(--muted);font-size:14px;line-height:1}
#filebox .clear:hover{color:var(--red)}

.modes{display:flex;gap:6px}
.mode-btn{flex:1;padding:7px 0;text-align:center;border:1px solid var(--border);border-radius:5px;
  background:var(--surface2);color:var(--muted);cursor:pointer;font-size:11px;text-transform:capitalize;
  font-family:var(--mono)}
.mode-btn.active{border-color:var(--teal);color:var(--teal);background:rgba(45,212,191,.08)}

.opt{display:flex;justify-content:space-between;align-items:center;padding:6px 8px;border:1px solid var(--border);
  border-radius:5px;background:var(--surface2);cursor:pointer;margin-bottom:6px}
.opt .name{font-family:var(--mono);font-size:11px}
.opt .state{font-size:11px;color:var(--muted);font-family:var(--mono)}
.opt.on .state{color:var(--green)}

#run{width:100%;padding:11px 0;border:1px solid var(--green);border-radius:6px;
  background:rgba(57,211,83,.12);color:var(--green);font-weight:600;cursor:pointer;font-size:13px}
#run:hover{background:rgba(57,211,83,.2)}
#run:disabled{opacity:.55;cursor:default}

#history{display:flex;flex-direction:column;gap:5px}
.hist{border:1px solid var(--border);border-radius:5px;padding:7px 8px;background:var(--surface2);cursor:pointer}
.hist:hover{border-color:var(--teal)}
.hist .top{display:flex;justify-content:space-between;align-items:center;gap:6px}
.hist .hn{font-size:11px;font-family:var(--mono)}
.hist .hs{font-weight:700;font-family:var(--mono);font-size:12px}
.hist .hm{font-size:10px;color:var(--muted);margin-top:2px;display:flex;justify-content:space-between}

/* ---- main ---- */
#main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}
#tabbar{display:flex;gap:2px;border-bottom:1px solid var(--border);background:var(--surface);
  overflow-x:auto;scrollbar-width:none}
#tabbar::-webkit-scrollbar{display:none}
.tab{padding:11px 16px;cursor:pointer;color:var(--muted);font-size:12px;white-space:nowrap;
  border-bottom:2px solid transparent}
.tab:hover{color:var(--text)}
.tab.active{color:var(--teal);border-bottom-color:var(--teal)}
#tabwrap{flex:1;overflow-y:auto;padding:20px 24px;min-width:0}
.panel{display:none}
.panel.active{display:block}

/* placeholder / scanning */
#placeholder,#scanning,#errbox{display:none;flex-direction:column;align-items:center;justify-content:center;
  height:100%;text-align:center;color:var(--muted);gap:14px}
#placeholder.show,#scanning.show,#errbox.show{display:flex}
.spinner{font-family:var(--mono);font-size:40px;color:var(--teal);animation:spin 1s steps(8) infinite}
@keyframes spin{to{transform:rotate(360deg)}}
#scanning .sf{font-family:var(--mono);color:var(--teal);font-size:15px;word-break:break-all}
#logfeed{font-family:var(--mono);font-size:11px;color:var(--muted);max-width:480px;text-align:left;
  width:100%;max-height:200px;overflow:auto}
#logfeed div{padding:1px 0}
#errbox .em{color:var(--red);font-family:var(--mono);max-width:560px;word-break:break-word}

/* result components */
.verdict{display:flex;align-items:center;gap:20px;justify-content:space-between;flex-wrap:wrap}
.verdict .vleft{display:flex;align-items:center;gap:18px}
.verdict .score{font-family:var(--mono);font-size:54px;font-weight:700;line-height:1}
.verdict .vlabel{font-size:20px;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.verdict .vmeta{text-align:right;font-size:11px;color:var(--muted);font-family:var(--mono)}
.verdict .vmeta b{color:var(--text)}
.scorebar{height:2px;background:var(--border);margin:14px 0 18px;border-radius:2px}
.scorebar>div{height:100%;border-radius:2px}

.pills{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:18px}
.pill{font-family:var(--mono);font-size:11px;border:1px solid var(--border);border-radius:20px;
  padding:3px 10px;background:var(--surface2)}
.pill b{color:var(--teal)}

.cells{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px}
.cell{border:1px solid var(--border);border-radius:6px;padding:10px 12px;background:var(--surface);min-width:0}
.cell .k{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.cell .v{font-family:var(--mono);font-size:14px;margin-top:4px;color:var(--text)}

details.box{border:1px solid var(--border);border-radius:6px;margin-bottom:14px;background:var(--surface)}
details.box>summary{cursor:pointer;padding:11px 14px;font-weight:600;font-size:12px;
  list-style:none;display:flex;justify-content:space-between;align-items:center}
details.box>summary::-webkit-details-marker{display:none}
details.box>summary .chev{color:var(--muted);font-size:11px}
details.box[open]>summary .chev{transform:rotate(90deg)}
details.box .body{padding:4px 14px 14px}

.kv{display:flex;gap:10px;padding:4px 0;border-bottom:1px solid var(--surface2);min-width:0}
.kv:last-child{border-bottom:none}
.kv .kk{width:120px;min-width:120px;color:var(--muted);font-size:11px}
.kv .vv{font-family:var(--mono);font-size:12px;word-break:break-all;flex:1;min-width:0}

.copy{background:none;border:none;color:var(--muted);cursor:pointer;font-size:12px;padding:0 4px;font-family:var(--mono)}
.copy:hover{color:var(--teal)}

.secbar{display:grid;grid-template-columns:90px 1fr 60px 40px;gap:8px;align-items:center;
  font-family:var(--mono);font-size:11px;padding:3px 0}
.secbar .track{height:10px;background:var(--surface2);border-radius:3px;overflow:hidden;border:1px solid var(--border)}
.secbar .track>div{height:100%}

/* findings */
.fgroup{margin-bottom:14px}
.fgroup>.fhead{padding:8px 12px;border-radius:5px;font-weight:600;font-size:12px;cursor:pointer;
  border:1px solid var(--border);display:flex;justify-content:space-between}
.finding{border-left:2px solid var(--border);background:var(--surface);margin:6px 0;border-radius:0 5px 5px 0;
  padding:9px 12px;cursor:pointer}
.finding .ft{display:flex;justify-content:space-between;gap:10px;align-items:center}
.finding .title{font-weight:600;font-size:12px}
.finding .tags{display:flex;gap:5px;flex-wrap:wrap;margin-top:5px}
.tag{font-family:var(--mono);font-size:10px;border:1px solid var(--border);border-radius:3px;padding:1px 6px;color:var(--muted)}
.badge{font-family:var(--mono);font-size:11px;font-weight:700;border-radius:4px;padding:1px 7px}
.finding .detail{display:none;margin-top:9px;padding-top:9px;border-top:1px solid var(--surface2);font-size:12px;color:var(--muted)}
.finding.open .detail{display:block}
.finding .detail .lbl{color:var(--text);font-weight:600;margin-top:6px}

/* ioc */
.subtabs{display:flex;gap:4px;flex-wrap:wrap;margin-bottom:14px}
.subtab{font-family:var(--mono);font-size:11px;padding:5px 11px;border:1px solid var(--border);border-radius:5px;
  background:var(--surface2);color:var(--muted);cursor:pointer}
.subtab.active{border-color:var(--teal);color:var(--teal)}
.ioclist{display:flex;flex-direction:column;gap:3px}
.iocrow{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:5px 10px;
  background:var(--surface);border:1px solid var(--border);border-radius:4px;font-family:var(--mono);font-size:12px}
.iocrow span{word-break:break-all;min-width:0}

/* tables */
table.grid{width:100%;border-collapse:collapse;font-size:12px}
table.grid th{text-align:left;color:var(--muted);font-weight:500;font-size:10px;text-transform:uppercase;
  letter-spacing:.06em;padding:7px 10px;border-bottom:1px solid var(--border)}
table.grid td{padding:7px 10px;border-bottom:1px solid var(--surface2);font-family:var(--mono);min-width:0}
table.grid tr:hover td{background:var(--surface)}

.implist{display:grid;grid-template-columns:1fr 1fr;gap:2px 18px}
.implist .imp{font-family:var(--mono);font-size:12px;padding:2px 0;border-bottom:1px solid var(--surface2)}

.list-dot{list-style:none;padding:0;margin:0}
.list-dot li{padding:3px 0 3px 16px;position:relative;font-size:12px}
.list-dot li:before{content:'\203A';position:absolute;left:2px;color:var(--teal)}

.outrow{display:flex;align-items:center;gap:14px;padding:11px 14px;border:1px solid var(--border);
  border-radius:6px;background:var(--surface);margin-bottom:8px}
.outrow .ext{font-family:var(--mono);color:var(--teal);width:64px;font-weight:600}
.outrow .desc{flex:1;min-width:0}
.outrow .sz{font-family:var(--mono);color:var(--muted);font-size:11px}
.dlbtn{border:1px solid var(--teal);color:var(--teal);background:rgba(45,212,191,.08);border-radius:5px;
  padding:6px 14px;cursor:pointer;font-size:12px;font-family:var(--mono)}
.dlbtn:hover{background:rgba(45,212,191,.2)}

.logline{font-family:var(--mono);font-size:11.5px;padding:1px 6px;white-space:pre-wrap;word-break:break-all}
.empty{color:var(--muted);font-style:italic;padding:14px 0}
h3.sh{font-size:13px;margin:18px 0 8px;color:var(--text)}
</style>
</head>
<body>
<div id="app">
  <aside id="sidebar">
    <div class="brand"><span class="logo">FlatScan</span><span class="ver">web</span></div>

    <div>
      <div class="section-label">target</div>
      <div id="drop">drop a file here<br>or click to browse</div>
      <div id="filebox">
        <span class="clear" id="clearfile" title="remove">&times;</span>
        <div class="fn trunc" id="fbname">-</div>
        <div class="meta" id="fbmeta">-</div>
      </div>
      <input type="file" id="fileinput" style="display:none">
    </div>

    <div>
      <div class="section-label">scan mode</div>
      <div class="modes">
        <div class="mode-btn" data-mode="quick">quick</div>
        <div class="mode-btn active" data-mode="standard">standard</div>
        <div class="mode-btn" data-mode="deep">deep</div>
      </div>
    </div>

    <div>
      <div class="section-label">options</div>
      <div class="opt" data-opt="carve"><span class="name">--carve</span><span class="state">off</span></div>
      <div class="opt on" data-opt="yara"><span class="name">--yara</span><span class="state">on</span></div>
      <div class="opt on" data-opt="sigma"><span class="name">--sigma</span><span class="state">on</span></div>
      <div class="opt" data-opt="stix"><span class="name">--stix</span><span class="state">off</span></div>
      <div class="opt" data-opt="report_pack"><span class="name">--report-pack</span><span class="state">off</span></div>
    </div>

    <button id="run">Run Scan</button>

    <div>
      <div class="section-label">history</div>
      <div id="history"><div class="empty" style="font-size:11px">no scans yet</div></div>
    </div>
  </aside>

  <main id="main">
    <div id="tabbar">
      <div class="tab active" data-tab="overview">overview</div>
      <div class="tab" data-tab="findings">findings</div>
      <div class="tab" data-tab="ioc">ioc</div>
      <div class="tab" data-tab="functions">functions</div>
      <div class="tab" data-tab="pe">pe details</div>
      <div class="tab" data-tab="artifacts">artifacts</div>
      <div class="tab" data-tab="profile">profile</div>
      <div class="tab" data-tab="log">log</div>
      <div class="tab" data-tab="outputs">outputs</div>
    </div>
    <div id="tabwrap">
      <div id="placeholder" class="show">
        <div class="spinner" style="animation:none;color:var(--border)">&#9676;</div>
        <div>load a file and run a scan to begin</div>
      </div>
      <div id="scanning">
        <div class="spinner">&#9676;</div>
        <div class="sf" id="scanfile">-</div>
        <div class="muted" id="scanstage">scanning&hellip;</div>
        <div id="logfeed"></div>
      </div>
      <div id="errbox">
        <div style="font-size:30px">&#9888;</div>
        <div class="em" id="errmsg">-</div>
      </div>
      <div id="results" style="display:none">
        <div class="panel active" id="tab-overview"></div>
        <div class="panel" id="tab-findings"></div>
        <div class="panel" id="tab-ioc"></div>
        <div class="panel" id="tab-functions"></div>
        <div class="panel" id="tab-pe"></div>
        <div class="panel" id="tab-artifacts"></div>
        <div class="panel" id="tab-profile"></div>
        <div class="panel" id="tab-log"></div>
        <div class="panel" id="tab-outputs"></div>
      </div>
    </div>
  </main>
</div>

<script>
"use strict";
var state = {
  file:null,
  mode:"standard",
  opts:{carve:false,yara:true,sigma:true,stix:false,report_pack:false},
  currentId:null,
  pollTimer:null,
  jobs:{},        // id -> result response
  history:[]
};

/* ---------- helpers ---------- */
function $(s){return document.querySelector(s);}
function $all(s){return Array.prototype.slice.call(document.querySelectorAll(s));}
function esc(s){
  if(s===null||s===undefined) return "";
  return String(s).replace(/[&<>"']/g,function(c){
    return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c];
  });
}
function hex(n){
  var v=Number(n);
  if(!isFinite(v)||v<0) v=0;
  return "0x"+Math.floor(v).toString(16).toUpperCase();
}
function num(n){ var v=Number(n); return isFinite(v)?v:0; }
function fmtBytes(b){
  b=num(b);
  if(b<1024) return b+" B";
  var u=["KB","MB","GB","TB"],i=-1;
  do{b/=1024;i++;}while(b>=1024&&i<u.length-1);
  return b.toFixed(b<10?2:1)+" "+u[i];
}
function scoreColor(s){ s=num(s); return s>=80?"var(--red)":(s>=30?"var(--amber)":"var(--green)"); }
function sevColor(sev){
  switch(String(sev||"").toLowerCase()){
    case "critical": case "high": return "var(--red)";
    case "medium": return "var(--amber)";
    case "low": return "var(--blue)";
    default: return "var(--muted)";
  }
}
function sevRank(sev){
  switch(String(sev||"").toLowerCase()){
    case "critical": return 4; case "high": return 3; case "medium": return 2;
    case "low": return 1; default: return 0;
  }
}
function cp(v){ return "<button class=\"copy\" data-v=\"" + esc(v) + "\" title=\"copy\">&#9096;</button>"; }
function timeAgo(ts){
  var s=Math.max(0,Math.floor((Date.now()-ts)/1000));
  if(s<60) return s+"s ago";
  var m=Math.floor(s/60); if(m<60) return m+"m ago";
  var h=Math.floor(m/60); if(h<24) return h+"h ago";
  return Math.floor(h/24)+"d ago";
}

/* ---------- copy delegation ---------- */
document.addEventListener("click",function(e){
  var b=e.target.closest(".copy");
  if(!b) return;
  navigator.clipboard.writeText(b.getAttribute("data-v")||"").catch(function(){});
  var prev=b.innerHTML; b.textContent="✓";
  setTimeout(function(){b.innerHTML=prev;},1200);
});

/* ---------- file handling ---------- */
var drop=$("#drop"), fileinput=$("#fileinput"), filebox=$("#filebox");
drop.addEventListener("click",function(){fileinput.click();});
fileinput.addEventListener("change",function(){ if(fileinput.files[0]) setFile(fileinput.files[0]); });
["dragenter","dragover"].forEach(function(ev){
  drop.addEventListener(ev,function(e){e.preventDefault();drop.classList.add("hover");});
});
["dragleave","drop"].forEach(function(ev){
  drop.addEventListener(ev,function(e){e.preventDefault();drop.classList.remove("hover");});
});
drop.addEventListener("drop",function(e){
  if(e.dataTransfer.files&&e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
});
$("#clearfile").addEventListener("click",clearFile);
function setFile(f){
  state.file=f;
  $("#fbname").textContent=f.name;
  $("#fbmeta").textContent=fmtBytes(f.size)+" · "+(f.type||"unknown type");
  filebox.classList.add("show");
  drop.style.display="none";
}
function clearFile(){
  state.file=null; fileinput.value="";
  filebox.classList.remove("show");
  drop.style.display="";
}

/* ---------- mode + options ---------- */
$all(".mode-btn").forEach(function(btn){
  btn.addEventListener("click",function(){
    $all(".mode-btn").forEach(function(b){b.classList.remove("active");});
    btn.classList.add("active");
    state.mode=btn.getAttribute("data-mode");
  });
});
$all(".opt").forEach(function(row){
  row.addEventListener("click",function(){
    var k=row.getAttribute("data-opt");
    state.opts[k]=!state.opts[k];
    row.classList.toggle("on",state.opts[k]);
    row.querySelector(".state").textContent=state.opts[k]?"on":"off";
  });
});

/* ---------- view switching ---------- */
function showView(which){
  $("#placeholder").classList.toggle("show",which==="placeholder");
  $("#scanning").classList.toggle("show",which==="scanning");
  $("#errbox").classList.toggle("show",which==="error");
  $("#results").style.display=(which==="results")?"block":"none";
}
$all(".tab").forEach(function(t){
  t.addEventListener("click",function(){
    $all(".tab").forEach(function(x){x.classList.remove("active");});
    t.classList.add("active");
    var name=t.getAttribute("data-tab");
    $all(".panel").forEach(function(p){p.classList.remove("active");});
    var p=$("#tab-"+name); if(p) p.classList.add("active");
  });
});

/* ---------- run scan ---------- */
$("#run").addEventListener("click",function(){
  if(!state.file){
    drop.classList.add("error");
    setTimeout(function(){drop.classList.remove("error");},700);
    return;
  }
  var fd=new FormData();
  fd.append("file",state.file);
  fd.append("mode",state.mode);
  Object.keys(state.opts).forEach(function(k){ fd.append(k,state.opts[k]?"true":"false"); });

  setRun(true,"Scanning…");
  $("#scanfile").textContent=state.file.name;
  $("#scanstage").textContent="uploading…";
  $("#logfeed").innerHTML="";
  showView("scanning");

  fetch("/api/scan",{method:"POST",body:fd}).then(function(r){return r.json();}).then(function(j){
    if(!j.job_id){ throw new Error(j.error||"upload rejected"); }
    state.currentId=j.job_id;
    logFeed("job "+j.job_id+" accepted");
    poll(j.job_id);
  }).catch(function(e){ showError(String(e&&e.message?e.message:e)); setRun(false,"Run Scan"); });
});
function setRun(disabled,label){
  var b=$("#run"); b.disabled=disabled; if(label) b.textContent=label;
}
function logFeed(msg){
  var d=document.createElement("div");
  d.textContent="["+new Date().toLocaleTimeString()+"] "+msg;
  var f=$("#logfeed"); f.appendChild(d); f.scrollTop=f.scrollHeight;
}
function poll(id){
  fetch("/api/result/"+id).then(function(r){
    return r.json().then(function(j){return {code:r.status,body:j};});
  }).then(function(res){
    if(state.currentId!==id) return; // superseded
    var j=res.body;
    if(j.status==="scanning"||res.code===202){
      $("#scanstage").textContent=(j.stage||"scanning…")+(j.elapsed?(" · "+j.elapsed):"");
      state.pollTimer=setTimeout(function(){poll(id);},800);
      return;
    }
    if(j.status==="error"){ showError(j.error||"scan failed"); setRun(false,"Scan again"); return; }
    if(j.status==="done"){ onDone(id,j); return; }
    showError(j.error||"unexpected response"); setRun(false,"Scan again");
  }).catch(function(e){ showError(String(e)); setRun(false,"Scan again"); });
}
function showError(msg){ $("#errmsg").textContent=msg; showView("error"); }
function onDone(id,res){
  state.jobs[id]=res;
  logFeed("scan complete");
  renderResult(res);
  addHistory(id,res);
  showView("results");
  selectTab("overview");
  setRun(false,"Scan again");
}
function selectTab(name){
  $all(".tab").forEach(function(x){x.classList.toggle("active",x.getAttribute("data-tab")===name);});
  $all(".panel").forEach(function(p){p.classList.remove("active");});
  var p=$("#tab-"+name); if(p) p.classList.add("active");
}

/* ---------- history ---------- */
function addHistory(id,res){
  state.history.unshift({id:id,name:res.file_name||"sample",score:num(res.risk_score),
    mode:res.mode||state.mode,time:Date.now()});
  if(state.history.length>10) state.history.length=10;
  try{ sessionStorage.setItem("flatscan_hist",JSON.stringify(state.history)); }catch(e){}
  renderHistory();
}
function renderHistory(){
  var h=$("#history");
  if(!state.history.length){ h.innerHTML="<div class=\"empty\" style=\"font-size:11px\">no scans yet</div>"; return; }
  h.innerHTML=state.history.map(function(e){
    return "<div class=\"hist\" data-id=\""+esc(e.id)+"\">"+
      "<div class=\"top\"><span class=\"hn trunc\">"+esc(e.name)+"</span>"+
      "<span class=\"hs\" style=\"color:"+scoreColor(e.score)+"\">"+e.score+"</span></div>"+
      "<div class=\"hm\"><span>"+esc(e.mode)+"</span><span>"+timeAgo(e.time)+"</span></div></div>";
  }).join("");
  $all("#history .hist").forEach(function(row){
    row.addEventListener("click",function(){
      var id=row.getAttribute("data-id");
      if(state.jobs[id]){ state.currentId=id; renderResult(state.jobs[id]); showView("results"); selectTab("overview"); }
    });
  });
}

/* ---------- rendering ---------- */
function renderResult(r){
  renderOverview(r);
  renderFindings(r);
  renderIOC(r);
  renderFunctions(r);
  renderPE(r);
  renderArtifacts(r);
  renderProfile(r);
  renderLog(r);
  renderOutputs(r);
}

function kvRow(k,v){ return "<div class=\"kv\"><div class=\"kk\">"+esc(k)+"</div><div class=\"vv\">"+v+"</div></div>"; }
function box(title,bodyHtml,open){
  return "<details class=\"box\""+(open?" open":"")+"><summary><span>"+esc(title)+
    "</span><span class=\"chev\">›</span></summary><div class=\"body\">"+bodyHtml+"</div></details>";
}

function renderOverview(r){
  var pe=r.pe||null, sim=r.similarity||{}, h=r.hashes||{};
  var score=num(r.risk_score);
  var fam=(r.family_matches&&r.family_matches.length)?r.family_matches[0].family:"—";
  var html="";
  // verdict bar
  html+="<div class=\"verdict\"><div class=\"vleft\">"+
    "<div class=\"score\" style=\"color:"+scoreColor(score)+"\">"+score+"</div>"+
    "<div><div class=\"vlabel\" style=\"color:"+scoreColor(score)+"\">"+esc(r.verdict||"unknown")+"</div>"+
    "<div class=\"muted mono\" style=\"font-size:11px\">"+esc(r.file_type||"")+
    (r.mime_hint?(" · "+esc(r.mime_hint)):"")+"</div></div></div>"+
    "<div class=\"vmeta\"><b>"+esc(r.file_name||"")+"</b><br>"+
    fmtBytes(r.size)+" · "+esc(r.mode||"")+" mode<br>"+
    esc(r.duration||"")+" · "+esc(r.tool||"FlatScan")+" "+esc(r.version||"")+"</div></div>";
  // score bar
  html+="<div class=\"scorebar\"><div style=\"width:"+Math.min(100,score)+"%;background:"+scoreColor(score)+"\"></div></div>";
  // breakdown pills
  if(r.score_breakdown&&Object.keys(r.score_breakdown).length){
    html+="<div class=\"pills\">";
    Object.keys(r.score_breakdown).forEach(function(k){
      html+="<span class=\"pill\">"+esc(k)+" <b>"+num(r.score_breakdown[k])+"</b></span>";
    });
    html+="</div>";
  }
  // stat cells (two rows of 4)
  function cell(k,v){ return "<div class=\"cell\"><div class=\"k\">"+esc(k)+"</div><div class=\"v trunc\">"+esc(v)+"</div></div>"; }
  html+="<div class=\"cells\">";
  html+=cell("file type",r.file_type||"—");
  html+=cell("entropy",(num(r.entropy).toFixed(2))+"/8.00");
  html+=cell("strings",num(r.strings_total));
  html+=cell("findings",(r.findings?r.findings.length:0));
  html+=cell("arch",pe?(pe.machine||"—"):"—");
  html+=cell("subsystem",pe?(pe.subsystem||"—"):"—");
  html+=cell("compiled",pe?(pe.timestamp||"—"):"—");
  html+=cell("family",fam);
  html+="</div>";
  // hashes
  var hb="";
  hb+=kvRow("MD5",esc(h.md5||"—")+cp(h.md5||""));
  hb+=kvRow("SHA-1",esc(h.sha1||"—")+cp(h.sha1||""));
  hb+=kvRow("SHA-256",esc(h.sha256||"—")+cp(h.sha256||""));
  hb+=kvRow("SHA-512",esc(h.sha512||"—")+cp(h.sha512||""));
  if(pe&&pe.import_hash) hb+=kvRow("PE imphash",esc(pe.import_hash)+cp(pe.import_hash));
  if(sim.rich_header_hash) hb+=kvRow("Rich hash",esc(sim.rich_header_hash)+cp(sim.rich_header_hash));
  if(sim.flat_hash) hb+=kvRow("FlatHash",esc(sim.flat_hash)+cp(sim.flat_hash));
  if(sim.byte_histogram_hash) hb+=kvRow("BHH",esc(sim.byte_histogram_hash)+cp(sim.byte_histogram_hash));
  if(sim.string_set_hash) hb+=kvRow("StringSetHash",esc(sim.string_set_hash)+cp(sim.string_set_hash));
  html+=box("hashes",hb,true);
  // section entropy map
  if(pe&&pe.sections&&pe.sections.length){
    var sb="";
    pe.sections.forEach(function(s){
      var e=num(s.entropy);
      var col=e<5?"var(--green)":(e<7?"var(--amber)":"var(--red)");
      var flags=(s.executable?"X":"")+(s.writable?"W":""); if(!flags) flags="-";
      sb+="<div class=\"secbar\"><span class=\"trunc\">"+esc(s.name)+"</span>"+
        "<span class=\"track\"><div style=\"width:"+((e/8)*100).toFixed(1)+"%;background:"+col+"\"></div></span>"+
        "<span style=\"color:"+col+"\">"+e.toFixed(2)+"</span><span class=\"muted\">"+flags+"</span></div>";
    });
    if(r.high_entropy_regions&&r.high_entropy_regions.length){
      sb+="<h3 class=\"sh\" style=\"color:var(--red)\">high-entropy regions</h3>";
      r.high_entropy_regions.forEach(function(re){
        sb+="<div class=\"mono\" style=\"color:var(--red);font-size:11px;padding:2px 0\">"+
          hex(re.offset)+" · "+num(re.length)+" bytes · entropy "+num(re.entropy).toFixed(2)+"</div>";
      });
    }
    html+=box("section entropy map",sb,false);
  }
  $("#tab-overview").innerHTML=html;
}

function renderFindings(r){
  var f=r.findings||[];
  if(!f.length){ $("#tab-findings").innerHTML="<div class=\"empty\">no findings</div>"; return; }
  var groups={High:[],Medium:[],"Low / Info":[]};
  f.forEach(function(x){
    var s=String(x.severity||"").toLowerCase();
    if(s==="critical"||s==="high") groups.High.push(x);
    else if(s==="medium") groups.Medium.push(x);
    else groups["Low / Info"].push(x);
  });
  var colors={High:"var(--red)",Medium:"var(--amber)","Low / Info":"var(--blue)"};
  var html="";
  Object.keys(groups).forEach(function(g){
    var arr=groups[g]; if(!arr.length) return;
    var inner="";
    arr.forEach(function(x){
      var sc=sevColor(x.severity);
      var tags="";
      if(x.category) tags+="<span class=\"tag\">"+esc(x.category)+"</span>";
      if(x.technique) tags+="<span class=\"tag\">"+esc(x.technique)+"</span>";
      var detail="";
      if(x.evidence) detail+="<div class=\"lbl\">evidence</div><div class=\"mono\">"+esc(x.evidence)+"</div>";
      if(x.tactic) detail+="<div class=\"lbl\">tactic</div><div>"+esc(x.tactic)+"</div>";
      if(x.technique) detail+="<div class=\"lbl\">technique</div><div>"+esc(x.technique)+"</div>";
      if(x.offset) detail+="<div class=\"lbl\">offset</div><div class=\"mono\">"+hex(x.offset)+"</div>";
      if(x.recommendation) detail+="<div class=\"lbl\">recommendation</div><div>"+esc(x.recommendation)+"</div>";
      if(!detail) detail="<div class=\"muted\">no further detail</div>";
      inner+="<div class=\"finding\" style=\"border-left-color:"+sc+"\">"+
        "<div class=\"ft\"><span class=\"title\">"+esc(x.title||"finding")+"</span>"+
        "<span class=\"badge\" style=\"color:"+sc+";border:1px solid "+sc+"\">"+num(x.score)+"</span></div>"+
        "<div class=\"tags\"><span class=\"tag\" style=\"color:"+sc+";border-color:"+sc+"\">"+esc(x.severity||"")+"</span>"+tags+"</div>"+
        "<div class=\"detail\">"+detail+"</div></div>";
    });
    html+="<div class=\"fgroup\"><div class=\"fhead\" style=\"color:"+colors[g]+";border-color:"+colors[g]+"\">"+
      "<span>"+g+"</span><span>"+arr.length+"</span></div>"+inner+"</div>";
  });
  var el=$("#tab-findings"); el.innerHTML=html;
  el.querySelectorAll(".finding").forEach(function(row){
    row.addEventListener("click",function(){row.classList.toggle("open");});
  });
}

function renderIOC(r){
  var iocs=r.iocs||{};
  var cats=[
    ["domains","domains"],["urls","urls"],["ipv4","ipv4"],["ipv6","ipv6"],["emails","emails"],
    ["md5","md5"],["sha1","sha1"],["sha256","sha256"],["registry_keys","registry keys"],
    ["windows_paths","windows paths"],["mutexes","mutexes"],["named_pipes","named pipes"],
    ["crypto_wallets","crypto wallets"]
  ];
  var present=cats.filter(function(c){ return iocs[c[0]]&&iocs[c[0]].length; });
  var sup=num(iocs.suppressed_count);
  if(!present.length){
    $("#tab-ioc").innerHTML="<div class=\"empty\">no indicators extracted</div>"+
      (sup>0?"<div class=\"muted mono\" style=\"font-size:11px\">"+sup+" suppressed</div>":"");
    return;
  }
  var html="<div class=\"subtabs\">";
  present.forEach(function(c,i){
    html+="<div class=\"subtab"+(i===0?" active":"")+"\" data-cat=\""+esc(c[0])+"\">"+
      esc(c[1])+" <span class=\"muted\">"+iocs[c[0]].length+"</span></div>";
  });
  html+="</div>";
  present.forEach(function(c,i){
    html+="<div class=\"ioclist iocpane\" data-cat=\""+esc(c[0])+"\" style=\"display:"+(i===0?"flex":"none")+"\">";
    iocs[c[0]].forEach(function(v){
      html+="<div class=\"iocrow\"><span>"+esc(v)+"</span>"+cp(v)+"</div>";
    });
    html+="</div>";
  });
  if(sup>0) html+="<div class=\"muted mono\" style=\"font-size:11px;margin-top:12px\">"+sup+" indicator(s) suppressed by allowlist</div>";
  var el=$("#tab-ioc"); el.innerHTML=html;
  el.querySelectorAll(".subtab").forEach(function(t){
    t.addEventListener("click",function(){
      el.querySelectorAll(".subtab").forEach(function(x){x.classList.remove("active");});
      t.classList.add("active");
      var cat=t.getAttribute("data-cat");
      el.querySelectorAll(".iocpane").forEach(function(p){
        p.style.display=(p.getAttribute("data-cat")===cat)?"flex":"none";
      });
    });
  });
}

function renderFunctions(r){
  var fns=r.functions||[];
  if(!fns.length){ $("#tab-functions").innerHTML="<div class=\"empty\">no behavioral functions detected</div>"; return; }
  var best={};
  fns.forEach(function(f){
    var key=f.name||"";
    if(!best[key]||sevRank(f.severity)>sevRank(best[key].severity)) best[key]=f;
  });
  var list=Object.keys(best).map(function(k){return best[k];});
  list.sort(function(a,b){return sevRank(b.severity)-sevRank(a.severity);});
  var rows=list.map(function(f){
    return "<tr><td class=\"trunc\">"+esc(f.name)+"</td><td>"+esc(f.family||"—")+
      "</td><td style=\"color:"+sevColor(f.severity)+"\">"+esc(f.severity||"—")+
      "</td><td class=\"muted\">"+esc(f.source||"—")+"</td></tr>";
  }).join("");
  $("#tab-functions").innerHTML="<table class=\"grid\"><thead><tr><th>function</th><th>category</th>"+
    "<th>severity</th><th>source</th></tr></thead><tbody>"+rows+"</tbody></table>";
}

function renderPE(r){
  var pe=r.pe;
  if(!pe){ $("#tab-pe").innerHTML="<div class=\"empty\">not a PE file</div>"; return; }
  var html="";
  var hb="";
  hb+=kvRow("machine",esc(pe.machine||"—"));
  hb+=kvRow("subsystem",esc(pe.subsystem||"—"));
  hb+=kvRow("timestamp",esc(pe.timestamp||"—"));
  hb+=kvRow("image base",pe.image_base?esc(pe.image_base):"—");
  hb+=kvRow("entry point",pe.entry_point?esc(pe.entry_point):"—");
  hb+=kvRow("managed runtime",pe.managed_runtime?"yes":"no");
  hb+=kvRow("certificate",pe.has_certificate?"present":"none");
  if(pe.import_hash) hb+=kvRow("imphash",esc(pe.import_hash)+cp(pe.import_hash));
  html+=box("PE header",hb,true);

  // suspicious imports = imports also present in functions as High/Medium
  var sus={};
  (r.functions||[]).forEach(function(f){
    var rk=sevRank(f.severity);
    if(rk>=2 && f.name) sus[f.name.toLowerCase()]=(rk>=3)?"var(--red)":"var(--amber)";
  });
  var imps=pe.imports||[];
  if(imps.length){
    var shown=imps.slice(0,20);
    var ib="<div class=\"implist\">";
    shown.forEach(function(im){
      var col=sus[String(im).toLowerCase()];
      ib+="<div class=\"imp trunc\""+(col?(" style=\"color:"+col+"\""):"")+">"+esc(im)+"</div>";
    });
    ib+="</div>";
    if(imps.length>20) ib+="<div class=\"muted mono\" style=\"font-size:11px;margin-top:8px\">"+(imps.length-20)+" more imports</div>";
    html+=box("imports ("+imps.length+")",ib,true);
  }
  $("#tab-pe").innerHTML=html;
}

function renderArtifacts(r){
  var html="";
  // carved
  var ca=r.carved_artifacts||[];
  if(ca.length){
    var cb="";
    ca.forEach(function(a){
      cb+="<div style=\"border-bottom:1px solid var(--surface2);padding:8px 0\">"+
        "<div><b>"+esc(a.type||"artifact")+"</b> <span class=\"muted mono\">"+hex(a.offset)+" · "+num(a.length)+" bytes · H "+num(a.entropy).toFixed(2)+"</span></div>"+
        (a.sha256?"<div class=\"mono\" style=\"font-size:11px\">"+esc(a.sha256)+cp(a.sha256)+"</div>":"")+
        (a.reason?"<div class=\"muted\" style=\"font-size:11px\">"+esc(a.reason)+"</div>":"")+
        (a.preview?"<div class=\"mono muted\" style=\"font-size:11px\">"+esc(a.preview)+"</div>":"")+"</div>";
    });
    html+=box("carved artifacts ("+ca.length+")",cb,true);
  }
  // config
  var cfa=r.config_artifacts||[];
  if(cfa.length){
    var fb="";
    cfa.forEach(function(a){
      fb+="<div style=\"border-bottom:1px solid var(--surface2);padding:8px 0\">"+
        "<div><b>"+esc(a.type||"config")+"</b> <span class=\"muted\">"+esc(a.source||"")+
        (a.confidence?(" · "+esc(a.confidence)):"")+"</span></div>"+
        (a.evidence?"<div class=\"mono\" style=\"font-size:11px\">"+esc(a.evidence)+"</div>":"")+
        (a.preview?"<div class=\"mono muted\" style=\"font-size:11px\">"+esc(a.preview)+"</div>":"")+"</div>";
    });
    html+=box("config artifacts ("+cfa.length+")",fb,false);
  }
  // external tools
  var et=r.external_tools||[];
  if(et.length){
    var eb="";
    et.forEach(function(t){
      var col=t.found?"var(--green)":"var(--muted)";
      var out=(t.output||t.error||t.status||"");
      if(out.length>120) out=out.slice(0,120)+"…";
      eb+="<div style=\"border-bottom:1px solid var(--surface2);padding:6px 0\">"+
        "<span style=\"color:"+col+"\" class=\"mono\">"+esc(t.name)+"</span>"+
        (t.timed_out?" <span class=\"muted\">(timed out)</span>":"")+
        "<div class=\"mono muted\" style=\"font-size:11px\">"+esc(out)+"</div></div>";
    });
    html+=box("external tools ("+et.length+")",eb,false);
  }
  // family matches
  var fm=r.family_matches||[];
  if(fm.length){
    var mb="";
    fm.forEach(function(m){
      mb+="<div style=\"border-bottom:1px solid var(--surface2);padding:8px 0\">"+
        "<div><b>"+esc(m.family)+"</b> <span class=\"muted\">"+esc(m.category||"")+" · "+
        esc(m.confidence||"")+" · score "+num(m.score)+"</span></div>"+
        ((m.evidence&&m.evidence.length)?"<ul class=\"list-dot\">"+m.evidence.map(function(e){return "<li>"+esc(e)+"</li>";}).join("")+"</ul>":"")+
        "</div>";
    });
    html+=box("family matches ("+fm.length+")",mb,true);
  }
  if(!html) html="<div class=\"empty\">no carved or config artifacts</div>";
  $("#tab-artifacts").innerHTML=html;
}

function renderProfile(r){
  var p=r.profile||{};
  var html="";
  html+="<h3 class=\"sh\" style=\"font-size:16px\">"+esc(p.classification||"unclassified")+"</h3>";
  if(p.malware_type&&p.malware_type.length)
    html+="<div class=\"pills\">"+p.malware_type.map(function(t){return "<span class=\"pill\"><b>"+esc(t)+"</b></span>";}).join("")+"</div>";
  if(p.confidence||p.confidence_score)
    html+="<div class=\"muted mono\" style=\"font-size:11px;margin-bottom:10px\">confidence: "+esc(p.confidence||"")+" ("+num(p.confidence_score)+")</div>";
  if(p.executive_assessment)
    html+="<p style=\"max-width:760px;color:var(--text)\">"+esc(p.executive_assessment)+"</p>";

  if(p.key_capabilities&&p.key_capabilities.length){
    html+="<h3 class=\"sh\">key capabilities</h3><ul class=\"list-dot\">"+
      p.key_capabilities.map(function(c){return "<li>"+esc(c)+"</li>";}).join("")+"</ul>";
  }
  if(p.ttps&&p.ttps.length){
    html+="<h3 class=\"sh\">MITRE ATT&amp;CK</h3><table class=\"grid\"><thead><tr><th>tactic</th>"+
      "<th>technique</th><th>id</th><th>confidence</th></tr></thead><tbody>";
    p.ttps.forEach(function(t){
      html+="<tr><td>"+esc(t.tactic||"")+"</td><td class=\"trunc\">"+esc(t.technique||"")+
        "</td><td><span class=\"tag\" style=\"color:var(--blue);border-color:var(--blue)\">"+esc(t.id||"—")+
        "</span></td><td style=\"color:"+sevColor(t.severity)+"\">"+esc(t.confidence||"")+"</td></tr>";
    });
    html+="</tbody></table>";
  }
  if(p.crypto_indicators&&p.crypto_indicators.length){
    html+="<h3 class=\"sh\">crypto indicators</h3>";
    p.crypto_indicators.forEach(function(c){
      html+="<div style=\"padding:6px 0;border-bottom:1px solid var(--surface2)\">"+
        "<span class=\"mono\" style=\"color:var(--purple)\">"+esc(c.primitive)+"</span> "+
        "<span class=\"muted\">"+esc(c.purpose||"")+(c.confidence?(" · "+esc(c.confidence)):"")+"</span>"+
        (c.evidence?"<div class=\"mono muted\" style=\"font-size:11px\">"+esc(c.evidence)+"</div>":"")+"</div>";
    });
  }
  if(p.recommended_actions&&p.recommended_actions.length){
    html+="<h3 class=\"sh\">recommended actions</h3><ul class=\"list-dot\">"+
      p.recommended_actions.map(function(a){return "<li>"+esc(a)+"</li>";}).join("")+"</ul>";
  }
  if(p.business_impact&&p.business_impact.length){
    html+="<h3 class=\"sh\">business impact</h3><ul class=\"list-dot\">"+
      p.business_impact.map(function(a){return "<li>"+esc(a)+"</li>";}).join("")+"</ul>";
  }
  $("#tab-profile").innerHTML=html;
}

function renderLog(r){
  var log=r.debug_log||[];
  if(!log.length){ $("#tab-log").innerHTML="<div class=\"empty\">run with --debug to capture log output</div>"; return; }
  var html=log.map(function(line){
    var col="var(--muted)";
    if(line.indexOf("[WARN]")>=0) col="var(--amber)";
    else if(line.indexOf("[DEBUG]")>=0) col="var(--blue)";
    else if(line.indexOf("[OK]")>=0) col="var(--green)";
    else if(line.indexOf("[INFO]")>=0) col="var(--text)";
    return "<div class=\"logline\" style=\"color:"+col+"\">"+esc(line)+"</div>";
  }).join("");
  $("#tab-log").innerHTML=html;
}

function renderOutputs(r){
  var avail=r.available_downloads||[];
  var meta={
    json:["application/json","machine-readable JSON result"],
    txt:["text report","full plain-text analyst report"],
    iocs:["ioc list","extracted indicators of compromise"],
    yar:["YARA","generated YARA hunting rule"],
    yml:["Sigma","generated Sigma detection rule"],
    stix:["STIX 2.1","threat-intel bundle (STIX 2.1)"],
    pack:["report pack","full report pack (.zip)"]
  };
  if(!avail.length){ $("#tab-outputs").innerHTML="<div class=\"empty\">no downloadable outputs</div>"; return; }
  var html="";
  avail.forEach(function(fmt){
    var m=meta[fmt]||[fmt,fmt];
    var url="/api/download/"+esc(state.currentId)+"/"+esc(fmt);
    html+="<div class=\"outrow\"><span class=\"ext\">"+esc(m[0])+"</span>"+
      "<span class=\"desc trunc\">"+esc(m[1])+"</span>"+
      "<span class=\"sz\">"+(fmt==="pack"?".zip":"."+esc(fmt))+"</span>"+
      "<a class=\"dlbtn\" href=\""+url+"\">&#8595; download</a></div>";
  });
  $("#tab-outputs").innerHTML=html;
}

/* ---------- restore history ---------- */
(function(){
  try{
    var saved=sessionStorage.getItem("flatscan_hist");
    if(saved){ state.history=JSON.parse(saved)||[]; renderHistory(); }
  }catch(e){}
})();
</script>
</body>
</html>`
