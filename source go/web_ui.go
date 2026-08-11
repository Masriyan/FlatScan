package main

// webUIHTML is the complete single-page FlatScan web GUI. It is fully
// self-contained: all CSS and JavaScript are inlined and there are no external
// CDN, font, or package dependencies. The constant is a Go raw string literal,
// so it must never contain a backtick — the embedded JavaScript therefore uses
// string concatenation instead of template literals.
//
// Layout model: a compact command bar (scan setup, used once per scan), a
// sticky verdict header (always-visible score provenance), and a full-width
// workspace. The workspace is organised around what an analyst does — triage
// evidence, collect indicators, follow payloads, predict behaviour, inspect
// structure, export — rather than around the shape of the ScanResult JSON.
const webUIHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FlatScan</title>
<style>
/* ============ tokens ============
   Dark is the default (analyst tooling lives on dark), but every colour is a
   token so the light theme is a pure token swap. Light matters because findings
   get pasted into tickets and reports, where dark screenshots read badly. */
:root{
  --bg:#0e0f13; --surface:#15171d; --surface2:#1b1e26; --raise:#212530;
  --border:#272b36; --border2:#39404f;
  --text:#e6e8ef; --muted:#9aa0b0; --faint:#727888;
  --red:#ff6b6b; --amber:#ffb454; --green:#4ade80; --blue:#60a5fa;
  --purple:#c4a2ff; --teal:#2dd4bf;
  --red-bg:rgba(255,107,107,.12); --amber-bg:rgba(255,180,84,.12);
  --green-bg:rgba(74,222,128,.12); --blue-bg:rgba(96,165,250,.12);
  --teal-bg:rgba(45,212,191,.12);
  --shadow:0 8px 24px rgba(0,0,0,.45);
  --ui:system-ui,-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
  --mono:ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono',monospace;

  /* Categorical series slots for the score-contribution bar. Fixed hue order,
     never cycled: a category always draws the same slot so colour follows the
     entity, not its rank. Validated as a set against this surface — worst
     adjacent CVD deltaE 8.4, normal-vision 19.3, all >= 3:1 contrast. */
  --s1:#3987e5; --s2:#d95926; --s3:#199e70; --s4:#c98500;
  --s5:#d55181; --s6:#008300; --s7:#9085e9; --s8:#e66767;
  --sother:#6b7180;
  /* Sequential ramp for entropy (a magnitude, so one hue light-to-dark).
     On the dark surface near-zero recedes toward the surface, so the ramp
     runs dark-to-light as entropy climbs. */
  --e0:#0d366b; --e1:#104281; --e2:#184f95; --e3:#256abf;
  --e4:#3987e5; --e5:#6da7ec; --e6:#9ec5f4;
}
:root[data-theme="light"]{
  --bg:#f5f6f8; --surface:#ffffff; --surface2:#eef0f4; --raise:#e6e9ef;
  --border:#dde1e9; --border2:#c3cad7;
  --text:#12141a; --muted:#565d6e; --faint:#7d8494;
  --red:#c62828; --amber:#9a5b00; --green:#1b7f3b; --blue:#1d4ed8;
  --purple:#6d28d9; --teal:#0f766e;
  --red-bg:rgba(198,40,40,.09); --amber-bg:rgba(154,91,0,.10);
  --green-bg:rgba(27,127,59,.10); --blue-bg:rgba(29,78,216,.09);
  --teal-bg:rgba(15,118,110,.09);
  --shadow:0 8px 24px rgba(20,25,40,.10);
  /* Same eight hues stepped for the light surface, validated as a set:
     worst adjacent CVD deltaE 9.1, normal-vision 19.6. Three slots sit under
     3:1 here, so the legend always ships a visible text label beside the
     swatch — identity is never carried by colour alone. */
  --s1:#2a78d6; --s2:#eb6834; --s3:#1baf7a; --s4:#eda100;
  --s5:#e87ba4; --s6:#008300; --s7:#4a3aa7; --s8:#e34948;
  --sother:#8a9099;
  /* Light surface: near-zero entropy recedes toward white, so light-to-dark. */
  --e0:#cde2fb; --e1:#9ec5f4; --e2:#6da7ec; --e3:#3987e5;
  --e4:#2a78d6; --e5:#256abf; --e6:#184f95;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;height:100%}
body{background:var(--bg);color:var(--text);font-family:var(--ui);font-size:13.5px;line-height:1.55;
  -webkit-font-smoothing:antialiased}
a{color:var(--blue);text-decoration:none}
.mono{font-family:var(--mono)}
.muted{color:var(--muted)}
.faint{color:var(--faint)}
.trunc{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
button{font-family:inherit;font-size:inherit;color:inherit}
:focus-visible{outline:2px solid var(--teal);outline-offset:2px;border-radius:3px}
#app{display:flex;flex-direction:column;height:100vh;overflow:hidden}

/* ============ command bar ============ */
#bar{display:flex;align-items:center;gap:14px;padding:0 16px;height:52px;flex:0 0 auto;
  background:var(--surface);border-bottom:1px solid var(--border);position:relative;z-index:30}
.brand{display:flex;align-items:baseline;gap:7px}
.brand .logo{font-family:var(--mono);font-weight:700;font-size:15px;color:var(--teal);letter-spacing:-.02em}
.brand .ver{font-size:10px;color:var(--faint);font-family:var(--mono)}
.barsep{width:1px;height:24px;background:var(--border)}
.barspace{flex:1}

#target{display:flex;align-items:center;gap:8px;min-width:0}
#drop{display:flex;align-items:center;gap:8px;border:1.5px dashed var(--border2);border-radius:7px;
  padding:6px 14px;color:var(--muted);cursor:pointer;font-size:12.5px;white-space:nowrap;
  transition:border-color .15s,background .15s,color .15s;background:transparent}
#drop:hover{border-color:var(--teal);color:var(--teal)}
#drop.hover{border-color:var(--teal);background:var(--teal-bg);color:var(--teal)}
#drop.error{border-color:var(--red);background:var(--red-bg);color:var(--red)}
#filebox{display:none;align-items:center;gap:9px;border:1px solid var(--border);border-radius:7px;
  padding:5px 8px 5px 12px;background:var(--surface2);max-width:340px}
#filebox.show{display:flex}
#filebox .fn{font-family:var(--mono);font-size:12.5px;color:var(--teal);min-width:0;max-width:190px}
#filebox .meta{font-size:11px;color:var(--faint);font-family:var(--mono);white-space:nowrap}
#clearfile{cursor:pointer;color:var(--faint);font-size:15px;line-height:1;background:none;border:none;padding:2px 4px}
#clearfile:hover{color:var(--red)}

.seg{display:flex;border:1px solid var(--border);border-radius:7px;overflow:hidden;background:var(--surface2)}
.seg .mode-btn{padding:6px 13px;cursor:pointer;font-size:12px;color:var(--muted);font-family:var(--mono);
  border-right:1px solid var(--border);background:none;border-top:none;border-bottom:none;border-left:none}
.seg .mode-btn:last-child{border-right:none}
.seg .mode-btn:hover{color:var(--text)}
.seg .mode-btn.active{background:var(--teal-bg);color:var(--teal);font-weight:600}

.ghost{border:1px solid var(--border);background:var(--surface2);color:var(--muted);border-radius:7px;
  padding:6px 12px;cursor:pointer;font-size:12.5px;display:flex;align-items:center;gap:7px;white-space:nowrap}
.ghost:hover{border-color:var(--border2);color:var(--text)}
.ghost .dot{width:6px;height:6px;border-radius:50%;background:var(--teal)}

#optpop{display:none;position:absolute;top:46px;right:150px;background:var(--surface);border:1px solid var(--border2);
  border-radius:9px;padding:8px;box-shadow:var(--shadow);z-index:40;min-width:212px}
#optpop.show{display:block}
.opt{display:flex;justify-content:space-between;align-items:center;gap:14px;padding:7px 9px;border-radius:6px;
  cursor:pointer;background:none;border:none;width:100%;text-align:left}
.opt:hover{background:var(--surface2)}
.opt .name{font-family:var(--mono);font-size:12px}
.opt .state{font-size:11px;color:var(--faint);font-family:var(--mono)}
.opt.on .state{color:var(--green)}

#run{padding:7px 18px;border:1px solid var(--green);border-radius:7px;background:var(--green-bg);
  color:var(--green);font-weight:600;cursor:pointer;font-size:12.5px;white-space:nowrap}
#run:hover:not(:disabled){background:var(--green);color:var(--bg)}
#run:disabled{opacity:.5;cursor:default}
.iconbtn{border:1px solid var(--border);background:var(--surface2);color:var(--muted);border-radius:7px;
  width:32px;height:32px;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:14px}
.iconbtn:hover{color:var(--text);border-color:var(--border2)}

/* ============ verdict header ============ */
#verdict{flex:0 0 auto;display:none;background:var(--surface);border-bottom:1px solid var(--border);
  padding:15px 20px 0}
#verdict.show{display:block}
.vtop{display:flex;align-items:flex-start;gap:22px;flex-wrap:wrap}
.vscore{font-family:var(--mono);font-size:46px;font-weight:700;line-height:.95;letter-spacing:-.03em}
.vmain{flex:1;min-width:200px}
.vlabel{font-size:17px;font-weight:650;letter-spacing:-.01em}
.vsub{font-size:12px;color:var(--muted);margin-top:2px}
.vsub b{color:var(--text);font-weight:600}
.vright{text-align:right;font-size:11.5px;color:var(--faint);font-family:var(--mono);line-height:1.7}
.vright b{color:var(--text);font-weight:600;font-size:12.5px}

/* score provenance: a stacked contribution bar you can actually interrogate */
.prov{margin:14px 0 0}
.provbar{display:flex;height:9px;border-radius:5px;overflow:hidden;background:var(--surface2);
  border:1px solid var(--border)}
.provbar>button{height:100%;border:none;padding:0;cursor:pointer;transition:filter .12s;min-width:3px}
.provbar>button:hover{filter:brightness(1.35)}
.provbar>button.dim{opacity:.28}
.provkeys{display:flex;flex-wrap:wrap;gap:6px;margin-top:9px}
.provkey{display:flex;align-items:center;gap:6px;font-size:11.5px;font-family:var(--mono);
  border:1px solid var(--border);border-radius:20px;padding:3px 10px 3px 7px;background:var(--surface2);
  color:var(--muted);cursor:pointer}
.provkey:hover{border-color:var(--border2);color:var(--text)}
.provkey.active{border-color:var(--teal);color:var(--teal);background:var(--teal-bg)}
.provkey .sw{width:8px;height:8px;border-radius:2px;flex:0 0 auto}
.provkey b{color:var(--text);font-weight:600}
.provkey.active b{color:var(--teal)}

.banner{display:flex;gap:11px;align-items:flex-start;border:1px solid var(--border2);border-left:3px solid var(--blue);
  background:var(--blue-bg);border-radius:7px;padding:10px 13px;margin-top:13px;font-size:12.5px}
.banner .bt{font-weight:650;margin-bottom:2px}
.banner.warn{border-left-color:var(--amber);background:var(--amber-bg)}

/* ============ tabs ============ */
#tabbar{display:flex;gap:3px;padding:12px 20px 0;overflow-x:auto;scrollbar-width:none}
#tabbar::-webkit-scrollbar{display:none}
.tab{padding:8px 14px;cursor:pointer;color:var(--muted);font-size:12.5px;white-space:nowrap;
  border:1px solid transparent;border-bottom:none;border-radius:7px 7px 0 0;background:none;
  display:flex;align-items:center;gap:7px;position:relative;top:1px}
.tab:hover{color:var(--text)}
.tab.active{color:var(--text);background:var(--bg);border-color:var(--border);font-weight:600}
.tab .cnt{font-family:var(--mono);font-size:10.5px;color:var(--faint);background:var(--surface2);
  border-radius:10px;padding:1px 6px}
.tab.active .cnt{color:var(--teal);background:var(--teal-bg)}
.tab .kbd{font-family:var(--mono);font-size:9.5px;color:var(--faint);opacity:.65}

/* ============ workspace ============ */
#work{flex:1;overflow:hidden;display:flex;flex-direction:column;min-height:0;
  border-top:1px solid var(--border)}
#stage{flex:1;overflow-y:auto;padding:18px 20px 40px;min-height:0}
.panel{display:none}
.panel.active{display:block}

/* master-detail evidence workspace */
.md{display:grid;grid-template-columns:minmax(320px,1.05fr) minmax(340px,1.35fr);gap:16px;align-items:start}
.mdlist{display:flex;flex-direction:column;gap:5px;min-width:0}
.toolrow{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:11px}
.search{flex:1;min-width:150px;background:var(--surface);border:1px solid var(--border);border-radius:7px;
  padding:7px 11px;color:var(--text);font-size:12.5px;font-family:var(--ui)}
.search::placeholder{color:var(--faint)}
.search:focus{border-color:var(--teal);outline:none}
.chip{font-family:var(--mono);font-size:11.5px;padding:5px 11px;border:1px solid var(--border);border-radius:20px;
  background:var(--surface);color:var(--muted);cursor:pointer;white-space:nowrap}
.chip:hover{border-color:var(--border2);color:var(--text)}
.chip.active{border-color:var(--teal);color:var(--teal);background:var(--teal-bg)}
.chip .n{opacity:.7;margin-left:3px}

.ev{display:grid;grid-template-columns:3px 1fr auto;gap:0 11px;background:var(--surface);
  border:1px solid var(--border);border-radius:8px;padding:0;cursor:pointer;overflow:hidden;
  text-align:left;width:100%;font:inherit;color:inherit}
.ev:hover{border-color:var(--border2)}
.ev.sel{border-color:var(--teal);background:var(--teal-bg)}
.ev .stripe{background:var(--border2)}
.ev .evbody{padding:9px 0 9px 0;min-width:0}
.ev .evtitle{font-size:12.8px;font-weight:600;line-height:1.35}
.ev .evmeta{display:flex;gap:6px;flex-wrap:wrap;margin-top:5px;align-items:center}
.ev .evright{padding:9px 11px 9px 0;display:flex;flex-direction:column;align-items:flex-end;gap:5px}
.ev.done{opacity:.5}
.tag{font-family:var(--mono);font-size:10px;border:1px solid var(--border);border-radius:4px;padding:1px 6px;
  color:var(--muted);white-space:nowrap}
.tag.sev{font-weight:700;letter-spacing:.04em;text-transform:uppercase}
.badge{font-family:var(--mono);font-size:11.5px;font-weight:700;border-radius:5px;padding:1px 8px;border:1px solid}
.tri{font-family:var(--mono);font-size:9.5px;letter-spacing:.05em;text-transform:uppercase;
  border-radius:4px;padding:1px 6px;border:1px solid}
.tri.reviewed{color:var(--green);border-color:var(--green);background:var(--green-bg)}
.tri.fp{color:var(--faint);border-color:var(--border2)}
.tri.escalate{color:var(--red);border-color:var(--red);background:var(--red-bg)}

.detail{background:var(--surface);border:1px solid var(--border);border-radius:9px;padding:16px 17px;
  position:sticky;top:0;max-height:calc(100vh - 260px);overflow-y:auto}
.detail h3{margin:0 0 3px;font-size:15px;font-weight:650;line-height:1.3}
.detail .dmeta{display:flex;gap:6px;flex-wrap:wrap;margin:9px 0 14px}
.dsec{margin-top:14px}
.dsec .dl{font-size:10px;letter-spacing:.11em;text-transform:uppercase;color:var(--faint);margin-bottom:4px}
.dsec .dv{font-size:12.5px;word-break:break-word}
.dsec .dv.mono{font-family:var(--mono);font-size:12px;background:var(--surface2);border:1px solid var(--border);
  border-radius:6px;padding:8px 10px;white-space:pre-wrap}
.triage{display:flex;gap:6px;margin-top:16px;padding-top:14px;border-top:1px solid var(--border);flex-wrap:wrap}
.tbtn{border:1px solid var(--border);background:var(--surface2);color:var(--muted);border-radius:6px;
  padding:6px 11px;cursor:pointer;font-size:11.5px;display:flex;align-items:center;gap:6px}
.tbtn:hover{border-color:var(--border2);color:var(--text)}
.tbtn.on{border-color:var(--teal);color:var(--teal);background:var(--teal-bg)}
.tbtn .k{font-family:var(--mono);font-size:9.5px;opacity:.6}

/* indicators */
.iocgrid{display:flex;flex-direction:column;gap:4px}
.iocrow{display:grid;grid-template-columns:22px 1fr auto;gap:10px;align-items:center;padding:7px 11px;
  background:var(--surface);border:1px solid var(--border);border-radius:7px;font-family:var(--mono);font-size:12.5px}
.iocrow:hover{border-color:var(--border2)}
.iocrow input{accent-color:var(--teal);width:14px;height:14px;cursor:pointer}
.iocrow .val{word-break:break-all;min-width:0}
.iocrow .src{font-size:10.5px;color:var(--faint);white-space:nowrap}
.copy{background:none;border:none;color:var(--faint);cursor:pointer;font-size:12px;padding:0 4px;font-family:var(--mono)}
.copy:hover{color:var(--teal)}

/* file map: where the entropy actually sits, along the byte axis */
.filemap{background:var(--surface);border:1px solid var(--border);border-radius:9px;padding:15px 16px;margin-bottom:12px}
.fmhead{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:11px}
.fmtitle{font-size:12.5px;font-weight:650}
.fmtrack{position:relative;height:34px;border-radius:5px;overflow:hidden;background:var(--surface2);
  border:1px solid var(--border)}
/* Sections are placed at their true raw offset, not laid end to end, so the
   strip reads as a real map of the file rather than a proportion chart. */
.fmseg{position:absolute;top:0;bottom:0;min-width:2px;box-shadow:0 0 0 1px var(--surface) inset}
.fmflex{position:relative;height:100%}
.fmmark{position:absolute;top:0;bottom:0;width:2px;background:var(--amber)}
.fmmark.carve{background:var(--purple)}
.fmaxis{display:flex;justify-content:space-between;font-family:var(--mono);font-size:10px;color:var(--faint);margin-top:5px}
.fmlegend{display:flex;align-items:center;gap:9px;margin-top:11px;flex-wrap:wrap;font-size:11px;color:var(--muted)}
.fmramp{display:flex;height:9px;width:120px;border-radius:3px;overflow:hidden;border:1px solid var(--border)}
.fmramp>span{flex:1}
.fmkey{display:flex;align-items:center;gap:5px;font-family:var(--mono);font-size:10.5px}
.fmkey .kd{width:9px;height:9px;border-radius:2px}
.fmrows{margin-top:12px;display:flex;flex-direction:column;gap:3px}
.fmrow{display:grid;grid-template-columns:110px 1fr 62px 44px;gap:9px;align-items:center;
  font-family:var(--mono);font-size:11.5px;padding:3px 0}
.fmbar{height:9px;border-radius:3px;background:var(--surface2);border:1px solid var(--border);overflow:hidden}
.fmbar>div{height:100%}

/* config / operator intelligence */
.cfggrid{display:flex;flex-direction:column;gap:4px}
.cfgrow{display:grid;grid-template-columns:132px 1fr auto;gap:11px;align-items:center;padding:7px 11px;
  background:var(--surface);border:1px solid var(--border);border-radius:7px}
.cfgrow .ck{font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--faint)}
.cfgrow .cv{font-family:var(--mono);font-size:12.5px;word-break:break-all;min-width:0}
.cfgrow.hot{border-color:var(--red);background:var(--red-bg)}

/* suppressed indicators — the false-positive guard, made inspectable */
.suprow{display:grid;grid-template-columns:76px 1fr auto;gap:11px;align-items:center;padding:6px 11px;
  background:var(--surface);border:1px dashed var(--border2);border-radius:7px;
  font-family:var(--mono);font-size:12px;opacity:.82}
.suprow .sk{font-size:10px;color:var(--faint);text-transform:uppercase;letter-spacing:.06em}
.suprow .sr{font-size:10.5px;color:var(--faint);white-space:nowrap}

/* detection provenance */
.rulerow{display:grid;grid-template-columns:auto 1fr auto;gap:11px;align-items:start;padding:9px 12px;
  background:var(--surface);border:1px solid var(--border);border-radius:7px;margin-bottom:5px}
.ruleid{font-family:var(--mono);font-size:10.5px;color:var(--teal);border:1px solid var(--teal);
  border-radius:4px;padding:1px 7px;white-space:nowrap}

/* raw-score toggle */
.rawtoggle{border:1px solid var(--border2);background:var(--surface2);color:var(--muted);border-radius:6px;
  padding:3px 10px;cursor:pointer;font-size:11px;font-family:var(--mono);margin-left:10px}
.rawtoggle:hover{color:var(--text);border-color:var(--text)}
.rawtoggle.on{border-color:var(--amber);color:var(--amber);background:var(--amber-bg)}
.vscore.raw{opacity:.55;text-decoration:line-through;font-size:26px;margin-right:8px}

/* payload tree */
.pnode{display:flex;gap:11px;align-items:flex-start;padding:10px 12px;background:var(--surface);
  border:1px solid var(--border);border-radius:8px;margin-bottom:6px}
.pnode .rail{font-family:var(--mono);font-size:11px;color:var(--faint);white-space:nowrap;padding-top:1px}
.pnode .pmeta{font-size:11.5px;color:var(--muted);margin-top:3px;font-family:var(--mono)}
.method{font-family:var(--mono);font-size:11px;border-radius:4px;padding:1px 7px;border:1px solid var(--purple);
  color:var(--purple);background:rgba(196,162,255,.10)}

/* generic blocks */
details.box{border:1px solid var(--border);border-radius:9px;margin-bottom:12px;background:var(--surface)}
details.box>summary{cursor:pointer;padding:11px 15px;font-weight:600;font-size:12.5px;list-style:none;
  display:flex;justify-content:space-between;align-items:center}
details.box>summary::-webkit-details-marker{display:none}
details.box>summary .chev{color:var(--faint);font-size:11px;transition:transform .15s}
details.box[open]>summary .chev{transform:rotate(90deg)}
details.box .body{padding:2px 15px 15px}
.kv{display:flex;gap:12px;padding:5px 0;border-bottom:1px solid var(--surface2);min-width:0}
.kv:last-child{border-bottom:none}
.kv .kk{width:128px;min-width:128px;color:var(--muted);font-size:11.5px}
.kv .vv{font-family:var(--mono);font-size:12px;word-break:break-all;flex:1;min-width:0}
.cells{display:grid;grid-template-columns:repeat(auto-fit,minmax(158px,1fr));gap:9px;margin-bottom:16px}
.cell{border:1px solid var(--border);border-radius:8px;padding:10px 13px;background:var(--surface);min-width:0}
.cell .k{font-size:10px;text-transform:uppercase;letter-spacing:.09em;color:var(--faint)}
.cell .v{font-family:var(--mono);font-size:14px;margin-top:3px}
table.grid{width:100%;border-collapse:collapse;font-size:12.5px}
table.grid th{text-align:left;color:var(--faint);font-weight:500;font-size:10px;text-transform:uppercase;
  letter-spacing:.07em;padding:7px 10px;border-bottom:1px solid var(--border)}
table.grid td{padding:7px 10px;border-bottom:1px solid var(--surface2);font-family:var(--mono);min-width:0}
table.grid tr:hover td{background:var(--surface)}
.tablewrap{overflow-x:auto}
.secbar{display:grid;grid-template-columns:100px 1fr 58px 38px;gap:9px;align-items:center;
  font-family:var(--mono);font-size:11.5px;padding:3px 0}
.secbar .track{height:10px;background:var(--surface2);border-radius:3px;overflow:hidden;border:1px solid var(--border)}
.secbar .track>div{height:100%}
.implist{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1px 18px}
.implist .imp{font-family:var(--mono);font-size:12px;padding:2px 0;border-bottom:1px solid var(--surface2)}
.list-dot{list-style:none;padding:0;margin:0}
.list-dot li{padding:4px 0 4px 17px;position:relative;font-size:12.5px}
.list-dot li:before{content:'\203A';position:absolute;left:3px;color:var(--teal)}
.checklist{list-style:none;padding:0;margin:0;display:flex;flex-direction:column;gap:5px}
.checklist li{display:flex;gap:10px;align-items:flex-start;padding:9px 12px;background:var(--surface);
  border:1px solid var(--border);border-radius:7px;font-size:12.5px}
.checklist li:before{content:'\25A1';color:var(--teal);font-size:14px;line-height:1.2}
.outrow{display:flex;align-items:center;gap:15px;padding:11px 15px;border:1px solid var(--border);
  border-radius:8px;background:var(--surface);margin-bottom:7px}
.outrow .ext{font-family:var(--mono);color:var(--teal);width:88px;font-weight:600;font-size:12.5px}
.outrow .desc{flex:1;min-width:0;color:var(--muted);font-size:12.5px}
.dlbtn{border:1px solid var(--teal);color:var(--teal);background:var(--teal-bg);border-radius:7px;
  padding:6px 15px;cursor:pointer;font-size:12px;font-family:var(--mono)}
.dlbtn:hover{background:var(--teal);color:var(--bg)}
.logline{font-family:var(--mono);font-size:11.5px;padding:1px 6px;white-space:pre-wrap;word-break:break-all}
.empty{color:var(--faint);padding:26px 0;text-align:center;font-size:12.5px}
h3.sh{font-size:13px;margin:20px 0 9px;font-weight:650}
.pills{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px}
.pill{font-family:var(--mono);font-size:11.5px;border:1px solid var(--border);border-radius:20px;
  padding:3px 11px;background:var(--surface)}
.pill b{color:var(--teal)}

/* ============ idle / scanning / error ============ */
.center{display:none;flex-direction:column;align-items:center;justify-content:center;height:100%;
  text-align:center;gap:15px;padding:40px 20px}
.center.show{display:flex}
#idledrop{border:2px dashed var(--border2);border-radius:16px;padding:52px 60px;cursor:pointer;
  transition:border-color .15s,background .15s;max-width:560px;width:100%;background:var(--surface)}
#idledrop:hover,#idledrop.hover{border-color:var(--teal);background:var(--teal-bg)}
#idledrop .big{font-size:17px;font-weight:600;margin-bottom:6px}
#idledrop .sm{color:var(--muted);font-size:12.5px}
.hintgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(158px,1fr));gap:9px;max-width:560px;width:100%;margin-top:6px}
/* These read as selectable options, so they are real controls, not captions. */
.hintcard{border:1px solid var(--border);border-radius:9px;padding:11px 13px;background:var(--surface);
  text-align:left;cursor:pointer;font:inherit;color:inherit;transition:border-color .12s,background .12s}
.hintcard:hover{border-color:var(--border2)}
.hintcard.sel{border-color:var(--teal);background:var(--teal-bg)}
.hintcard .hk{font-size:11px;color:var(--teal);font-family:var(--mono);margin-bottom:3px}
.hintcard .hv{font-size:11.5px;color:var(--muted);line-height:1.45}
/* Selected-file state for the idle panel. */
#idledrop.armed{border-style:solid;border-color:var(--teal);background:var(--teal-bg)}
#idlego{display:flex;flex-direction:column;align-items:center;gap:9px;margin-top:4px}
#idlerun{padding:12px 30px;border:1px solid var(--green);border-radius:9px;background:var(--green-bg);
  color:var(--green);font-weight:650;cursor:pointer;font-size:14px}
#idlerun:hover{background:var(--green);color:var(--bg)}
.linkish{background:none;border:none;color:var(--muted);cursor:pointer;font-size:12px;text-decoration:underline}
.linkish:hover{color:var(--text)}
.spinner{width:34px;height:34px;border:3px solid var(--border);border-top-color:var(--teal);border-radius:50%;
  animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.spinner{animation-duration:2.4s}}
.progtrack{width:100%;max-width:420px;height:4px;background:var(--surface2);border-radius:3px;overflow:hidden}
.progtrack>div{height:100%;background:var(--teal);width:30%;animation:slide 1.4s ease-in-out infinite}
@keyframes slide{0%{margin-left:-30%}100%{margin-left:100%}}
@media (prefers-reduced-motion:reduce){.progtrack>div{animation:none;width:100%;opacity:.4}}
#scanfile{font-family:var(--mono);color:var(--teal);font-size:14px;word-break:break-all}
#logfeed{font-family:var(--mono);font-size:11px;color:var(--faint);max-width:460px;text-align:left;
  width:100%;max-height:150px;overflow:auto}
#errbox .em{color:var(--red);font-family:var(--mono);max-width:560px;word-break:break-word}

/* history drawer */
#histpop{display:none;position:absolute;top:46px;right:16px;background:var(--surface);border:1px solid var(--border2);
  border-radius:9px;padding:7px;box-shadow:var(--shadow);z-index:40;min-width:270px;max-height:60vh;overflow-y:auto}
#histpop.show{display:block}
.hist{display:flex;justify-content:space-between;align-items:center;gap:11px;padding:8px 10px;border-radius:6px;
  cursor:pointer;background:none;border:none;width:100%;text-align:left}
.hist:hover{background:var(--surface2)}
.hist .hn{font-family:var(--mono);font-size:12px;min-width:0}
.hist .hm{font-size:10.5px;color:var(--faint)}
.hist .hs{font-family:var(--mono);font-weight:700;font-size:13px}

/* keyboard help */
#kbd{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:60;align-items:center;justify-content:center}
#kbd.show{display:flex}
#kbd .sheet{background:var(--surface);border:1px solid var(--border2);border-radius:12px;padding:22px 26px;
  box-shadow:var(--shadow);max-width:440px;width:90%}
#kbd h3{margin:0 0 14px;font-size:15px}
#kbd .row{display:flex;justify-content:space-between;gap:20px;padding:5px 0;font-size:12.5px}
#kbd kbd{font-family:var(--mono);font-size:11px;background:var(--surface2);border:1px solid var(--border2);
  border-bottom-width:2px;border-radius:4px;padding:1px 6px;color:var(--text)}

#toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);background:var(--raise);
  border:1px solid var(--border2);border-radius:8px;padding:9px 17px;font-size:12.5px;box-shadow:var(--shadow);
  opacity:0;pointer-events:none;transition:opacity .2s;z-index:70}
#toast.show{opacity:1}

/* ============ responsive ============ */
@media (max-width:980px){
  .md{grid-template-columns:1fr}
  .detail{position:static;max-height:none}
}
@media (max-width:760px){
  #bar{flex-wrap:wrap;height:auto;padding:9px 12px;gap:9px}
  #verdict{padding:13px 13px 0}
  #stage{padding:14px 13px 30px}
  #tabbar{padding:10px 13px 0}
  .vright{text-align:left}
  #optpop,#histpop{right:10px;left:10px;min-width:0}
}
</style>
</head>
<body>
<div id="app">

  <!-- ============ command bar ============ -->
  <header id="bar">
    <div class="brand"><span class="logo">FlatScan</span><span class="ver" id="verlabel">web</span></div>
    <div class="barsep"></div>

    <div id="target">
      <button id="drop" type="button" aria-describedby="drop-hint">
        <span aria-hidden="true">&#8681;</span><span>drop or choose a file</span>
      </button>
      <span id="drop-hint" class="sr-only">Press Enter or Space to open the file picker. You can also drop a file anywhere on the page.</span>
      <div id="filebox">
        <span class="fn trunc" id="fbname">-</span>
        <span class="meta" id="fbmeta">-</span>
        <button id="clearfile" type="button" title="remove file" aria-label="remove selected file">&times;</button>
      </div>
      <input type="file" id="fileinput" style="display:none" aria-label="file to scan">
    </div>

    <div class="seg" role="radiogroup" aria-label="scan mode">
      <button class="mode-btn" type="button" data-mode="quick" role="radio" aria-checked="false">quick</button>
      <button class="mode-btn active" type="button" data-mode="standard" role="radio" aria-checked="true">standard</button>
      <button class="mode-btn" type="button" data-mode="deep" role="radio" aria-checked="false">deep</button>
    </div>

    <button class="ghost" id="optbtn" type="button" aria-expanded="false" aria-controls="optpop">
      <span>outputs</span><span class="dot" id="optdot"></span>
    </button>

    <button id="run" type="button">Run scan</button>
    <div class="barspace"></div>
    <button class="ghost" id="histbtn" type="button" aria-expanded="false" aria-controls="histpop">history</button>
    <button class="iconbtn" id="themebtn" type="button" title="toggle light / dark" aria-label="toggle light or dark theme">&#9681;</button>
    <button class="iconbtn" id="helpbtn" type="button" title="keyboard shortcuts" aria-label="keyboard shortcuts">?</button>

    <div id="optpop" role="group" aria-label="output options">
      <button class="opt" type="button" data-opt="carve" role="switch" aria-checked="false"><span class="name">--carve</span><span class="state">off</span></button>
      <button class="opt on" type="button" data-opt="yara" role="switch" aria-checked="true"><span class="name">--yara</span><span class="state">on</span></button>
      <button class="opt on" type="button" data-opt="sigma" role="switch" aria-checked="true"><span class="name">--sigma</span><span class="state">on</span></button>
      <button class="opt" type="button" data-opt="stix" role="switch" aria-checked="false"><span class="name">--stix</span><span class="state">off</span></button>
      <button class="opt" type="button" data-opt="report_pack" role="switch" aria-checked="false"><span class="name">--report-pack</span><span class="state">off</span></button>
    </div>
    <div id="histpop" aria-label="scan history"><div class="empty" style="padding:14px 0">no scans yet</div></div>
  </header>

  <!-- ============ verdict header ============ -->
  <section id="verdict" aria-live="polite"></section>

  <!-- ============ workspace ============ -->
  <div id="work">
    <nav id="tabbar" role="tablist" aria-label="analysis sections" style="display:none">
      <button class="tab active" type="button" data-tab="evidence" role="tab" aria-selected="true">evidence <span class="cnt" id="cnt-evidence">0</span><span class="kbd">1</span></button>
      <button class="tab" type="button" data-tab="indicators" role="tab" aria-selected="false">indicators <span class="cnt" id="cnt-indicators">0</span><span class="kbd">2</span></button>
      <button class="tab" type="button" data-tab="config" role="tab" aria-selected="false">config <span class="cnt" id="cnt-config">0</span><span class="kbd">3</span></button>
      <button class="tab" type="button" data-tab="payloads" role="tab" aria-selected="false">payloads <span class="cnt" id="cnt-payloads">0</span><span class="kbd">4</span></button>
      <button class="tab" type="button" data-tab="behavior" role="tab" aria-selected="false">behaviour <span class="cnt" id="cnt-behavior">0</span><span class="kbd">5</span></button>
      <button class="tab" type="button" data-tab="structure" role="tab" aria-selected="false">structure<span class="kbd">6</span></button>
      <button class="tab" type="button" data-tab="report" role="tab" aria-selected="false">report<span class="kbd">7</span></button>
    </nav>

    <div id="stage">
      <!-- The idle panel is stateful: it must acknowledge the chosen file at the
           point the user clicked, not only in the command bar 400px away. -->
      <div id="idle" class="center show">
        <button id="idledrop" type="button">
          <div class="big" id="idlebig">Drop a sample to analyse</div>
          <div class="sm" id="idlesm">or click to browse &middot; nothing leaves this machine</div>
        </button>
        <div class="hintgrid" role="radiogroup" aria-label="scan depth">
          <button class="hintcard" type="button" data-mode="quick" role="radio" aria-checked="false">
            <div class="hk">quick</div><div class="hv">hashes, strings, IOCs. Seconds.</div></button>
          <button class="hintcard sel" type="button" data-mode="standard" role="radio" aria-checked="true">
            <div class="hk">standard</div><div class="hv">adds format parsing, rules, classification.</div></button>
          <button class="hintcard" type="button" data-mode="deep" role="radio" aria-checked="false">
            <div class="hk">deep</div><div class="hv">adds disassembly, carving, recursive payload resolution.</div></button>
        </div>
        <div id="idlego" style="display:none">
          <button id="idlerun" type="button">Analyse sample</button>
          <button id="idleclear" type="button" class="linkish">choose a different file</button>
        </div>
      </div>

      <div id="scanning" class="center">
        <div class="spinner" role="status" aria-label="scanning"></div>
        <div id="scanfile">-</div>
        <div class="progtrack"><div></div></div>
        <div class="muted" id="scanstage">scanning&hellip;</div>
        <div id="logfeed"></div>
      </div>

      <div id="errbox" class="center">
        <div style="font-size:30px" aria-hidden="true">&#9888;</div>
        <div class="em" id="errmsg">-</div>
        <button class="ghost" id="errretry" type="button">try another file</button>
      </div>

      <div id="results" style="display:none">
        <div class="panel active" id="tab-evidence"></div>
        <div class="panel" id="tab-indicators"></div>
        <div class="panel" id="tab-config"></div>
        <div class="panel" id="tab-payloads"></div>
        <div class="panel" id="tab-behavior"></div>
        <div class="panel" id="tab-structure"></div>
        <div class="panel" id="tab-report"></div>
      </div>
    </div>
  </div>
</div>

<div id="kbd" role="dialog" aria-modal="true" aria-label="keyboard shortcuts">
  <div class="sheet">
    <h3>Keyboard</h3>
    <div class="row"><span>Next / previous evidence</span><span><kbd>j</kbd> <kbd>k</kbd></span></div>
    <div class="row"><span>Mark reviewed</span><span><kbd>r</kbd></span></div>
    <div class="row"><span>Mark false positive</span><span><kbd>f</kbd></span></div>
    <div class="row"><span>Mark escalate</span><span><kbd>e</kbd></span></div>
    <div class="row"><span>Search evidence</span><span><kbd>/</kbd></span></div>
    <div class="row"><span>Switch section</span><span><kbd>1</kbd>&hellip;<kbd>7</kbd></span></div>
    <div class="row"><span>Toggle theme</span><span><kbd>t</kbd></span></div>
    <div class="row"><span>Close / clear</span><span><kbd>Esc</kbd></span></div>
    <div class="row"><span>This help</span><span><kbd>?</kbd></span></div>
  </div>
</div>
<div id="toast" role="status" aria-live="polite"></div>

<script>
"use strict";
var state = {
  file:null, mode:"standard",
  opts:{carve:false,yara:true,sigma:true,stix:false,report_pack:false},
  currentId:null, pollTimer:null, jobs:{}, history:[],
  result:null,
  evidence:[],        // normalised finding list for the workspace
  filter:{q:"",sev:"",cat:"",tri:""},
  selected:0,
  triage:{},          // findingKey -> reviewed|fp|escalate
  defang:true,
  showRaw:false       // reveal the pre-cap score when the FP guard fired
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
function hex(n){ var v=Number(n); if(!isFinite(v)||v<0) v=0; return "0x"+Math.floor(v).toString(16).toUpperCase(); }
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
function toast(msg){
  var t=$("#toast"); t.textContent=msg; t.classList.add("show");
  clearTimeout(t._t); t._t=setTimeout(function(){t.classList.remove("show");},1700);
}
/* Defanging keeps live C2 out of the clipboard and out of accidental clicks. */
function defang(v){
  if(!state.defang) return String(v);
  return String(v).replace(/^http:/i,"hxxp:").replace(/^https:/i,"hxxps:").replace(/\./g,"[.]");
}
/* Categorical colour is assigned from a fixed table so a category always draws
   the same hue — colour follows the entity, never its rank or its position in
   this particular sample. Anything outside the table folds into a neutral
   "other" slot rather than being handed a generated hue. */
var CAT_SLOT={
  "Behavior":1,"Evasion":2,"Persistence":3,"Credential Access":4,
  "Network":5,"Execution":6,"Packing":7,"Obfuscation":8,
  // Aliases that share a slot with their canonical category.
  "Defense Evasion":2,"Credential Theft":4,"Script":6,"Payload":7
};
function catColor(name){
  var slot=CAT_SLOT[name];
  return slot?("var(--s"+slot+")"):"var(--sother)";
}
/* Sequential ramp lookup for entropy: 0..8 mapped onto seven ordered steps.
   One hue, monotonic lightness — a magnitude encoding, not a status one. */
function entropyColor(e){
  var v=num(e); if(v<0) v=0; if(v>8) v=8;
  var i=Math.min(6,Math.floor((v/8)*7));
  return "var(--e"+i+")";
}

/* ---------- theme ---------- */
function applyTheme(t){
  document.documentElement.setAttribute("data-theme",t);
  try{ localStorage.setItem("flatscan_theme",t); }catch(e){}
}
function toggleTheme(){
  var cur=document.documentElement.getAttribute("data-theme")||"dark";
  applyTheme(cur==="dark"?"light":"dark");
}
(function(){
  var saved=null;
  try{ saved=localStorage.getItem("flatscan_theme"); }catch(e){}
  applyTheme(saved||"dark");
})();
$("#themebtn").addEventListener("click",toggleTheme);

/* ---------- copy delegation ---------- */
document.addEventListener("click",function(e){
  var b=e.target.closest?e.target.closest(".copy"):null;
  if(!b) return;
  navigator.clipboard.writeText(b.getAttribute("data-v")||"").catch(function(){});
  var prev=b.innerHTML; b.textContent="✓";
  setTimeout(function(){b.innerHTML=prev;},1100);
});

/* ---------- popovers ---------- */
function closePops(){
  $("#optpop").classList.remove("show"); $("#optbtn").setAttribute("aria-expanded","false");
  $("#histpop").classList.remove("show"); $("#histbtn").setAttribute("aria-expanded","false");
}
$("#optbtn").addEventListener("click",function(e){
  e.stopPropagation();
  var on=$("#optpop").classList.contains("show");
  closePops();
  if(!on){ $("#optpop").classList.add("show"); $("#optbtn").setAttribute("aria-expanded","true"); }
});
$("#histbtn").addEventListener("click",function(e){
  e.stopPropagation();
  var on=$("#histpop").classList.contains("show");
  closePops();
  if(!on){ $("#histpop").classList.add("show"); $("#histbtn").setAttribute("aria-expanded","true"); }
});
document.addEventListener("click",function(e){
  if(!e.target.closest) return;
  if(!e.target.closest("#optpop") && !e.target.closest("#optbtn") &&
     !e.target.closest("#histpop") && !e.target.closest("#histbtn")) closePops();
});

/* ---------- file handling ---------- */
var fileinput=$("#fileinput"), filebox=$("#filebox");
function pick(){ fileinput.click(); }
$("#drop").addEventListener("click",pick);
$("#idledrop").addEventListener("click",pick);
fileinput.addEventListener("change",function(){ if(fileinput.files[0]) setFile(fileinput.files[0]); });
/* Drop anywhere: the whole window is the target, not a 60px box. */
["dragenter","dragover"].forEach(function(ev){
  window.addEventListener(ev,function(e){ e.preventDefault(); $("#drop").classList.add("hover"); $("#idledrop").classList.add("hover"); });
});
["dragleave","drop"].forEach(function(ev){
  window.addEventListener(ev,function(e){ e.preventDefault(); $("#drop").classList.remove("hover"); $("#idledrop").classList.remove("hover"); });
});
window.addEventListener("drop",function(e){
  if(e.dataTransfer&&e.dataTransfer.files&&e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
});
$("#clearfile").addEventListener("click",function(e){e.stopPropagation();clearFile();});
$("#errretry").addEventListener("click",function(){ clearFile(); showView("idle"); });
function setFile(f){
  state.file=f;
  $("#fbname").textContent=f.name;
  $("#fbname").title=f.name;
  $("#fbmeta").textContent=fmtBytes(f.size);
  filebox.classList.add("show");
  $("#drop").style.display="none";
  renderIdle();
}
function clearFile(){
  state.file=null; fileinput.value="";
  filebox.classList.remove("show");
  $("#drop").style.display="";
  renderIdle();
}
/* renderIdle keeps the idle panel in sync with the selection. Without it the
   only acknowledgement of a chosen file was a chip in the command bar, far from
   where the user clicked — so picking a file looked like nothing had happened. */
function renderIdle(){
  var f=state.file;
  var drop=$("#idledrop"), go=$("#idlego");
  if(!drop||!go) return;
  if(f){
    drop.classList.add("armed");
    $("#idlebig").textContent=f.name;
    $("#idlesm").textContent=fmtBytes(f.size)+" · "+(f.type||"unknown type")+" · ready to analyse";
    $("#idlerun").textContent="Analyse in "+state.mode+" mode";
    go.style.display="flex";
  } else {
    drop.classList.remove("armed");
    $("#idlebig").textContent="Drop a sample to analyse";
    $("#idlesm").innerHTML="or click to browse &middot; nothing leaves this machine";
    go.style.display="none";
  }
  $all(".hintcard").forEach(function(c){
    var on=c.getAttribute("data-mode")===state.mode;
    c.classList.toggle("sel",on);
    c.setAttribute("aria-checked",on?"true":"false");
  });
}

/* ---------- mode + options ---------- */
function setMode(m){
  state.mode=m;
  $all(".mode-btn").forEach(function(b){
    var on=b.getAttribute("data-mode")===m;
    b.classList.toggle("active",on);
    b.setAttribute("aria-checked",on?"true":"false");
  });
  renderIdle();
}
$all(".mode-btn").forEach(function(btn){
  btn.addEventListener("click",function(){ setMode(btn.getAttribute("data-mode")); });
});
/* The depth cards on the idle screen look like options, so they behave like
   options — previously they were inert captions that silently ignored clicks. */
$all(".hintcard").forEach(function(card){
  card.addEventListener("click",function(){ setMode(card.getAttribute("data-mode")); });
});
$all(".opt").forEach(function(row){
  row.addEventListener("click",function(e){
    e.stopPropagation();
    var k=row.getAttribute("data-opt");
    state.opts[k]=!state.opts[k];
    row.classList.toggle("on",state.opts[k]);
    row.setAttribute("aria-checked",state.opts[k]?"true":"false");
    row.querySelector(".state").textContent=state.opts[k]?"on":"off";
    var n=Object.keys(state.opts).filter(function(x){return state.opts[x];}).length;
    $("#optdot").style.background=n?"var(--teal)":"var(--border2)";
  });
});

/* ---------- views ---------- */
function showView(which){
  $("#idle").classList.toggle("show",which==="idle");
  $("#scanning").classList.toggle("show",which==="scanning");
  $("#errbox").classList.toggle("show",which==="error");
  $("#results").style.display=(which==="results")?"block":"none";
  $("#verdict").classList.toggle("show",which==="results");
  $("#tabbar").style.display=(which==="results")?"flex":"none";
}
function selectTab(name){
  $all(".tab").forEach(function(x){
    var on=x.getAttribute("data-tab")===name;
    x.classList.toggle("active",on); x.setAttribute("aria-selected",on?"true":"false");
  });
  $all(".panel").forEach(function(p){p.classList.remove("active");});
  var p=$("#tab-"+name); if(p) p.classList.add("active");
  state.tab=name;
}
$all(".tab").forEach(function(t){
  t.addEventListener("click",function(){ selectTab(t.getAttribute("data-tab")); });
});

/* ---------- run scan ---------- */
function startScan(){
  if(!state.file){
    $("#drop").classList.add("error");
    $("#idledrop").classList.add("hover");
    toast("choose a file first");
    setTimeout(function(){$("#drop").classList.remove("error");$("#idledrop").classList.remove("hover");},800);
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
  }).catch(function(e){ showError(String(e&&e.message?e.message:e)); setRun(false,"Run scan"); });
}
$("#run").addEventListener("click",startScan);
$("#idlerun").addEventListener("click",startScan);
$("#idleclear").addEventListener("click",function(e){ e.stopPropagation(); clearFile(); });
function setRun(disabled,label){ var b=$("#run"); b.disabled=disabled; if(label) b.textContent=label; }
function logFeed(msg){
  var d=document.createElement("div");
  d.textContent="["+new Date().toLocaleTimeString()+"] "+msg;
  var f=$("#logfeed"); f.appendChild(d); f.scrollTop=f.scrollHeight;
}
function poll(id){
  fetch("/api/result/"+id).then(function(r){
    return r.json().then(function(j){return {code:r.status,body:j};});
  }).then(function(res){
    if(state.currentId!==id) return;
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
  loadResult(res);
  addHistory(id,res);
  setRun(false,"Scan again");
}

/* ---------- triage persistence ---------- */
function triageKey(r){ return "flatscan_triage_"+((r.hashes&&r.hashes.sha256)||r.file_name||"sample"); }
function loadTriage(r){
  try{ state.triage=JSON.parse(localStorage.getItem(triageKey(r))||"{}")||{}; }
  catch(e){ state.triage={}; }
}
function saveTriage(){
  if(!state.result) return;
  try{ localStorage.setItem(triageKey(state.result),JSON.stringify(state.triage)); }catch(e){}
}
function evKey(x){ return (x.title||"")+" |#| "+(x.evidence||""); }
function setTriage(idx,status){
  var ev=visibleEvidence()[idx]; if(!ev) return;
  var k=evKey(ev);
  if(state.triage[k]===status) delete state.triage[k]; else state.triage[k]=status;
  saveTriage();
  renderEvidence();
  renderVerdict(state.result);
}

/* ---------- result load ---------- */
function loadResult(r){
  state.result=r;
  state.filter={q:"",sev:"",cat:"",tri:""};
  state.selected=0;
  state.showRaw=false;
  loadTriage(r);
  state.evidence=(r.findings||[]).slice().sort(function(a,b){
    var d=sevRank(b.severity)-sevRank(a.severity);
    return d!==0?d:(num(b.score)-num(a.score));
  });
  renderVerdict(r);
  renderEvidence();
  renderIndicators(r);
  renderConfig(r);
  renderPayloads(r);
  renderBehavior(r);
  renderStructure(r);
  renderReport(r);
  $("#cnt-evidence").textContent=state.evidence.length;
  $("#cnt-indicators").textContent=iocTotal(r);
  $("#cnt-config").textContent=configCount(r);
  $("#cnt-payloads").textContent=(r.payload_tree||[]).length+(r.carved_artifacts||[]).length;
  $("#cnt-behavior").textContent=((r.profile&&r.profile.expected_behavior)||[]).length;
  showView("results");
  selectTab("evidence");
}
function iocTotal(r){
  var i=r.iocs||{}, n=0;
  Object.keys(i).forEach(function(k){ if(Array.isArray(i[k])) n+=i[k].length; });
  return n;
}

/* ---------- verdict header with score provenance ---------- */
function renderVerdict(r){
  var score=num(r.risk_score), h=r.hashes||{};
  var bd=r.score_breakdown||{};
  var keys=Object.keys(bd).sort(function(a,b){return num(bd[b])-num(bd[a]);});
  var total=keys.reduce(function(s,k){return s+num(bd[k]);},0)||1;

  /* When the false-positive guard capped the score, showRaw lets the analyst
     see the number the detection engine actually produced. Both are shown so
     the cap is never silently believed in either direction. */
  var capped=r.benign_context&&num(r.benign_context.original_score)>score;
  var shown=(capped&&state.showRaw)?num(r.benign_context.original_score):score;

  var html="<div class=\"vtop\">";
  if(capped&&state.showRaw){
    html+="<div class=\"vscore raw\" style=\"color:var(--muted)\">"+score+"</div>";
  }
  html+="<div class=\"vscore\" style=\"color:"+scoreColor(shown)+"\">"+shown+"</div>";
  html+="<div class=\"vmain\">";
  html+="<div class=\"vlabel\" style=\"color:"+scoreColor(score)+"\">"+esc(r.verdict||"unknown")+"</div>";
  html+="<div class=\"vsub\"><b>"+esc(r.file_type||"unknown type")+"</b>"+
        (r.mime_hint?(" · "+esc(r.mime_hint)):"")+
        " · entropy "+num(r.entropy).toFixed(2)+"/8.00"+
        " · "+num(r.strings_total)+" strings</div>";
  html+="</div>";
  html+="<div class=\"vright\"><b>"+esc(r.file_name||"")+"</b><br>"+
        fmtBytes(r.size)+" · "+esc(r.mode||"")+" mode · "+esc(r.duration||"")+"<br>"+
        "<span class=\"mono\">"+esc((h.sha256||"").slice(0,24))+"…</span>"+cp(h.sha256||"")+"</div>";
  html+="</div>";

  /* Score provenance: which categories built this number, click to filter.
     Membership is by contribution — the top seven get their own segment and
     the tail aggregates into "other" — but the hue of each survivor comes from
     the fixed category table, so filtering never repaints anything. */
  if(keys.length){
    var MAXSEG=7;
    var segs=keys.slice(0,MAXSEG).map(function(k){ return {name:k,val:num(bd[k]),real:true}; });
    var tail=keys.slice(MAXSEG);
    if(tail.length){
      segs.push({name:"other",val:tail.reduce(function(s,k){return s+num(bd[k]);},0),
                 real:false,members:tail});
    }
    html+="<div class=\"prov\"><div class=\"provbar\" role=\"group\" aria-label=\"score contribution by category\">";
    segs.forEach(function(sg){
      var pct=(sg.val/total)*100;
      var active=state.filter.cat===sg.name;
      var dim=state.filter.cat&&!active?" dim":"";
      var label=sg.real?sg.name:("other ("+sg.members.join(", ")+")");
      html+="<button type=\"button\" class=\"provseg"+dim+"\""+(sg.real?(" data-cat=\""+esc(sg.name)+"\""):"")+" "+
        "style=\"width:"+pct.toFixed(2)+"%;background:"+catColor(sg.name)+"\" "+
        "title=\""+esc(label)+": "+sg.val+" points\" aria-label=\""+esc(label)+" "+sg.val+" points\"></button>";
    });
    html+="</div><div class=\"provkeys\">";
    segs.forEach(function(sg){
      var label=sg.real?sg.name:("other ×"+sg.members.length);
      html+="<button type=\"button\" class=\"provkey"+(state.filter.cat===sg.name?" active":"")+"\""+
        (sg.real?(" data-cat=\""+esc(sg.name)+"\""):" style=\"cursor:default\" title=\""+esc(sg.members.join(", "))+"\"")+">"+
        "<span class=\"sw\" style=\"background:"+catColor(sg.name)+"\"></span>"+esc(label)+" <b>"+sg.val+"</b></button>";
    });
    var done=Object.keys(state.triage).length;
    if(done) html+="<span class=\"provkey\" style=\"cursor:default;border-style:dashed\">"+done+" triaged</span>";
    html+="</div></div>";
  }

  /* benign_context: explain a capped score instead of silently showing it. */
  if(r.benign_context){
    var bc=r.benign_context;
    html+="<div class=\"banner\"><div style=\"flex:1\"><div class=\"bt\">False-positive guard applied — score capped at "+
      num(bc.score_cap)+", detection engine produced "+num(bc.original_score)+
      "<button type=\"button\" class=\"rawtoggle"+(state.showRaw?" on":"")+"\" id=\"rawbtn\">"+
      (state.showRaw?"showing raw":"show raw")+"</button></div><div class=\"muted\">"+esc(bc.reason||"")+
      (bc.archetypes&&bc.archetypes.length?(" · archetypes: "+esc(bc.archetypes.join(", "))):"")+
      (bc.tool_markers&&bc.tool_markers.length?(" · markers: "+esc(bc.tool_markers.slice(0,6).join(", "))):"")+
      (bc.mitre_technique_refs?(" · "+num(bc.mitre_technique_refs)+" ATT&amp;CK references catalogued as data"):"")+
      "</div><div class=\"faint\" style=\"font-size:11.5px;margin-top:5px\">"+
      "If this is a genuine multi-purpose sample rather than a rule pack or report, the cap is hiding a real verdict — "+
      "check the raw score and the evidence below.</div></div></div>";
  }
  if(r.truncated_analysis){
    html+="<div class=\"banner warn\"><div><div class=\"bt\">Partial coverage</div>"+
      "<div class=\"muted\">Only "+fmtBytes(r.analyzed_bytes)+" of "+fmtBytes(r.size)+
      " was analysed. Findings below the cut-off will not appear.</div></div></div>";
  }
  html+="<div style=\"height:14px\"></div>";
  $("#verdict").innerHTML=html;

  $all("#verdict .provseg[data-cat],#verdict .provkey[data-cat]").forEach(function(b){
    b.addEventListener("click",function(){
      var c=b.getAttribute("data-cat");
      state.filter.cat=(state.filter.cat===c)?"":c;
      state.selected=0;
      renderVerdict(state.result); renderEvidence(); selectTab("evidence");
    });
  });
  var rb=$("#rawbtn");
  if(rb) rb.addEventListener("click",function(){
    state.showRaw=!state.showRaw;
    renderVerdict(state.result);
    toast(state.showRaw?"showing the uncapped detection score":"showing the capped score");
  });
}

/* ---------- evidence workspace (master + detail) ---------- */
function visibleEvidence(){
  var q=state.filter.q.toLowerCase();
  return state.evidence.filter(function(x){
    if(state.filter.sev){
      var s=String(x.severity||"").toLowerCase();
      if(state.filter.sev==="high" && !(s==="high"||s==="critical")) return false;
      if(state.filter.sev!=="high" && s!==state.filter.sev) return false;
    }
    if(state.filter.cat && x.category!==state.filter.cat) return false;
    if(state.filter.tri){
      var t=state.triage[evKey(x)]||"";
      if(state.filter.tri==="untriaged"?t!=="":t!==state.filter.tri) return false;
    }
    if(q){
      var hay=((x.title||"")+" "+(x.evidence||"")+" "+(x.technique||"")+" "+(x.tactic||"")+" "+(x.category||"")).toLowerCase();
      if(hay.indexOf(q)<0) return false;
    }
    return true;
  });
}
function renderEvidence(){
  var all=state.evidence;
  if(!all.length){ $("#tab-evidence").innerHTML="<div class=\"empty\">No findings. The scanner completed without raising anything.</div>"; return; }
  var list=visibleEvidence();
  if(state.selected>=list.length) state.selected=Math.max(0,list.length-1);

  var counts={high:0,medium:0,low:0};
  all.forEach(function(x){
    var s=String(x.severity||"").toLowerCase();
    if(s==="high"||s==="critical") counts.high++;
    else if(s==="medium") counts.medium++;
    else counts.low++;
  });
  var triCount={reviewed:0,fp:0,escalate:0,untriaged:0};
  all.forEach(function(x){ var t=state.triage[evKey(x)]||"untriaged"; triCount[t]=(triCount[t]||0)+1; });

  var html="<div class=\"toolrow\">";
  html+="<input class=\"search\" id=\"evsearch\" type=\"search\" placeholder=\"filter evidence — title, technique, string…\" value=\""+esc(state.filter.q)+"\" aria-label=\"filter evidence\">";
  html+=chip("sev","","all",all.length);
  html+=chip("sev","high","high",counts.high);
  html+=chip("sev","medium","medium",counts.medium);
  html+=chip("sev","low","low",counts.low);
  html+="<span style=\"width:8px\"></span>";
  html+=chip("tri","untriaged","untriaged",triCount.untriaged);
  html+=chip("tri","escalate","escalated",triCount.escalate);
  html+=chip("tri","reviewed","reviewed",triCount.reviewed);
  html+=chip("tri","fp","false pos",triCount.fp);
  html+="</div>";

  if(state.filter.cat){
    html+="<div class=\"muted\" style=\"font-size:12px;margin-bottom:9px\">filtered to category <b style=\"color:var(--teal)\">"+
      esc(state.filter.cat)+"</b> — <button class=\"copy\" id=\"clearcat\" style=\"color:var(--teal)\">clear</button></div>";
  }

  html+="<div class=\"md\"><div class=\"mdlist\" id=\"evlist\" role=\"listbox\" aria-label=\"evidence\">";
  if(!list.length){
    html+="<div class=\"empty\">Nothing matches this filter.</div>";
  }
  list.forEach(function(x,i){
    var sc=sevColor(x.severity);
    var t=state.triage[evKey(x)]||"";
    html+="<button type=\"button\" class=\"ev"+(i===state.selected?" sel":"")+(t==="fp"?" done":"")+"\" data-i=\""+i+"\" role=\"option\" aria-selected=\""+(i===state.selected)+"\">"+
      "<span class=\"stripe\" style=\"background:"+sc+"\"></span>"+
      "<span class=\"evbody\"><span class=\"evtitle\">"+esc(x.title||"finding")+"</span>"+
      "<span class=\"evmeta\">"+
        "<span class=\"tag sev\" style=\"color:"+sc+";border-color:"+sc+"\">"+esc(x.severity||"")+"</span>"+
        (x.category?("<span class=\"tag\">"+esc(x.category)+"</span>"):"")+
        (x.technique?("<span class=\"tag\">"+esc(x.technique)+"</span>"):"")+
        (num(x.evidence_count)>1?("<span class=\"tag\" style=\"color:var(--teal);border-color:var(--teal)\">"+num(x.evidence_count)+"× corroborated</span>"):"")+
        (t?("<span class=\"tri "+t+"\">"+(t==="fp"?"false pos":t)+"</span>"):"")+
      "</span></span>"+
      "<span class=\"evright\"><span class=\"badge\" style=\"color:"+sc+";border-color:"+sc+"\">"+num(x.score)+"</span>"+
        (num(x.confidence)?("<span class=\"faint mono\" style=\"font-size:10px\">"+num(x.confidence)+"% conf</span>"):"")+
      "</span></button>";
  });
  html+="</div><div id=\"evdetail\"></div></div>";

  $("#tab-evidence").innerHTML=html;
  renderDetail(list[state.selected]);

  var s=$("#evsearch");
  if(s){
    s.addEventListener("input",function(){
      state.filter.q=s.value; state.selected=0;
      var pos=s.selectionStart;
      renderEvidence();
      var ns=$("#evsearch"); if(ns){ ns.focus(); try{ns.setSelectionRange(pos,pos);}catch(e){} }
    });
  }
  var cc=$("#clearcat");
  if(cc) cc.addEventListener("click",function(){ state.filter.cat=""; renderVerdict(state.result); renderEvidence(); });
  $all("#tab-evidence .chip").forEach(function(c){
    c.addEventListener("click",function(){
      var k=c.getAttribute("data-k"), v=c.getAttribute("data-v");
      state.filter[k]=(state.filter[k]===v)?"":v;
      state.selected=0; renderEvidence();
    });
  });
  $all("#evlist .ev").forEach(function(row){
    row.addEventListener("click",function(){
      state.selected=num(row.getAttribute("data-i"));
      renderEvidence();
    });
  });
}
function chip(kind,val,label,n){
  var active=state.filter[kind]===val;
  return "<button type=\"button\" class=\"chip"+(active?" active":"")+"\" data-k=\""+kind+"\" data-v=\""+esc(val)+"\">"+
    esc(label)+"<span class=\"n\">"+n+"</span></button>";
}
function renderDetail(x){
  var el=$("#evdetail"); if(!el) return;
  if(!x){ el.innerHTML="<div class=\"detail\"><div class=\"empty\">Select a finding to see its evidence.</div></div>"; return; }
  var sc=sevColor(x.severity);
  var t=state.triage[evKey(x)]||"";
  var h="<div class=\"detail\">";
  h+="<h3>"+esc(x.title||"finding")+"</h3>";
  h+="<div class=\"dmeta\">"+
    "<span class=\"tag sev\" style=\"color:"+sc+";border-color:"+sc+"\">"+esc(x.severity||"")+"</span>"+
    "<span class=\"badge\" style=\"color:"+sc+";border-color:"+sc+"\">"+num(x.score)+" pts</span>"+
    (x.category?("<span class=\"tag\">"+esc(x.category)+"</span>"):"")+
    (num(x.confidence)?("<span class=\"tag\">"+num(x.confidence)+"% confidence</span>"):"")+
    (num(x.evidence_count)>1?("<span class=\"tag\" style=\"color:var(--teal);border-color:var(--teal)\">"+num(x.evidence_count)+" evidence groups</span>"):"")+
    "</div>";
  if(x.evidence) h+="<div class=\"dsec\"><div class=\"dl\">evidence</div><div class=\"dv mono\">"+esc(x.evidence)+"</div></div>";
  if(x.tactic||x.technique){
    h+="<div class=\"dsec\"><div class=\"dl\">ATT&amp;CK</div><div class=\"dv\">"+
      esc(x.tactic||"")+(x.tactic&&x.technique?" → ":"")+esc(x.technique||"")+"</div></div>";
  }
  if(num(x.offset)) h+="<div class=\"dsec\"><div class=\"dl\">offset</div><div class=\"dv mono\">"+hex(x.offset)+"</div></div>";
  if(x.recommendation) h+="<div class=\"dsec\"><div class=\"dl\">what to do</div><div class=\"dv\">"+esc(x.recommendation)+"</div></div>";
  h+="<div class=\"triage\">"+
    tbtn("reviewed","reviewed","r",t)+tbtn("escalate","escalate","e",t)+tbtn("fp","false positive","f",t)+
    "</div>";
  h+="</div>";
  el.innerHTML=h;
  $all("#evdetail .tbtn").forEach(function(b){
    b.addEventListener("click",function(){ setTriage(state.selected,b.getAttribute("data-s")); });
  });
}
function tbtn(status,label,key,cur){
  return "<button type=\"button\" class=\"tbtn"+(cur===status?" on":"")+"\" data-s=\""+status+"\">"+
    esc(label)+"<span class=\"k\">"+key+"</span></button>";
}

/* ---------- indicators ---------- */
function renderIndicators(r){
  var iocs=r.iocs||{};
  var cats=[
    ["domains","domains"],["urls","urls"],["ipv4","ipv4"],["ipv6","ipv6"],["emails","emails"],
    ["md5","md5"],["sha1","sha1"],["sha256","sha256"],["registry_keys","registry keys"],
    ["windows_paths","windows paths"],["unix_paths","unix paths"],["mutexes","mutexes"],
    ["named_pipes","named pipes"],["crypto_wallets","crypto wallets"],["cves","cves"]
  ];
  var present=cats.filter(function(c){ return iocs[c[0]]&&iocs[c[0]].length; });
  var sup=num(iocs.suppressed_count);
  if(!present.length){
    $("#tab-indicators").innerHTML="<div class=\"empty\">No indicators extracted."+
      (sup>0?(" "+sup+" suppressed by the allowlist."):"")+"</div>";
    return;
  }
  var networky={domains:1,urls:1,ipv4:1,ipv6:1,emails:1};
  var html="<div class=\"toolrow\">";
  html+="<button type=\"button\" class=\"chip"+(state.defang?" active":"")+"\" id=\"defangbtn\" "+
    "title=\"render network indicators inert so they cannot be clicked or pasted live\">defanged</button>";
  html+="<button type=\"button\" class=\"chip\" id=\"selall\">select all</button>";
  html+="<button type=\"button\" class=\"chip\" id=\"copysel\">copy selected</button>";
  html+="<button type=\"button\" class=\"chip\" id=\"exportsel\">download .txt</button>";
  html+="<span class=\"muted\" style=\"font-size:12px\" id=\"selcount\">0 selected</span>";
  html+="</div>";

  present.forEach(function(c){
    var key=c[0], vals=iocs[key];
    var body="<div class=\"iocgrid\">";
    vals.forEach(function(v){
      var shown=networky[key]?defang(v):String(v);
      body+="<label class=\"iocrow\"><input type=\"checkbox\" class=\"iocck\" data-v=\""+esc(v)+"\">"+
        "<span class=\"val\">"+esc(shown)+"</span>"+
        "<span style=\"display:flex;align-items:center;gap:4px\"><span class=\"src\">"+esc(c[1])+"</span>"+cp(v)+"</span></label>";
    });
    body+="</div>";
    html+="<details class=\"box\" open><summary><span>"+esc(c[1])+"</span><span class=\"chev\">›</span></summary>"+
      "<div class=\"body\">"+body+"</div></details>";
  });
  /* The allowlist is the second half of the false-positive guard. Suppressed
     indicators stay in the result, so show them on demand rather than making
     the analyst re-run: an attacker abusing a legitimate CDN or PKI host is
     exactly the case the allowlist would quietly swallow. */
  var log=iocs.suppression_log||[];
  if(sup>0||log.length){
    html+="<details class=\"box\"><summary><span>suppressed by the false-positive guard — "+
      sup+" occurrence(s), "+log.length+" distinct</span><span class=\"chev\">›</span></summary><div class=\"body\">";
    if(iocs.suppression_reason) html+="<div class=\"muted\" style=\"font-size:12px;margin-bottom:9px\">"+esc(iocs.suppression_reason)+"</div>";
    if(log.length){
      html+="<div class=\"iocgrid\">";
      log.forEach(function(s){
        var shown=networky[s.type]?defang(s.value):String(s.value||"");
        html+="<div class=\"suprow\"><span class=\"sk\">"+esc(s.type||"")+"</span>"+
          "<span class=\"val\">"+esc(shown)+"</span>"+
          "<span style=\"display:flex;align-items:center;gap:5px\"><span class=\"sr\">"+esc(s.reason||"")+"</span>"+cp(s.value||"")+"</span></div>";
      });
      html+="</div>";
    } else {
      html+="<div class=\"muted\" style=\"font-size:12px\">The count is recorded but no per-indicator detail was captured for this scan.</div>";
    }
    html+="</div></details>";
  }
  $("#tab-indicators").innerHTML=html;

  function selected(){
    return $all("#tab-indicators .iocck").filter(function(c){return c.checked;})
      .map(function(c){return c.getAttribute("data-v");});
  }
  function updateCount(){ $("#selcount").textContent=selected().length+" selected"; }
  $all("#tab-indicators .iocck").forEach(function(c){ c.addEventListener("change",updateCount); });
  $("#defangbtn").addEventListener("click",function(){ state.defang=!state.defang; renderIndicators(r); });
  $("#selall").addEventListener("click",function(){
    var boxes=$all("#tab-indicators .iocck");
    var allOn=boxes.every(function(c){return c.checked;});
    boxes.forEach(function(c){c.checked=!allOn;});
    updateCount();
  });
  $("#copysel").addEventListener("click",function(){
    var s=selected(); if(!s.length){ toast("nothing selected"); return; }
    navigator.clipboard.writeText(s.join("\n")).catch(function(){});
    toast(s.length+" indicator(s) copied");
  });
  $("#exportsel").addEventListener("click",function(){
    var s=selected(); if(!s.length){ toast("nothing selected"); return; }
    var blob=new Blob([s.join("\n")+"\n"],{type:"text/plain"});
    var a=document.createElement("a");
    a.href=URL.createObjectURL(blob);
    a.download=(r.file_name||"sample")+".selected-iocs.txt";
    a.click();
    setTimeout(function(){URL.revokeObjectURL(a.href);},1000);
  });
}

/* ---------- config: recovered operator intelligence ----------
   ExtractMalwareConfig recovers the operator-controlled side of a sample — C2
   endpoints, mutexes, bot tokens, webhooks, campaign and build identifiers.
   That is the highest-value pivot material in the whole result and it had no
   representation in the UI at all. config_artifacts and the crypto summary sit
   alongside it because they answer the same question: what was this built to
   talk to, and how does it protect that. */
function configCount(r){
  var c=r.malware_config||{}, n=0;
  ["c2","mutexes","bot_tokens","webhooks","wallets","campaign_id","build_id","version"].forEach(function(k){
    if(Array.isArray(c[k])) n+=c[k].length;
  });
  n+=(r.config_artifacts||[]).length;
  var cc=r.crypto_config||{};
  ["crypto_markers","candidate_xor_keys"].forEach(function(k){ if(Array.isArray(cc[k])) n+=cc[k].length; });
  return n;
}
function renderConfig(r){
  var c=r.malware_config||{}, arts=r.config_artifacts||[], cc=r.crypto_config||{};
  var html="";
  var rows=[
    ["c2","C2 endpoint",true],
    ["webhooks","webhook",true],
    ["bot_tokens","bot token",false],
    ["mutexes","mutex",false],
    ["wallets","wallet",false],
    ["campaign_id","campaign id",false],
    ["build_id","build id",false],
    ["version","version",false]
  ];
  var any=rows.some(function(x){ return c[x[0]]&&c[x[0]].length; });
  if(any||c.family){
    html+="<h3 class=\"sh\" style=\"margin-top:0\">Recovered configuration"+
      (c.family?(" <span class=\"muted\" style=\"font-weight:400\">— "+esc(c.family)+"</span>"):"")+"</h3>";
    html+="<div class=\"cfggrid\">";
    rows.forEach(function(x){
      var key=x[0], label=x[1], hot=x[2];
      (c[key]||[]).forEach(function(v){
        var shown=(key==="c2"||key==="webhooks")?defang(v):String(v);
        html+="<div class=\"cfgrow"+(hot?" hot":"")+"\"><span class=\"ck\">"+esc(label)+"</span>"+
          "<span class=\"cv\">"+esc(shown)+"</span>"+cp(v)+"</div>";
      });
    });
    html+="</div>";
  }

  if((cc.crypto_markers&&cc.crypto_markers.length)||(cc.candidate_xor_keys&&cc.candidate_xor_keys.length)){
    html+="<h3 class=\"sh\">Obfuscation and crypto</h3><div class=\"cfggrid\">";
    (cc.crypto_markers||[]).forEach(function(v){
      html+="<div class=\"cfgrow\"><span class=\"ck\">crypto marker</span><span class=\"cv\">"+esc(v)+"</span>"+cp(v)+"</div>";
    });
    (cc.candidate_xor_keys||[]).forEach(function(v){
      html+="<div class=\"cfgrow\"><span class=\"ck\">xor key candidate</span><span class=\"cv\">"+esc(v)+"</span>"+cp(v)+"</div>";
    });
    html+="</div>";
  }

  if(arts.length){
    html+="<h3 class=\"sh\">Config artifacts ("+arts.length+")</h3>";
    arts.forEach(function(a){
      html+="<div style=\"border-bottom:1px solid var(--surface2);padding:9px 0\">"+
        "<div><b>"+esc(a.type||"config")+"</b> <span class=\"muted\">"+esc(a.source||"")+
        (a.confidence?(" · "+esc(a.confidence)):"")+"</span></div>"+
        (a.evidence?("<div class=\"mono\" style=\"font-size:11.5px\">"+esc(a.evidence)+"</div>"):"")+
        (a.preview?("<div class=\"mono faint\" style=\"font-size:11px\">"+esc(a.preview)+"</div>"):"")+"</div>";
    });
  }

  var im=r.intel_matches||r.enrichment||[];
  if(im.length){
    html+="<h3 class=\"sh\">Threat-intel matches ("+im.length+")</h3><div class=\"cfggrid\">";
    im.forEach(function(m){
      html+="<div class=\"cfgrow hot\"><span class=\"ck\">"+esc(m.type||m.indicator||"match")+"</span>"+
        "<span class=\"cv\">"+esc(m.value||m.indicator||"")+"</span>"+
        "<span class=\"tag\">"+esc(m.label||m.source||"")+"</span></div>";
    });
    html+="</div>";
  }

  if(!html) html="<div class=\"empty\">No operator configuration recovered. "+
    "Config extraction looks for C2 endpoints, mutexes, tokens and campaign markers in the decoded string set.</div>";
  $("#tab-config").innerHTML=html;
}

/* ---------- payloads: the recursive resolution tree ---------- */
function renderPayloads(r){
  var tree=r.payload_tree||[], carved=r.carved_artifacts||[];
  if(!tree.length && !carved.length){
    $("#tab-payloads").innerHTML="<div class=\"empty\">No embedded or encoded payloads resolved. "+
      "Run in <b>deep</b> mode with <b>--carve</b> to peel encoding, compression and XOR layers.</div>";
    return;
  }
  var html="";
  if(tree.length){
    html+="<h3 class=\"sh\">Resolved payload stages <span class=\"muted\" style=\"font-weight:400\">"+
      "— each layer peeled from the sample, statically</span></h3>";
    tree.forEach(function(n){
      var indent=num(n.depth)*18;
      var sc=n.verdict?scoreColor(n.score):"var(--border2)";
      html+="<div class=\"pnode\" style=\"margin-left:"+indent+"px\">"+
        "<span class=\"rail\">L"+num(n.depth)+"</span>"+
        "<span style=\"flex:1;min-width:0\">"+
          "<span style=\"display:flex;gap:8px;align-items:center;flex-wrap:wrap\">"+
            "<span class=\"method\">"+esc(n.method||"?")+"</span>"+
            "<b>"+esc(n.file_type||"unknown")+"</b>"+
            "<span class=\"muted mono\" style=\"font-size:11px\">"+fmtBytes(n.size)+" · H "+num(n.entropy).toFixed(2)+"</span>"+
            (n.verdict?("<span class=\"badge\" style=\"color:"+sc+";border-color:"+sc+"\">"+num(n.score)+"</span>"):"")+
            (n.family?("<span class=\"tag\">"+esc(n.family)+"</span>"):"")+
          "</span>"+
          (n.detail?("<div class=\"pmeta\">"+esc(n.detail)+"</div>"):"")+
          (n.sha256?("<div class=\"pmeta\">"+esc(n.sha256)+cp(n.sha256)+"</div>"):"")+
          ((n.findings&&n.findings.length)?("<ul class=\"list-dot\" style=\"margin-top:5px\">"+
            n.findings.map(function(f){return "<li>"+esc(f)+"</li>";}).join("")+"</ul>"):"")+
          ((n.iocs&&n.iocs.length)?("<div class=\"pmeta\" style=\"color:var(--amber)\">"+
            n.iocs.map(function(v){return esc(defang(v));}).join(" · ")+"</div>"):"")+
        "</span></div>";
    });
  }
  if(carved.length){
    var cb="";
    carved.forEach(function(a){
      cb+="<div style=\"border-bottom:1px solid var(--surface2);padding:9px 0\">"+
        "<div><b>"+esc(a.type||"artifact")+"</b> <span class=\"muted mono\" style=\"font-size:11px\">"+
          hex(a.offset)+" · "+fmtBytes(a.length)+" · H "+num(a.entropy).toFixed(2)+"</span></div>"+
        (a.sha256?("<div class=\"mono\" style=\"font-size:11px\">"+esc(a.sha256)+cp(a.sha256)+"</div>"):"")+
        (a.reason?("<div class=\"muted\" style=\"font-size:11.5px\">"+esc(a.reason)+"</div>"):"")+
        (a.preview?("<div class=\"mono faint\" style=\"font-size:11px\">"+esc(a.preview)+"</div>"):"")+"</div>";
    });
    html+=box("carved artifacts ("+carved.length+")",cb,!tree.length);
  }
  $("#tab-payloads").innerHTML=html;
}

/* ---------- behaviour: what to expect at runtime ---------- */
function renderBehavior(r){
  var p=r.profile||{};
  var html="";
  var exp=p.expected_behavior||[];
  if(exp.length){
    html+="<h3 class=\"sh\" style=\"margin-top:0\">Expected runtime behaviour "+
      "<span class=\"muted\" style=\"font-weight:400\">— validate these in a sandbox or against EDR telemetry</span></h3>";
    html+="<ul class=\"checklist\">"+exp.map(function(b){return "<li><span>"+esc(b)+"</span></li>";}).join("")+"</ul>";
  }
  if(p.classification||p.malware_type){
    html+="<h3 class=\"sh\">Assessment</h3>";
    html+="<div style=\"font-size:15px;font-weight:650;margin-bottom:6px\">"+esc(p.classification||"unclassified")+"</div>";
    if(p.malware_type&&p.malware_type.length)
      html+="<div class=\"pills\">"+p.malware_type.map(function(t){return "<span class=\"pill\"><b>"+esc(t)+"</b></span>";}).join("")+"</div>";
    if(p.confidence||p.confidence_score)
      html+="<div class=\"muted mono\" style=\"font-size:11.5px;margin-bottom:9px\">confidence "+esc(p.confidence||"")+" ("+num(p.confidence_score)+")</div>";
    if(p.executive_assessment)
      html+="<p style=\"max-width:78ch\">"+esc(p.executive_assessment)+"</p>";
  }
  if(p.key_capabilities&&p.key_capabilities.length){
    html+="<h3 class=\"sh\">Key capabilities</h3><ul class=\"list-dot\">"+
      p.key_capabilities.map(function(c){return "<li>"+esc(c)+"</li>";}).join("")+"</ul>";
  }
  var fm=r.family_matches||[];
  if(fm.length){
    html+="<h3 class=\"sh\">Family hypotheses</h3>";
    fm.forEach(function(m){
      html+="<div style=\"border-bottom:1px solid var(--surface2);padding:9px 0\">"+
        "<div><b>"+esc(m.family)+"</b> <span class=\"muted\">"+esc(m.category||"")+" · "+
        esc(m.confidence||"")+" · score "+num(m.score)+"</span></div>"+
        ((m.evidence&&m.evidence.length)?("<ul class=\"list-dot\">"+m.evidence.map(function(e){return "<li>"+esc(e)+"</li>";}).join("")+"</ul>"):"")+
        "</div>";
    });
  }
  if(p.ttps&&p.ttps.length){
    html+="<h3 class=\"sh\">MITRE ATT&amp;CK</h3><div class=\"tablewrap\"><table class=\"grid\"><thead><tr><th>tactic</th>"+
      "<th>technique</th><th>id</th><th>confidence</th></tr></thead><tbody>";
    p.ttps.forEach(function(t){
      html+="<tr><td>"+esc(t.tactic||"")+"</td><td class=\"trunc\">"+esc(t.technique||"")+
        "</td><td><span class=\"tag\" style=\"color:var(--blue);border-color:var(--blue)\">"+esc(t.id||"—")+
        "</span></td><td style=\"color:"+sevColor(t.severity)+"\">"+esc(t.confidence||"")+"</td></tr>";
    });
    html+="</tbody></table></div>";
  }
  if(p.crypto_indicators&&p.crypto_indicators.length){
    html+="<h3 class=\"sh\">Crypto indicators</h3>";
    p.crypto_indicators.forEach(function(c){
      html+="<div style=\"padding:6px 0;border-bottom:1px solid var(--surface2)\">"+
        "<span class=\"mono\" style=\"color:var(--purple)\">"+esc(c.primitive)+"</span> "+
        "<span class=\"muted\">"+esc(c.purpose||"")+(c.confidence?(" · "+esc(c.confidence)):"")+"</span>"+
        (c.evidence?("<div class=\"mono faint\" style=\"font-size:11px\">"+esc(c.evidence)+"</div>"):"")+"</div>";
    });
  }
  if(p.recommended_actions&&p.recommended_actions.length){
    html+="<h3 class=\"sh\">Recommended actions</h3><ul class=\"list-dot\">"+
      p.recommended_actions.map(function(a){return "<li>"+esc(a)+"</li>";}).join("")+"</ul>";
  }
  if(p.business_impact&&p.business_impact.length){
    html+="<h3 class=\"sh\">Business impact</h3><ul class=\"list-dot\">"+
      p.business_impact.map(function(a){return "<li>"+esc(a)+"</li>";}).join("")+"</ul>";
  }
  if(!html) html="<div class=\"empty\">No behavioural profile was produced for this sample.</div>";
  $("#tab-behavior").innerHTML=html;
}

/* ---------- structure ---------- */
function box(title,bodyHtml,open){
  return "<details class=\"box\""+(open?" open":"")+"><summary><span>"+esc(title)+
    "</span><span class=\"chev\">›</span></summary><div class=\"body\">"+bodyHtml+"</div></details>";
}
function kvRow(k,v){ return "<div class=\"kv\"><div class=\"kk\">"+esc(k)+"</div><div class=\"vv\">"+v+"</div></div>"; }
/* renderFileMap answers a question no table answers well: *where* in the file
   the suspicious density sits. Position along the byte axis is the whole point,
   so it is the one place here that earns a plotted form rather than a list.
   Entropy is a magnitude, so it uses a single-hue sequential ramp; the
   high-entropy regions and carved offsets are overlaid as marks, not as extra
   hues. */
function renderFileMap(r){
  var size=num(r.size); if(size<=0) return "";
  /* PE, ELF and Mach-O all publish the same SectionInfo shape, so the map works
     for any of them rather than only for PE. */
  var secs=(r.pe&&r.pe.sections)||(r.elf&&r.elf.sections)||(r.macho&&r.macho.sections)||[];
  var regions=r.high_entropy_regions||[], carved=r.carved_artifacts||[];
  if(!secs.length && !regions.length && !carved.length) return "";

  var html="<div class=\"filemap\"><div class=\"fmhead\"><span class=\"fmtitle\">File map</span>"+
    "<span class=\"muted\" style=\"font-size:11.5px\">entropy across "+fmtBytes(size)+
    (r.truncated_analysis?(" · only "+fmtBytes(r.analyzed_bytes)+" analysed"):"")+"</span></div>";

  html+="<div class=\"fmtrack\">";
  if(secs.length){
    /* Each section is drawn at its real raw offset and width, so gaps between
       sections (overlays, appended data, slack) are visible as gaps. */
    secs.forEach(function(s){
      var off=num(s.raw_offset), sz=num(s.raw_size);
      if(sz<=0||off<0||off>size) return;
      var left=(off/size)*100;
      var wid=Math.max(0.35,(sz/size)*100);
      if(left+wid>100) wid=Math.max(0.35,100-left);
      html+="<span class=\"fmseg\" style=\"left:"+left.toFixed(3)+"%;width:"+wid.toFixed(3)+
        "%;background:"+entropyColor(s.entropy)+"\" "+
        "title=\""+esc(s.name||"section")+" · "+hex(off)+" · "+fmtBytes(sz)+
        " · entropy "+num(s.entropy).toFixed(2)+"\"></span>";
    });
  } else {
    /* No section table: bucket the file and shade buckets that carry a
       high-entropy region, so the strip still shows position. */
    var BUCKETS=48, buckets=[];
    for(var i=0;i<BUCKETS;i++) buckets.push(0);
    regions.forEach(function(re){
      var a=Math.floor((num(re.offset)/size)*BUCKETS);
      var b=Math.floor(((num(re.offset)+num(re.length))/size)*BUCKETS);
      for(var i=Math.max(0,a);i<=Math.min(BUCKETS-1,b);i++){
        if(num(re.entropy)>buckets[i]) buckets[i]=num(re.entropy);
      }
    });
    var base=num(r.entropy);
    buckets.forEach(function(v,i){
      var e=v||base;
      html+="<span class=\"fmseg\" style=\"left:"+((i/BUCKETS)*100).toFixed(3)+"%;width:"+
        (100/BUCKETS).toFixed(3)+"%;background:"+entropyColor(e)+"\" "+
        "title=\"offset "+hex(Math.floor(size*(i/BUCKETS)))+" · entropy "+e.toFixed(2)+"\"></span>";
    });
  }
  /* Overlay marks: high-entropy regions and carved artifact offsets. */
  regions.forEach(function(re){
    var left=(num(re.offset)/size)*100;
    if(left>=0&&left<=100) html+="<span class=\"fmmark\" style=\"left:"+left.toFixed(2)+"%\" "+
      "title=\"high entropy at "+hex(re.offset)+" · "+num(re.entropy).toFixed(2)+"\"></span>";
  });
  carved.forEach(function(a){
    var left=(num(a.offset)/size)*100;
    if(left>=0&&left<=100) html+="<span class=\"fmmark carve\" style=\"left:"+left.toFixed(2)+"%\" "+
      "title=\"carved "+esc(a.type||"artifact")+" at "+hex(a.offset)+"\"></span>";
  });
  html+="</div>";
  html+="<div class=\"fmaxis\"><span>0x0</span><span>"+hex(Math.floor(size/2))+"</span><span>"+hex(size)+"</span></div>";

  html+="<div class=\"fmlegend\"><span>entropy</span>"+
    "<span class=\"fmramp\"><span style=\"background:var(--e0)\"></span><span style=\"background:var(--e1)\"></span>"+
    "<span style=\"background:var(--e2)\"></span><span style=\"background:var(--e3)\"></span>"+
    "<span style=\"background:var(--e4)\"></span><span style=\"background:var(--e5)\"></span>"+
    "<span style=\"background:var(--e6)\"></span></span><span class=\"faint mono\">0 → 8</span>";
  if(regions.length) html+="<span class=\"fmkey\"><span class=\"kd\" style=\"background:var(--amber)\"></span>high-entropy region ×"+regions.length+"</span>";
  if(carved.length) html+="<span class=\"fmkey\"><span class=\"kd\" style=\"background:var(--purple)\"></span>carved artifact ×"+carved.length+"</span>";
  html+="</div>";

  /* The strip shows position; this table carries the exact numbers, which is
     also the accessible fallback for anyone who cannot read the colour. */
  if(secs.length){
    html+="<div class=\"fmrows\">";
    secs.forEach(function(s){
      var e=num(s.entropy);
      var flags=(s.executable?"X":"")+(s.writable?"W":""); if(!flags) flags="-";
      html+="<div class=\"fmrow\"><span class=\"trunc\">"+esc(s.name||"")+"</span>"+
        "<span class=\"fmbar\"><div style=\"width:"+((e/8)*100).toFixed(1)+"%;background:"+entropyColor(e)+"\"></div></span>"+
        "<span>"+e.toFixed(2)+"</span><span class=\"faint\">"+flags+"</span></div>";
    });
    html+="</div>";
  }
  html+="</div>";
  return html;
}

function renderStructure(r){
  var pe=r.pe, sim=r.similarity||{}, h=r.hashes||{};
  var html=renderFileMap(r);

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
  html+=box("hashes and similarity",hb,true);

  if(pe){
    var pb="";
    pb+=kvRow("machine",esc(pe.machine||"—"));
    pb+=kvRow("subsystem",esc(pe.subsystem||"—"));
    pb+=kvRow("timestamp",esc(pe.timestamp||"—"));
    pb+=kvRow("image base",pe.image_base?esc(pe.image_base):"—");
    pb+=kvRow("entry point",pe.entry_point?esc(pe.entry_point):"—");
    pb+=kvRow("managed runtime",pe.managed_runtime?"yes":"no");
    pb+=kvRow("certificate",pe.has_certificate?"present":"none");
    html+=box("PE header",pb,true);

    /* Section entropy is drawn by renderFileMap above, which carries both the
       positional strip and the exact per-section numbers. */
    var imps=pe.imports||[];
    if(imps.length){
      var sus={};
      (r.functions||[]).forEach(function(f){
        var rk=sevRank(f.severity);
        if(rk>=2 && f.name) sus[f.name.toLowerCase()]=(rk>=3)?"var(--red)":"var(--amber)";
      });
      var ib="<div class=\"implist\">";
      imps.slice(0,60).forEach(function(im){
        var col=sus[String(im).toLowerCase()];
        ib+="<div class=\"imp trunc\""+(col?(" style=\"color:"+col+";font-weight:600\""):"")+">"+esc(im)+"</div>";
      });
      ib+="</div>";
      if(imps.length>60) ib+="<div class=\"faint mono\" style=\"font-size:11px;margin-top:8px\">"+(imps.length-60)+" more</div>";
      html+=box("imports ("+imps.length+")",ib,false);
    }
  }

  if(r.high_entropy_regions&&r.high_entropy_regions.length){
    var eb="";
    r.high_entropy_regions.forEach(function(re){
      eb+="<div class=\"mono\" style=\"color:var(--red);font-size:11.5px;padding:2px 0\">"+
        hex(re.offset)+" · "+fmtBytes(re.length)+" · entropy "+num(re.entropy).toFixed(2)+"</div>";
    });
    html+=box("high-entropy regions ("+r.high_entropy_regions.length+")",eb,false);
  }

  var fns=r.functions||[];
  if(fns.length){
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
        "</td><td class=\"faint\">"+esc(f.source||"—")+"</td></tr>";
    }).join("");
    html+=box("behavioural functions ("+list.length+")",
      "<div class=\"tablewrap\"><table class=\"grid\"><thead><tr><th>function</th><th>category</th>"+
      "<th>severity</th><th>source</th></tr></thead><tbody>"+rows+"</tbody></table></div>",false);
  }

  var ae=r.archive_entries||[];
  if(ae.length){
    var ab="<div class=\"tablewrap\"><table class=\"grid\"><thead><tr><th>name</th><th>type</th><th>size</th><th>entropy</th></tr></thead><tbody>";
    ae.slice(0,80).forEach(function(e){
      ab+="<tr><td class=\"trunc\">"+esc(e.name)+"</td><td>"+esc(e.type||"—")+"</td><td>"+
        fmtBytes(e.size)+"</td><td>"+num(e.entropy).toFixed(2)+"</td></tr>";
    });
    ab+="</tbody></table></div>";
    html+=box("archive entries ("+ae.length+")",ab,false);
  }

  var et=r.external_tools||[];
  if(et.length){
    var xb="";
    et.forEach(function(t){
      var col=t.found?"var(--green)":"var(--faint)";
      var out=(t.output||t.error||t.status||"");
      if(out.length>160) out=out.slice(0,160)+"…";
      xb+="<div style=\"border-bottom:1px solid var(--surface2);padding:6px 0\">"+
        "<span style=\"color:"+col+"\" class=\"mono\">"+esc(t.name)+"</span>"+
        (t.timed_out?" <span class=\"faint\">(timed out)</span>":"")+
        "<div class=\"mono faint\" style=\"font-size:11px\">"+esc(out)+"</div></div>";
    });
    html+=box("external tools ("+et.length+")",xb,false);
  }

  if(!html) html="<div class=\"empty\">No structural detail available for this file type.</div>";
  $("#tab-structure").innerHTML=html;
}

/* ---------- report ---------- */
function renderReport(r){
  var avail=r.available_downloads||[];
  var meta={
    json:["JSON","machine-readable result for pipelines"],
    txt:["Text","full plain-text analyst report"],
    html:["HTML","standalone analyst report"],
    pdf:["PDF","management / CISO summary"],
    iocs:["IOCs","extracted indicators, one per line"],
    yar:["YARA","generated hunting rule"],
    yml:["Sigma","generated detection rule"],
    stix:["STIX 2.1","threat-intel bundle"],
    pack:["Report pack","every format, zipped"]
  };
  var html="<h3 class=\"sh\" style=\"margin-top:0\">Downloads</h3>";
  if(!avail.length){ html+="<div class=\"empty\">No downloadable outputs.</div>"; }
  avail.forEach(function(fmt){
    var m=meta[fmt]||[fmt,fmt];
    var url="/api/download/"+encodeURIComponent(state.currentId)+"/"+encodeURIComponent(fmt);
    html+="<div class=\"outrow\"><span class=\"ext\">"+esc(m[0])+"</span>"+
      "<span class=\"desc trunc\">"+esc(m[1])+"</span>"+
      "<a class=\"dlbtn\" href=\""+url+"\">↓ download</a></div>";
  });

  /* Detection provenance: which rule packs loaded, which rules actually fired,
     which plugins ran. Without this a custom --rules pack is a black box — you
     cannot tell a rule that did not match from a rule that failed to load. */
  var packs=r.rule_packs||[], matches=r.rule_matches||[], plugins=r.plugins||[];
  if(packs.length||matches.length||plugins.length){
    html+="<h3 class=\"sh\">Detection provenance</h3>";
    if(packs.length){
      var loaded=0, fired=0;
      packs.forEach(function(p){ loaded+=num(p.rules_loaded); fired+=num(p.rules_fired); });
      html+="<div class=\"muted\" style=\"font-size:12.5px;margin-bottom:8px\">"+
        packs.length+" rule pack(s) · "+loaded+" rule(s) loaded · <b style=\"color:var(--teal)\">"+fired+" fired</b></div>";
      packs.forEach(function(p){
        html+="<div class=\"rulerow\"><span class=\"ruleid\">"+num(p.rules_fired)+"/"+num(p.rules_loaded)+"</span>"+
          "<span style=\"min-width:0\"><b>"+esc(p.name||p.path||"pack")+"</b>"+
          (p.path?("<div class=\"faint mono\" style=\"font-size:11px\">"+esc(p.path)+"</div>"):"")+
          ((p.warnings&&p.warnings.length)?("<div style=\"color:var(--amber);font-size:11.5px\">"+
            p.warnings.map(function(w){return esc(w);}).join("<br>")+"</div>"):"")+
          "</span></div>";
      });
    }
    if(matches.length){
      html+="<div style=\"height:10px\"></div>";
      matches.forEach(function(m){
        var sc=sevColor(m.severity);
        html+="<div class=\"rulerow\"><span class=\"ruleid\">"+esc(m.rule_id||"rule")+"</span>"+
          "<span style=\"min-width:0\"><b>"+esc(m.name||"")+"</b> "+
          "<span class=\"tag sev\" style=\"color:"+sc+";border-color:"+sc+"\">"+esc(m.severity||"")+"</span> "+
          (m.category?("<span class=\"tag\">"+esc(m.category)+"</span>"):"")+
          (m.confidence?("<span class=\"tag\">"+esc(m.confidence)+"</span>"):"")+
          ((m.evidence&&m.evidence.length)?("<ul class=\"list-dot\" style=\"margin-top:4px\">"+
            m.evidence.map(function(e){return "<li>"+esc(e)+"</li>";}).join("")+"</ul>"):"")+
          "</span></div>";
      });
    }
    if(plugins.length){
      html+="<div style=\"height:10px\"></div>";
      plugins.forEach(function(p){
        var ok=String(p.status||"")==="complete";
        html+="<div class=\"rulerow\"><span class=\"ruleid\" style=\"color:"+(ok?"var(--green)":"var(--amber)")+
          ";border-color:"+(ok?"var(--green)":"var(--amber)")+"\">"+esc(p.status||"?")+"</span>"+
          "<span style=\"min-width:0\"><b>"+esc(p.name||"")+"</b> <span class=\"faint mono\" style=\"font-size:11px\">"+
          esc(p.version||"")+"</span>"+
          (p.summary?("<div class=\"muted\" style=\"font-size:11.5px\">"+esc(p.summary)+"</div>"):"")+
          ((p.warnings&&p.warnings.length)?("<div style=\"color:var(--amber);font-size:11.5px\">"+
            p.warnings.map(function(w){return esc(w);}).join("<br>")+"</div>"):"")+
          "</span></div>";
      });
    }
  }

  html+="<h3 class=\"sh\">Triage summary</h3>";
  html+="<div class=\"muted\" style=\"font-size:12.5px;margin-bottom:9px\">Your triage marks stay on this machine. "+
    "Copy them into a ticket or case note.</div>";
  html+="<button type=\"button\" class=\"chip\" id=\"copytriage\">copy triage summary</button>";

  var log=r.debug_log||[];
  if(log.length){
    var lb=log.map(function(line){
      var col="var(--faint)";
      if(line.indexOf("[WARN]")>=0) col="var(--amber)";
      else if(line.indexOf("[ERROR]")>=0) col="var(--red)";
      else if(line.indexOf("[INFO]")>=0) col="var(--text)";
      return "<div class=\"logline\" style=\"color:"+col+"\">"+esc(line)+"</div>";
    }).join("");
    html+="<div style=\"height:16px\"></div>"+box("scan log ("+log.length+" lines)",lb,false);
  }
  $("#tab-report").innerHTML=html;
  $("#copytriage").addEventListener("click",function(){
    var lines=[];
    lines.push("FlatScan triage — "+(r.file_name||"sample"));
    lines.push("sha256: "+((r.hashes&&r.hashes.sha256)||""));
    lines.push("verdict: "+(r.verdict||"")+" (score "+num(r.risk_score)+")");
    lines.push("");
    ["escalate","reviewed","fp"].forEach(function(st){
      var items=state.evidence.filter(function(x){return state.triage[evKey(x)]===st;});
      if(!items.length) return;
      lines.push((st==="fp"?"FALSE POSITIVE":st.toUpperCase())+":");
      items.forEach(function(x){ lines.push("  - ["+(x.severity||"")+"] "+(x.title||"")); });
      lines.push("");
    });
    var untriaged=state.evidence.filter(function(x){return !state.triage[evKey(x)];}).length;
    lines.push(untriaged+" finding(s) not yet triaged.");
    navigator.clipboard.writeText(lines.join("\n")).catch(function(){});
    toast("triage summary copied");
  });
}

/* ---------- history ---------- */
function addHistory(id,res){
  state.history.unshift({id:id,name:res.file_name||"sample",score:num(res.risk_score),
    mode:res.mode||state.mode,time:Date.now()});
  if(state.history.length>12) state.history.length=12;
  try{ sessionStorage.setItem("flatscan_hist",JSON.stringify(state.history)); }catch(e){}
  renderHistory();
}
function renderHistory(){
  var h=$("#histpop");
  if(!state.history.length){ h.innerHTML="<div class=\"empty\" style=\"padding:14px 0\">no scans yet</div>"; return; }
  h.innerHTML=state.history.map(function(e){
    return "<button type=\"button\" class=\"hist\" data-id=\""+esc(e.id)+"\">"+
      "<span style=\"min-width:0\"><span class=\"hn trunc\">"+esc(e.name)+"</span>"+
      "<span class=\"hm\"> · "+esc(e.mode)+" · "+timeAgo(e.time)+"</span></span>"+
      "<span class=\"hs\" style=\"color:"+scoreColor(e.score)+"\">"+e.score+"</span></button>";
  }).join("");
  $all("#histpop .hist").forEach(function(row){
    row.addEventListener("click",function(){
      var id=row.getAttribute("data-id");
      if(state.jobs[id]){ state.currentId=id; loadResult(state.jobs[id]); closePops(); }
      else toast("that result is no longer loaded");
    });
  });
}

/* ---------- keyboard ---------- */
$("#helpbtn").addEventListener("click",function(){ $("#kbd").classList.add("show"); });
$("#kbd").addEventListener("click",function(){ $("#kbd").classList.remove("show"); });
document.addEventListener("keydown",function(e){
  var tag=(e.target&&e.target.tagName)||"";
  var typing=(tag==="INPUT"||tag==="TEXTAREA");
  if(e.key==="Escape"){
    $("#kbd").classList.remove("show"); closePops();
    if(typing && e.target.id==="evsearch"){ state.filter.q=""; renderEvidence(); }
    return;
  }
  if(typing) return;
  if(e.key==="?"){ e.preventDefault(); $("#kbd").classList.toggle("show"); return; }
  if(e.key==="t"){ toggleTheme(); return; }
  if(e.key==="/"){ e.preventDefault(); selectTab("evidence"); var s=$("#evsearch"); if(s) s.focus(); return; }
  var tabs=["evidence","indicators","config","payloads","behavior","structure","report"];
  if(e.key>="1"&&e.key<="7"){ if($("#results").style.display!=="none") selectTab(tabs[Number(e.key)-1]); return; }
  if($("#results").style.display==="none") return;
  if(state.tab!=="evidence") return;
  var list=visibleEvidence();
  if(e.key==="j"){ if(state.selected<list.length-1){ state.selected++; renderEvidence(); scrollSel(); } return; }
  if(e.key==="k"){ if(state.selected>0){ state.selected--; renderEvidence(); scrollSel(); } return; }
  if(e.key==="r"){ setTriage(state.selected,"reviewed"); return; }
  if(e.key==="f"){ setTriage(state.selected,"fp"); return; }
  if(e.key==="e"){ setTriage(state.selected,"escalate"); return; }
});
function scrollSel(){
  var el=$("#evlist .ev.sel");
  if(el&&el.scrollIntoView) el.scrollIntoView({block:"nearest"});
}

/* ---------- startup ---------- */
(function(){
  try{
    var saved=sessionStorage.getItem("flatscan_hist");
    if(saved){ state.history=JSON.parse(saved)||[]; renderHistory(); }
  }catch(e){}
  renderIdle();
})();
</script>
</body>
</html>`
