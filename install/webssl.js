// SSL certificate reader/writer

(function () {

var hex = "0123456789ABCDEF", RSA = "1.2.840.113549.1.1.1";

var objects = {
  '2.5.4.6'   : 'Country Name',
  '2.5.4.10'  : 'Organization Name',
  '2.5.4.11'  : 'Organizational Unit Name',
  '2.5.4.3'   : 'Common Name',
  '2.5.29.17' : 'Subject Alternative Names',
  '2.5.29.19' : 'Basic Constraints',

  '1.2.840.113549.1.1.1'  : 'RSA Encryption',

  '1.2.840.113549.1.1.4'  : 'RSA with MD5',
  '1.2.840.113549.1.1.5'  : 'RSA with SHA1',
  '1.2.840.113549.1.1.11' : 'RSA with SHA256',
  '1.2.840.113549.1.1.12' : 'RSA with SHA384',
  '1.2.840.113549.1.1.13' : 'RSA with SHA512',
  '1.2.840.113549.1.1.14' : 'RSA with SHA224',
  '1.2.840.10045.4.3.1'   : 'ECDSA with SHA224',
  '1.2.840.10045.4.3.2'   : 'ECDSA with SHA256',
  '1.2.840.10045.4.3.3'   : 'ECDSA with SHA384',
  '1.2.840.10045.4.3.4'   : 'ECDSA with SHA512'
}

var to_str = function (x)
{
  return (String.fromCharCode (x));
}

var to_hex = function (x)
{
  if (x <= 255) return (hex [x >> 4] + hex [x & 15]);
  var y = ""; do y = hex [(x >> 4) & 15] + hex [x & 15] + y; while (x = x >> 8);
  return (y);
}

var bin2hex = function (x)
{
  var y = "", z = typeof (x) == "string";
  for (w of x) y += z ? to_hex (w.charCodeAt(0)) : to_hex (w);
  return (y);
}

var hex2bin = function (x)
{
  var z = 0, y = []; x = x.replace (/\s/g, "");
  for (; z < x.length; z += 2) y.push (parseInt (x.substr (z, 2), 16) || 0);
  return (y);
}

var form_pem = function (type, data)
{
  var n, p = "", q = "-----BEGIN " + type + "-----";

  for (x of data) p += to_str (x); p = btoa (p);
  for (n = 0; n < p.length; n += 64) q += "\n" + p.substr (n, 64);

  return (q + "\n-----END " + type + "-----\n");
}

var form_arg = function (data1, data2)
{
  var n, p = "", q = "", r = bin2hex (data1), s = bin2hex (data2);

  for (n = 0; n < r.length; n += 64) p += "\n" + r.substr (n, 64);
  for (n = 0; n < s.length; n += 64) q += "\n" + s.substr (n, 64);

  return ("\n<--->" + p + "\n<--->" + q + "\n");
}

var add_num = function (p, r, q)
{
  var a, b, m = [r, 0], n;

  if (typeof (q) == "number") q = ['', '', q]; else
  {
    q = q.split ("."); m.push (q[0] * 40 + q[1] * 1);
  }
  for (n = 2; n < q.length; n++)
  {
    r = q[n] * 1; a = (r >> 14) & 127; b = (r >> 7) & 127;
    if (a) m.push (a + 128); if (b) m.push (b + 128); m.push (r & 127);
  }
  m[1] = m.length - 2; return (p.concat (m));
}

var add_str = function (p, r, q)
{
  var a, b, m = [], n;

  if (typeof (q) != "string") m = q; else for (n = 0; n < q.length; n++)
  {
    a = q.charCodeAt (n); if (a < 32 || a > 125) a = 0x21; m.push (a);
  }

  n = m.length; a = n >> 8; b = n & 255;
  if (a) r = [r,130,a,b]; else if (b > 127) r = [r,129,b]; else r = [r,b];

  return (p.concat (r, m));
}

var calc_times = function (t1, t2)
{
  var m, n, time, s1, s2;

  var timestring = function (t)
  {
    if (t.length < 15) t = (t.substr (0,2) < "70" ? "20" : "19") + t;
    if (t.length != 15) return ["", 0]; m = [t.substr (0,4)];

    for (n = 2; n < 7; n++) m.push (t.substr (n * 2, 2));
    t = m.slice (0,3).join("-") + " " + m.slice (3,6).join (":");

    return ([t, Date.UTC (m[0], m[1], m[2], m[3], m[4], m[5]) / 1000]);
  }

  t1 = timestring (t1); t2 = timestring (t2);
  s1 = t1 [0]; s2 = t2 [0]; t1 = t1 [1]; t2 = t2 [1];

  if (!s1 || !s2 || (time = t2 - t1) <= 0) time = "none"; else
  {
    var H = time / 3600, D = Math.trunc (H / 24), Y = Math.trunc (D / 365);
    H -= D * 24; D -= Y * 365; H = Math.trunc (H * 10) / 10;
    time = Y + "-Y, " + D + "-D, " + H + "-H";
  }

  return ([t1, t2, s1 ? s1 : "none", s2 ? s2 : "none", time]);
}

var get_object = function (crt, n, s)
{
  if (s)
  {
    n = (crt && n < crt.length) ? (n ? n : crt.length - 1) : 0;
    for (; n > 0; n--) if (crt [n].includes (s)) break;
    return (n < 0 ? 0 : n);
  }

  if (!crt || n < 0 || n >= crt.length) n = 0;
  s = (n ? crt [n].split ("~") [0] : "....").split (".");
  return ([s[0], s[1] * 1, s[2] * 1, s[3] * 1, s[4] * 1]);
}

var parse_objects = function (crt, log)
{
  var a, b, c, d, m, n, p, q, r, s, t, pos, peg, pin, tag, len;

  if (!Array.isArray (crt) || !Array.isArray (d = crt [0])) return null;

  var getnum = function ()
  {
    n = 0; do { m = d [pin++]; n = (n << 7) + (m & 127); } while (m > 127); return (n);
  }

  for (pos = 0; pos < d.length; pos++)
  {
    peg = pin = pos; tag = d [pos]; len = d [++pos]; t = to_hex (tag);

    if (len > 127) if (len != 129 && len != 130) continue; else
      for (n = len, len = 0; n > 128; n--) len = (len << 8) + d [++pos];

    if (tag > 0x2F && (tag < 0x80 || tag > 0x8F))
    {
      pin = pos + len + 1; s = "." + peg + "." + (pos + 1) + "." + pin + "~";
      if (log) console.log (peg + 10000, t, pin + 10000, len);
      if (pin > d.length) continue;

      if (tag == 0x30) crt.push ("seq.0x" + t + s);
      if (tag == 0x31) crt.push ("set.0x" + t + s);

      if (tag >= 0x32)
      {
        r = "Unknown";
        if (tag == 0xA0) r = "Version"; else if (tag == 0xA3) r = "Extensions";
        crt.push ("app.0x" + t + s + r + "~");
      }
      continue;
    }

    pin = pos + 1; pos += len; s = "." + peg + "." + pin + "." + (pos + 1) + "~";
    if (log) console.log (peg + 10000, t, pos + 10001, len);
    if (pos >= d.length) continue;

    if (tag < 0x06)
    {
      crt.push ("bin.0x" + t + s);
    }
    else if (tag == 0x06)
    {
      a = d [pin++]; b = a % 40; a = Math.trunc (a / 40);
      p = a + "." + b; while (pin <= pos) p += "." + getnum();
      q = objects [p]; if (log) console.log (p, "-", q);
      crt.push ("obj.0x" + t + s + p + "~" + q + "~");
    }
    else if (tag == 0x0C || tag == 0x13 || tag == 0x17 || tag == 0x18 || tag == 0x82)
    {
      r = (tag == 0x17 || tag == 0x18) ? "time~" : (tag == 0x82 ? "dns~" : "");
      while (pin <= pos) r += ((c = d [pin++]) < 32 || c > 125) ? "!" : to_str (c);
      crt.push ("txt.0x" + t + s + r); if (log) console.log (r);
    }
    else if (tag == 0x87)
    {
      b = d.slice (pin, pos + 1); pin = pos; c = b.length; r = "#" + b.join (".");

      if (c > 4 && !(c & 1)) for (a = 0, r = "#"; a < c; a += 2)
        r += (a ? ":" : "") + to_hex ((b[a] << 8) + b[a + 1]).toLowerCase();

      crt.push ("txt.0x" + t + s + "dns~" + r); if (log) console.log (r);
    }
    else crt.push ("xxx.0x" + t + s);
  }

  if (log)
  {
    console.log ("Length:", d.length, "Stop:", pos); console.log ("-");
  }

  if (log > 0) for (n = 0; n < d.length; n++)
  {
    a = d [n]; b = (a > 32 && a < 127) ? to_str (a) : " ";
    console.log (n + 10000, " " + b + "  0x" + to_hex (a) + "  " + a);
  }

  if (log > 0) console.log ("-"); return (pos == d.length ? crt : null);
}

var birdcage = async (action, data) =>
{
  action = "/~gotta_birdcage=" + action; if (!data) data = "";

  try {
    var resp = await fetch (action, { method: 'POST', body: data });
    data = await resp.text(); if (resp.status != 200) data = "";
  }
  catch (e) { console.log (e); data = ""; }

  return (data);
}

var get_file = async (name, raw) =>
{
  var m, n; if (typeof (name) == "number") name = "";
  if (!name || typeof (name) != "string") return (name);

  if (!name.includes ("---")) try
  {
    var resp = await fetch (name);
    if (resp.status != 200) throw ("File GET error");
    name = raw ? await resp.text() : await resp.arrayBuffer();
  }
  catch (e) { console.log (e); return null; }

  if (raw) return (name); else if (typeof (name) != "string")
  {
    m = new Uint8Array (name); if (m[0] == 0x30) return (Array.from (m));
    name = ""; for (n = 0; n < m.length; n++) name += to_str (m [n]);
  }

  try { name = atob (name.split ("-----") [2]); } catch (e) { name = "" }

  for (m = [], n = 0; n < name.length; n++) m [n] = name.charCodeAt (n);
  if (!name || m[0] != 0x30) m = null; return (m);
}

var put_file = async (name, data) =>
{
  if (!name || typeof (name) != "string") return false;

  try {
    var resp = await fetch (name, { method: 'PUT', body: data });
    if (resp.status != 200) throw ("File PUT error"); return true;
  }
  catch (e) { console.log (e); return false; }
}

var Parse_certificate = async (file, log) =>  // returns object or null
{
  file = await (get_file (file, false));
  return (parse_objects ([file], log || 0));
}

var Generate_RSA_key = async (size, file) =>  // returns pem or array or empty string
{
  if (size)
  {
    var m = await birdcage ("PUDDYTAT=" + size, "");
    if (!m || !file) return (m); return (await put_file (file, m) ? m : "");
  }

  var m, crt = await Parse_certificate (file); if (!crt || crt.length < 4) return "";

  m = get_object (crt, 2); if (m[4] - m[3] == 1) m = get_object (crt, 3);
  if (m[1] != 2) return ""; m = crt [0].slice (m[3], m[4]);

  m = add_str ([], 2, m).concat ([2,3,1,0,1]); m = add_str ([], 3, add_str ([0], 0x30, m));
  m = add_str ([], 0x30, add_num ([], 6, RSA).concat ([5,0])).concat (m);
  m = add_str ([], 0x30, m); return (m);
}

var Verify_signature = async (state, key) =>  // returns true or false
{
  if (!state || !state.certificate || !state.signature || !state.algo [0]) return false;
  if (!key) key = state.public_pem; else key = await get_file (key, true);
  if (!key || typeof (key) != "string") return false;

  key += form_arg (state.certificate, state.signature);
  return (await birdcage ("TWEETY=" + state.algo [0], key) == "ok");
}

var Sign_certificate = async (state, key, file) =>  // returns pem or empty string, modifies state
{
  if (!state || !state.certificate || !state.algo [0] || !state.algo [1]) return "";
  if (!(key = await get_file (key, true)) || typeof (key) != "string") return "";

  var m; key += form_arg (state.certificate, "");
  key = await birdcage ("CANARY=" + state.algo [0], key);
  if (!key) return ""; key = state.signature = hex2bin (key);

  m = add_str (state.certificate, 0x30, add_num ([], 6, state.algo [1]).concat ([5,0]));
  m = add_str ([], 0x30, add_str (m, 3, [0].concat (key))); m = form_pem ("CERTIFICATE", m);

  if (!file) return (m); return (await put_file (file, m) ? m : "");
}

var Create_certificate = function (state, auth)  // returns object or null, modifies state
{
  var a, b, m, n, p, q, issuer = [], subject = [], altnames = [];
  var items = Object.entries (objects);

  if (auth != true && auth != false) return null;
  if (!state || !state.public_key || !(m = state.algo [0])) return null;

  for (p = "RSA with SHA" + m, q = "", n = 6; n < items.length; n++)
    if (p == items [n][1]) { q = items [n][0]; break; }

  if (!q) return null; state.algo [1] = q; state.algo [2] = p;

  if (p = state.issuer) for (n = 0; n < 4 && n < p.length; n++) if (m = p[n])
  {
    q = add_str (add_num ([], 6, items [n][0]), 0x0C, m);
    issuer = add_str (issuer, 0x31, add_str ([], 0x30, q));
  }
  if (p = state.subject) for (n = 0; n < 4 && n < p.length; n++) if (m = p[n])
  {
    q = add_str (add_num ([], 6, items [n][0]), 0x0C, m);
    subject = add_str (subject, 0x31, add_str ([], 0x30, q));
  }
  if (p = state.altnames) for (q = [], n = 0; n < p.length; n++)
  {
    if (!(m = p[n]) || q.includes (m)) continue; q.push (m);

    if (m [0] != "#")
    {
      a = m.substr (0,2) == "*."; b = a ? m.substr (2) : m;
      if (a && !b.includes (".")) b = ""; else b = "." + b + ".";
      if (b.replace (/[-_.]/g, "").replace (/[a-z\d]/g, "")) b = "";
      if (b.search (/\.[-_.]/) + b.search (/[-_.]\./) >= -1) b = "";
      if (b) altnames = add_str (altnames, 0x82, m); continue;
    }
    if (m.includes ("."))
    {
      m = m.substr (1).split ("."); if (m.length != 4) continue;
      for (a = 0; a < 4; a++) m [a] = (m[a] * 1) & 255;
    }
    else
    {
      m = m.substr (1); b = m.split (":"); a = b.length;
      if (a < 8) b = m.replace ("::", ":".repeat (10 - a)).split (":");
      m = []; if (b.length != 8) continue;

      for (a = 0; a < 8; a++) b[a] = parseInt (b[a], 16) || 0;
      for (a = 0; a < 8; a++) m.push (b[a] >> 8, b[a] & 255);
    }
    if (q.includes (b = m.join (" "))) continue;
    q.push (b); altnames = add_str (altnames, 0x87, m);
  }

  auth = auth ? [4,5,0x30,3,1,1,255] : [4,2,0x30,0];

  // notbefore, notafter
  a = "20201215060000Z"; b = "20401225060000Z";
  a = add_str ([], 0x30, add_str ([], 0x18, a).concat (add_str ([], 0x18, b)));

  // basic constraints, subject alternative names
  b = add_str ([], 4, add_str ([], 0x30, altnames));
  b = add_str ([], 0x30, add_num ([], 6, items [4][0]).concat (b));
  b = add_str ([], 0x30, add_num ([], 6, items [5][0]).concat (auth)).concat (b);
  b = add_str ([], 0xA3, add_str ([], 0x30, b));

  // version, serial number
  n = Math.trunc (Math.random() * 0x70000) + 0x10000;
  m = add_str ([0xA0,3,2,1,2], 2, [n >> 16, (n >> 8) & 255, n & 255]);

  // hash algorithm
  m = add_str (m, 0x30, add_num ([], 6, state.algo [1]).concat ([5,0]));
  // issuer, notbefore, notafter, subject
  m = add_str (add_str (m, 0x30, issuer).concat (a), 0x30, subject);
  // public key, constraints, alternative names
  m = add_str ([], 0x30, m.concat (state.public_key, b));

  state.certificate = m; return state;
}

var Get_certificate_state = function (crt, names)  // returns object
{
  var m, n, p, q, algo, issuer = [], subject = [], altnames = [];
  var bin, items = Object.entries (objects), state = { algo: ["","",""] };

  if (!Array.isArray (crt) || !Array.isArray (bin = crt [0])) return (state);

  for (n = 0; n < 4; n++)
  {
    m = "~" + items [n][0] + "~";
    p = get_object (crt, 0, m); q = get_object (crt, p - 1, m);
    if (!q) { q = p; p = 0; }

    p = p ? crt [p + 1].split ("~") [1] : "";
    q = q ? crt [q + 1].split ("~") [1] : "";

    issuer.push (q); subject.push (p);
  }

  if (n = get_object (crt, 0, "~Subject Alternative Names~"))
  {
    m = get_object (crt, n + 1); m = bin.slice (m[3], m[4]);
    
    if (m = parse_objects ([m])) for (n = 2; n < m.length; n++)
      if (m[n].includes ("~dns~")) altnames.push (m[n].split ("~")[2]);
  }

  n = get_object (crt, 0, "obj.0x06"); algo = n ? crt [n].split ("~") : "";
  if (!algo || !algo [2].includes (" with ")) algo = ["", "", "unknown"];

  if (algo [2].indexOf ("RSA with SHA")) algo [0] = ""; else
  {
    algo [0] = algo [2].substr (12);
    m = get_object (crt, n); state.certificate = bin.slice (4, m[2] - 2);
    m = get_object (crt, n + 2); state.signature = bin.slice (m[3] + 1);
  }

  if (!(n = get_object (crt, 0, "~RSA Encryption~"))) algo [3] = 0; else
  {
    m = get_object (crt, n - 2);
    state.public_key = bin.slice (m[2], m[4]);
    state.public_pem = form_pem ("PUBLIC KEY", state.public_key);

    m = get_object (crt, n + 2);
    m = parse_objects ([bin.slice (m[3] + 1, m[4])], 0);
    m = get_object (m, 2); algo [3] = (m[4] - m[3] - 1) * 8;
  }

  if (Array.isArray (names)) altnames = names [0] ? altnames.concat (names) : names;
  state.algo = algo; state.issuer = issuer; state.subject = subject; state.altnames = altnames;

  q = get_object (crt, 0, "~time~"); p = get_object (crt, q - 1, "~time~");
  q = q ? crt [q].split ("~")[2] : ""; p = p ? crt [p].split ("~")[2] : "";

  state.timestamps = calc_times (p, q); return (state);
}

webssl = {
  parseCertificate    : Parse_certificate,
  generateRSAkey      : Generate_RSA_key,
  verifySignature     : Verify_signature,
  signCertificate     : Sign_certificate,
  createCertificate   : Create_certificate,
  getCertificateState : Get_certificate_state,

  bin2hex : bin2hex, hex2bin : hex2bin,
  form_pem : form_pem, form_arg : form_arg, birdcage : birdcage
}

})();

/*
certificate anatomy (a lot of nesting)
one or two chars = hex, three digits = decimal
?? represents an indeterminate length (using one to three bytes)
object identifiers appear in braces

30 ??
  30 ??
    A0 3 2 1 2 - version, 2 3 x x x - serial #
    30 0D {6 9 2A 86 48 86 F7 D 1 1 B} 5 0 - RSA with SHA256 (1.2.840.113549.1.1.11)
    30 ??
      31 ?? 30 ?? {6 3 85 4 6} 0C ?? xx - issuer country (2 chars)
      31 ?? 30 ?? {6 3 85 4 A} 0C ?? xx - organization
      31 ?? 30 ?? {6 3 85 4 B} 0C ?? xx - organizational unit
      31 ?? 30 ?? {6 3 85 4 3} 0C ?? xx - common name
    30 22
      18 0F 20201215060000Z - not before
      18 0F 20401225060000Z - not after
    30 ??
      31 ?? 30 ?? {6 3 85 4 6} 0C ?? xx - subject country (2 chars)
      31 ?? 30 ?? {6 3 85 4 A} 0C ?? xx - organization
      31 ?? 30 ?? {6 3 85 4 B} 0C ?? xx - organizational unit
      31 ?? 30 ?? {6 3 85 4 3} 0C ?? xx - common name
    30 129 159
      30 0D {6 9 2A 86 48 86 F7 D 1 1 1} 5 0 - RSA Encryption (1.2.840.113549.1.1.1)
      3 129 141 0 30 129 137 (2 129 129 0 <public key>, 2 3 1 0 1) - for 1024-bit
    A3 ?? 30 ??
      - basic constraints (authority cert or server cert)
      30 0C {6 3 85 1D 13} 4 5 30 03 1 1 FF -or- 30 09 {6 3 85 1D 13} 4 2 30 0
      - subject alternative names
      30 ?? {6 3 85 1D 11} 4 ?? 30 ??
        82 ?? xx
        82 ?? xx
        82 ?? xx
  - body ends here, signature follows
  30 0D {6 9 2A 86 48 86 F7 D 1 1 B} 5 0 - RSA with SHA256 (same as above)
  3 129 129 0 <128-byte signature>
end

The signature is an encrypted data structure containing a 256-bit hash.
This is what it looks like (51 bytes):

30 31 30 0D {6 9 60 86 48 1 65 3 4 2 1} 5 0 4 20 <32-byte hash>
The object identifier is SHA-256 (2.16.840.1.101.3.4.2.1).
*/

/*
data types (recognized):
  1 (0x01) - boolean
  2 (0x02) - integer
  3 (0x03) - bit string
  4 (0x04) - octet string
  5 (0x05) - null
  6 (0x06) - object identifier
 12 (0x0C) - UTF8 string
 19 (0x13) - printable string
 23 (0x17) - time string (2-digit year)
 24 (0x18) - time string (4-digit year)
 48 (0x30) - sequence
 49 (0x31) - set
130 (0x82) - subject alternative name (DNS)
135 (0x87) - subject alternative name (IP address)
160 (0xA0) - version
163 (0xA3) - extensions
*/

/*
name objects (not recognized):
surname			2.5.4.4
serial number		2.5.4.5
locality		2.5.4.7
state or province	2.5.4.8
street address		2.5.4.9
title			2.5.4.12
postal code		2.5.4.17
name			2.5.4.41
given name		2.5.4.42
initials		2.5.4.43
generation qualifier	2.5.4.44
dnQualifier		2.5.4.46
*/

/*
Hashing:
MD2			1.2.840.113549.2.2
MD5			1.2.840.113549.2.5
SHA-1			1.3.14.3.2.26
SHA-256			2.16.840.1.101.3.4.2.1
SHA-394			2.16.840.1.101.3.4.2.2
SHA-512			2.16.840.1.101.3.4.2.3
SHA-224			2.16.840.1.101.3.4.2.4

Public key:
ecPublicKey		1.2.840.10045.2.1
Diffie-Hellman		1.2.840.10046.2.1
RSA Encryption		1.2.840.113549.1.1.1
md2WithRsaEncryption	1.2.840.113549.1.1.2

Signatures:
ecdsa-with-SHA256	1.2.840.10045.4.3.2
md5WithRsaEncryption	1.2.840.113549.1.1.4
sha1WithRsaEncryption	1.2.840.113549.1.1.5
sha256WithRsaEncryption	1.2.840.113549.1.1.11
sha384WithRsaEncryption	1.2.840.113549.1.1.12
sha512WithRsaEncryption	1.2.840.113549.1.1.13
sha224WithRsaEncryption	1.2.840.113549.1.1.14
*/
