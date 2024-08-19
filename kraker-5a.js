/*
Local Proxy Server for Alleycat Player

Improvements from version 1c to version 2a (June 29, 2020):

- handle double-slash at start of "location" response header
- handle rare case where "?" immediately follows host name without a slash
- do not strip byte-range headers in non-passthrough mode (problem with seeking on mp4 videos)
- handle socket disconnection error (ECONNRESET) in default_handler (crash issue)
- handle ".well-known/http-opportunistic" request coming from Firefox for 123tvnow.com streams
- delete request headers "origin" and "referer" if set to blank
- complete rewrite of local GET and PUT; security model via _aliases.txt

Improvements from version 2a to version 2b (March 11, 2021):

- added gzip decompression for m3u8 handler
- added ability to replace response headers (indicated with "!")
- added crash check in case SSL files are missing
- added Socks5 proxy server for DNS and TOR support

Improvements from version 2b to version 2c (April 8, 2021):

- updated init_settings to not invoke DNS "default" on reload
- updated proxy_handler to correctly destroy sockets (memory leak)
- added reporting system to track socket disposition
- added dns_lookup in http_handler and proxy_handler

Improvements from version 2c to version 3a (May 8, 2021):

- updated dns_lookup to report timing and IP address
- updated dns_lookup to handle four simultaneous lookups
- updated http_handler to destroy network connection (memory leak)
- added special cases "LOCAL" and "0.0.0.0"
- added DNS over HTTPS (JSON format only)

Improvements from version 3a to version 3b (November 19, 2021):

- modified options_proc to look for non-blank "access-control-request-method"
- tor4all corrected to exclude LOCAL or 0.0.0.0
- removed request.on callback in http_handler due to incompatibility with Node.js v16

Improvements from version 3b to version 4a (May 15, 2022):

- HTTP (8080) and HTTPS (8081) merged via http_handler
- added HTTP support on 8088 ("CONNECT" method for SSL)
- connections through 8080/8081 are now routed to 8088
- added restart command for HTTPS server
- added shadow ports and cookie stealer
- added "vpx" and "timeout" parameters
- added support for i2p and IPFS
- DoH routed through port 8080 for socket reuse
- updated dns_resolve to handle wildcard domains
- updated add_resolver to support VPN/TOR IP groups (example: TOR+group)

Improvements from version 4a to version 4b (June 13, 2022):

- rebuilt connection procedure in http_handler
- new "timeout" spec: negative for connect, positive for idle

Improvements from version 4b to version 4c (August 4, 2022):

- added security for "reload" command to only allow declared file names
- convert double vertical bar to %7C in url command string (extremely unusual case)
- support URI encoding for vpn/vpx username/password
- header values are URI decoded only if prepended with "!"
- change some headers to camel case to bypass bot detectors (Cloudflare)
- added option to auto-delete shadow port with shadow secret
- tor4all flag works for VPN (if one is specified)
- prevent invalid "server fail" status message in proxy_handler
  (when incoming socket is closed while outgoing socket is connecting)
- do not drop down to OS for DNS resolution in case of error (security risk)
  (only ".localhost" or dotless domains are permitted to be resolved by OS)
- initialize DNS resolver with more reasonable timeouts
- display literal error codes for DoH resolver
- added FETCH option (blank ip list ignored); ability to delete SHD 
- revised the "reload" and "activate" commands
- localhost:8081 no longer redirects to localhost:8080
- replaced unsafe decodeURIComponent with safe_decode
- fixed ECONNRESET unhandled exception for DoH (update: not fixed)

Improvements from version 4c to version 4d (August 22, 2022):

- do not auto-respond to OPTIONS request for shadow port
- changed access-control-allow-origin handling to work with cookies (shadow port only)
- added error handler for when a socket is idle (source of ECONNRESET exception for DoH)
- changed response._header in default_handler to response.headersSent

Improvements from version 4d to version 4e (November 9, 2022):

- added authorization check with !key parameter to prevent cookie abuse
- added $$$ keyword for domain shortcut on shadow ports
- added ability to GET file list from local directory
- convert string to buffer to ensure correct content length in responses
- allow localhost shadow for tweak_m3u8 and handle_boot_dash
- for localhost and localhost shadow: remove "set-cookie" response header
- allow auto-response to OPTIONS request for localhost shadow
- added file view listing for shadow ports (with shadow secret)
- added error handler for uncaughtException with crash log (_crashlog.txt)
- allow ** accept header to contain mime type (like **text/html**)
- upgraded local_link to support directory paths in _aliases.txt
- added caching policy with HTTP "last-modified" and "if-modified-since"
- added Dns.lookup to dns_master for LOCAL domains (Node.js 18 defaults to IPv6)
- all references to localhost are replaced with or resolve to proxy_addr
- allow tilde instead of vertical bar in header string (due to Chrome browsers)
- fixed online shadow setup to allow @ in parameter string

Improvements from version 4e to version 5a (August 19, 2024):

- support shadow fork in "location" header (ex: http://localhost:8080/$proxy$)
- revised some rules for shadow ports and shadow forks
- changed "local" in http_handler to a bit field
- updated local_link to catch some unsafe directory paths
- updated PUT to support "range" and truncation (++ mode)
- added get_head (HEAD method) for file stats
- "server" renamed to "iplist" (original name was unhelpful)
- improved http_handler by splitting off the query string
- added safe_numero for safe conversion from string (port number)
- added filter for header names (allowed specials: - + _ . ! ~ * $ & %)
- fixed get_file and get_head to prevent crash on restricted directories
- fixed issue with curl not connecting to socks5
- added secureContext and mock mode (1-2-3-A-1A-2A-3A)
- updated dns_servers to allow DoH and DNS in same setting
- changed dns_resolve to flag dotless domains as 0.0.0.0 instead of LOCAL
- allow "+" or "," as separator in "restart" and "activate" commands
- fixed dns_resolve so "VPN" w/o vpn_host resolves to "@vpn:" and not "@vpn"
- added mechanism for probing the socks5 port
- added support for websocket in http_handler
- added option to shadow_host for shadowing full path
- added "/" option to shadow port for deleting original path
- added "?" option to shadow port for replacing query string
- removed "+" option from shadow port due to security risk (can use an alias)
- added function:shadow_port to cover subdomains (example: .google.com)
- added websocket server for progress reporting and testing
- added "!" option for removing non-critical request headers
- added VPX and ability to cancel named profiles (add_resolver)
- file paths containing "@" now have write privilege
- added RSA keygen, sign, verify, encrypt, decrypt (gotta_birdcage)
- added AES encrypt/decrypt (gotta_pussyfoot)
- added support for Kraker Mockery
- added http/2 to mock mode (mock:X)
- added support for HTTP proxies
- fixed put_file (w/o range header)
  proc_done is now called on stream close (file truncation issue)
- "restart" command changed to invoke setSecureContext in start_servers
- added certificate forgery with two modes:
  TLS bridge in proxy_handler (major rewrite) and HTTP CONNECT method
- start_servers can load certificates from directory named after shadow secret
- added optional password protection for server commands (flags, reload, etc.)
- blocking cross-origin PUT and POST methods (shadow port can enable)
  @...@ instead of $secret$ may be used for query fork (more secure)
- added localhost IP detection in http_handler (127.0.0.1, ::1, 192.168.x.x)
  also improved loopback detection in proxy_handler
- added IP redirection after DNS lookup (shadow port)
- added LOCKED option for "vpn" command
- added method to save browser cookies to memory file
- added certificate pinning in http_handler and proxy_handler

- IMPORTANT
  removed variable declaration assignment chains everywhere
  (some vars were ending up in the "global" context - BAD!!!)

*/

const fs    = require ('fs');
const http  = require ('http');
const https = require ('https');
const http2 = require ('http2');
const crypt = require ('crypto');
const zlib  = require ('zlib');

const Dns   = require ('dns');
const net   = require ('net');
const tls   = require ('tls');
const dns   = new Dns.Resolver ({ timeout: 7500, tries: 2 });
// DNS timeout works only with Node 16.0.0 and up (maybe Windows-only issue)

process.on ("uncaughtException", function (error, origin)
{
  console.log (error.stack);
  fs.writeFile ("_crashlog.txt", error.stack, function() { process.exit (1); });
});

var proxy_name = "Kraker-5a", proxy_addr = "127.0.0.1";

var aliases = "_aliases.txt", settings = "_settings.txt";    // do not use uppercase

var http_port = 8080, https_port = 8081, socks_port = 8088, ipfs_port = 8089;
var tor1_port = 9050,  tor2_port = 9150,   i2p_port = 4444;

var mime_list = {
  txt: "text/plain", htm: "text/html", html: "text/html",
  css: "text/css", js: "application/javascript", json: "application/json",
  gif: "image/gif", jpeg: "image/jpeg", jpg: "image/jpeg", png: "image/png", webp: "image/webp",
  mpd: "application/dash+xml", m3u: "application/x-mpegurl", m3u8: "application/x-mpegurl",
  mp3: "audio/mpeg", mp4: "video/mp4", webm: "video/webm", ts: "video/mp2t"
};

var camel_case = [
  'host', "Host", 'user-agent', "User-Agent", 'accept', "Accept",
  'accept-language', "Accept-Language", 'accept-encoding', "Accept-Encoding",
  'connection', "Connection", 'content-type', "", 'content-length', "", 'range', ""
];

var reqcount = 0, passthru = 0, last_time = 0, last_pass = "", local_files = [0, ""];
var sockmon, program = {}, scratch = [], keepheaders = { Headers: 'none' }, keeprequest;

var profile_count = 0, proxy_flags = 0, dns_reset, dns_time, dns_count = 0;
var sockets_count = 9, sockets_open = 0, profile = [], iplist = [], dnslist = [], socklist = [];

var doh_address, doh_host, doh_path, vpn_host, vpn_port, vpn_name, vpn_pass, vpnlock;
doh_address = doh_host = doh_path = vpn_host = vpn_port = vpn_name = vpn_pass = "";

var tinfoil = "", shadow_secret = " ", shadow_host = {'shadow:80': ";", 'shadow:443': "$"};

console.log ("=-----------------------------------------------------------------------------=");
console.log (" Kraker (version 5a) Local Proxy Server - waiting on port " + http_port + ", ctrl-C to exit");
console.log ("=-----------------------------------------------------------------------------=");

// fix home directory if command line includes "-home"
if (process.argv.includes ("-home")) process.chdir (__dirname);

console.log ("@ Home directory is located at " + process.cwd());
console.log ("@ " + init_settings (settings) + " (" + settings + ")");

var state, http_server, https_server;
start_servers ("", ""); dns_servers ("default"); add_resolver (""); init_fetch();

// For Cloudflare TLS fingerprinting. See notes at end of file.

const secureContext = tls.createSecureContext
({
  ecdhCurve: [ 'X25519', 'prime256v1', 'secp384r1', 'secp521r1' ].join (':'),
    // prime256v1 is same as secp256r1

  ciphers: [
    'TLS_AES_128_GCM_SHA256',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_256_GCM_SHA384',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'ECDHE-RSA-CHACHA20-POLY1305',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-AES256-SHA',
    'ECDHE-ECDSA-AES128-SHA',
    'ECDHE-RSA-AES128-SHA',
    'ECDHE-RSA-AES256-SHA',
    'AES128-GCM-SHA256',
    'AES256-GCM-SHA384',
    'AES128-SHA',
    'AES256-SHA' ].join (":"),

  sigalgs: [
    'ecdsa_secp256r1_sha256',
    'ecdsa_secp384r1_sha384',
    'ecdsa_secp521r1_sha512',
    'rsa_pss_rsae_sha256',
    'rsa_pss_rsae_sha384',
    'rsa_pss_rsae_sha512',
    'rsa_pkcs1_sha256',
    'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha512' ].join (':')

    //'ECDSA+SHA1',      // for some reason, 'ecdsa_sha1' doesn't work
    //'rsa_pkcs1_sha1'

// Node versions earlier than 12.11.0 do not support the sigalgs option
// ecdsa_sha1 & rsa_pkcs1_sha1 are deprecated in OpenSSL 3.0 (Node 17.0.0)
});

///// End of Setup /////

///////////////////////////////////
///// function: start_servers /////
///////////////////////////////////

function start_servers (crtfile, keyfile)
{
  if (!keyfile) keyfile = "_https_key.pem"; var ssl_key = shadow_secret + "/" + keyfile;
  if (!crtfile) crtfile = "_https_crt.pem"; var ssl_crt = shadow_secret + "/" + crtfile;

  try { ssl_key = fs.readFileSync (ssl_key); } catch { ssl_key = "" }
  try { ssl_crt = fs.readFileSync (ssl_crt); } catch { ssl_crt = "" }

  if (!ssl_key) try { ssl_key = fs.readFileSync (keyfile); } catch {}
  if (!ssl_crt) try { ssl_crt = fs.readFileSync (crtfile); } catch {}

  // connectionsCheckingInterval is new to Node 18
  // it sets an idle timeout (default: 30000, cannot be disabled)

  var options = {
    SNICallback: function (host, func) { func (null, create_certificate (host, 1)); },
    key: ssl_key, cert: ssl_crt, handshakeTimeout: 5000, connectionsCheckingInterval: 86400000
  }

  if (!state)
  {
    var m = ""; net.createServer (proxy_handler).listen (socks_port, m);
    http_server = http.createServer (options, http_handler).listen (http_port, m);
    https_server = https.createServer (options, http_handler).listen (https_port, m);
  }
  else try
  {
    if (!ssl_key || !ssl_crt) throw (""); https_server.setSecureContext (options);
  }
  catch { return ("HTTPS certificate: error"); }

  http_server.timeout = https_server.timeout = 0;
  http_server.requestTimeout = https_server.requestTimeout = 0;
  http_server.headersTimeout = https_server.headersTimeout = 5000;
  http_server.keepAliveTimeout = https_server.keepAliveTimeout = 0;
  http_server.maxConnections = https_server.maxConnections = 150;

  if (!state) http_server.on ("connect", function (request, socket)
  {
    var n = 0, m = request.url, sock = socket;
    var conn = net.createConnection (https_port, proxy_addr);

    if (m[0] == "[") if ((n = m.indexOf ("]")) > 0) m = m.substr (1);
    if (n <= 0) n = m.lastIndexOf (":") + 1; if (n) m = m.substr (0, n - 1);

    if (m = create_certificate (m, -1)) try
    {
      sock = new tls.TLSSocket (socket, { isServer: true, key: m[0], cert: m[1] });
      conn = new tls.TLSSocket (conn);
    } catch { }

    function done () { conn.destroy(); sock.destroy(); }

    conn.on ("error", function() { }); conn.on ("close", function() { done(); });
    sock.on ("error", function() { }); sock.on ("close", function() { done(); });

    sock.pipe (conn, {end:true}); conn.pipe (sock, {end:true});
    socket.write ("HTTP/1.1 200 OK" + "\r\n\r\n");
  });

  options = tls.connect (https_port, proxy_addr, {rejectUnauthorized:false}, function()
  {
    var a = this.getPeerCertificate(), b = a.issuer; this.destroy(); state = {};
    state.algo = ['256', '1.2.840.113549.1.1.11']; state.issuer = [b.C, b.O, b.OU, b.CN];
    state.subject = ['', '', '', 'shadow']; state.public_key = Array.from (a.pubkey);
    state.names = a.subjectaltname.replace (/DNS:|\s/g, "").split (",");
    state.key = ssl_key; state.cert = ssl_crt; state.altnames = [];
  });

  options.on ("error", function()
  {
    if (!state) state = {}; console.log ("@ HTTPS certificate: invalid or missing");
  });

  return ("HTTPS certificate: okay");
}

///////////////////////////////////
///// function: init_settings /////
///////////////////////////////////

function init_settings (name)
{
  var i, j, k, p, q, data = "", msg = "Settings file: ";

  p = name; q = shadow_secret + "/" + name;
  if (p.search (/[:?*/]/) >= 0) return (msg + "DUMB NAME");

  if (fs.existsSync (p)) data = fs.readFileSync (p, "utf8"); else
    if (fs.existsSync (q)) data = fs.readFileSync (q, "utf8");

  if (!data) return (msg + "NOT FOUND"); k = data.indexOf ("$end$");
  if (k < 0) return (msg + "NOT VALID"); data = data.substr (0, k);

  if (name == settings)
  {
    p = (data.match (/\$shadow_secret=([^$\s]*)/) || [,""])[1].split ("+");
    shadow_secret = p[0] || " "; tinfoil = p[1] ? "+" + p[1] : "";
  }

  profile = []; iplist = [];

  for (i = k = 0; j = data.indexOf ("[", i) + 1; i = j)
  {
    if (j < k) return (msg + "ERROR"); k = data.indexOf ("]", j);
    p = data.substr (j, k - j); if (p.search (/[#?+]/)) continue;
    q = p.replace (/\s+/gm, " ").replace (/\s?\|\s?/g, "|").trim();
    if (q.split (" ").length > 1) profile.push (q);
  }

  if (!profile_count++ || data.includes ("$fmodify=1$"))
  {
    proxy_flags = 0;
    if (data.includes ("$console=1$")) proxy_flags |= 1;
    if (data.includes ("$altport=1$")) proxy_flags |= 2;
    if (data.includes ("$tor4all=1$")) proxy_flags |= 4;
    if (data.includes ("$showdns=1$")) proxy_flags |= 16;
  }

  return (msg + "parsed and loaded");
}

////////////////////////////////
///// function: init_fetch /////
////////////////////////////////

function init_fetch ()
{
  var i, j = 0, k = 0;

  for (i = 1; i < iplist.length; i += 2) { j++; if (!iplist [i]) k++; }
  for (i = 0; i < iplist.length; i += 2) init_lookup (i, profile_count);

  return ("Resolvers: " + j + " (Pre-fetching: " + k + ")");
}

function init_lookup (num, count)
{
  var name = iplist [num], ip = iplist [num + 1];

  if (ip) return; else if (dns_count < 4) dns_count++; else
  {
    setTimeout (function() { init_lookup (num, count); }, 150); return;
  }

  dns_master (name, false, function (err, ip, ttl)
  {
    if (err) err = name; else
    {
      if (count != profile_count) ip = "CANCEL"; else iplist [num + 1] = ip;
      err = name + " - " + ip + " (" + ttl + "s)";
    }
    console.log ("<< " + (doh_address ? "DoH: " : "DNS: ") + err); dns_count--;
  });
}

//////////////////////////////////
///// function: add_resolver /////
//////////////////////////////////

function add_resolver (name)
{
  var m, n, p, q, r, s, dat, sub, cancel;

  if ((n = name.indexOf ("\n")) >= 0)  // called from shadow_proc
  {
    p = name.substr (0, n); q = name.substr (n + 1);

    if (n = q.indexOf ("+") + 1)
    {
      if (n == q.length) q = q.replace (/:/g, "+");
      r = q.split ("+"); q = r[0]; s = q ? "" : r.splice (0,2)[1];
      q = (q ? "VPX" : "VPX:") + s + " " + r.slice (0,4).join (" ");
    }
    else if (q[0] != "*") s = q; else
    {
      r = Buffer.from (q = q.substr (1), 'hex');
      p = "*" + p + (p.includes (":") ? "" : ":443");
      if (q[0] == "*") { delete program [p]; return ("gone"); }
      if (q.length > 32 || (q && r.length < 16)) return ("error");
      program [p] = r; return ("okay");
    }

    if (!p || (s && !net.isIP (s))) return ("error");
    for (n = 0; n < iplist.length; n += 2) if (p == iplist [n]) break;
    if (!q) iplist.splice (n, 2); else { iplist [n++] = p; iplist [n] = q; }
    return ("okay");
  }

  if ((cancel = name [0] == "-") && !(name = name.substr (1))) return;

  for (dat of profile)
  {
    dat = dat.split (" "); if (dat [0] != "?" + name) continue;

    if (sub = dat [1], !sub.includes ("/")) sub = sub.split ("|"); else
    {
      q = dat [2]; p = "@" + sub; if (p.substr (-1) != "/") p += "/";
      if (q && !cancel) shadow_host [p] = q; else delete shadow_host [p];
      continue;
    }

    for (p of sub) if (p)
    {
      if (dat.length < 3) q = ""; else
      {
        q = dat [Math.trunc (Math.random() * (dat.length - 2)) + 2];
        m = q.split ("+"); r = m[0]; if (s = m[1]) s = "+" + s + " ";

        if (r.length < 4 && s) for (n of profile) if (!n.indexOf (s))
        {
          n = n.split (" "); if (n.length < 2) continue;
          n = m[1] = n [Math.trunc (Math.random() * (n.length - 1)) + 1];
          if (m.length < 3) m = [r ? r + ":" + n : n]; q = m.join ("+"); break;
        }
      }

      if (q[0] == "*")
      {
        r = Buffer.from (q = q.substr (1), 'hex');
        p = "*" + p + (p.includes (":") ? "" : ":443");
        if ((q && r.length < 16) || q.length > 32) r = Buffer.from ("\0");
        program [p] = r; if (cancel || q[0] == "*") delete program [p]; continue;
      }

      s = ""; if (q[0] == "@") q = "SHD:" + q.substr (1);
      r = (q.length == 3 || q[3] == ":") ? q.substr (0,3) : "";

      if (r == "SHD")
      {
        if (r == q) { delete shadow_host [p]; continue; }
        if (p[0] == "$") { s += "$"; p = p.substr (1); }
        if (p[0] == "~") { s += "~"; p = p.substr (1); }
        if (p[0] == "~") { s += "~"; p = p.substr (1); }

        r = ""; q = q.substr (4); n = q.indexOf ("?");
        if (n >= 0) { r = q.substr (n); q = q.substr (0, n); }
        n = q[0] != "@" ? 0 : q.indexOf ("@", 1) + 1; s += q.substr (n);

        m = s[0] == "$"; if (!m && s[0] != ";") s = ";" + s;
        if (!p.includes (":")) p += m ? ":443" : ":80";

        shadow_host [p] = q.substr (0, n) + s + r;
        if (cancel) delete shadow_host [p]; continue;
      }

      for (n = 0; n = iplist.indexOf (p, n) + 1;)
        if (n & 1) { profile_count++; iplist.splice (n - 1, 2); break; }

      if (cancel || !q) continue; else if (r == "TOR" || r == "VPN")
      {
        r = q.substr (4); if (r && !net.isIP (r)) continue;
      }
      else if (q == "FETCH") q = ""; else if (n = q.indexOf ("+") + 1)
      {
        if (n == q.length) q = q.replace (/:/g, "+");
        r = q.split ("+"); q = r[0]; s = q ? "" : r.splice (0,2)[1];
        q = (q ? "VPX" : "VPX:") + s + " " + r.slice (0,4).join (" ");
        if (s && !net.isIP (s)) continue;
      }
      else if (q != "LOCAL" && !net.isIP (q)) continue;

      iplist.push (p); iplist.push (q);
    }
  }
}

/////////////////////////////////
///// function: dns_servers /////
/////////////////////////////////

function dns_servers (name)
{
  var p, q; if (p = name [0] == "!") name = name.substr (1);
  q = "#" + name + " "; if (dns_count && name) return ([]);
 
  if (p) doh_address = ""; if (!dns_reset) dns_reset = dns.getServers();

  if (name) for (p of profile) if (!p.indexOf (q))
  {
    q = p.substr (q.length).split (" ");
    if (q.length > 1 && q[1].includes ("/") && net.isIP (q[0]))
    {
      p = q[1].split ("/"); doh_host = p[0]; doh_address = q[0];
      doh_path = "/" + p.slice (1).join ("/"); q.splice (0, 2);
    }
    if (q.length) try { dns.setServers (q); } catch {}; name = ""; break;
  }
  if (name == "reset" || name == "default") dns.setServers (dns_reset);

  return (dns.getServers());
}

/////////////////////////////////
///// function: dns_resolve /////
/////////////////////////////////

function dns_resolve (name, vpx)
{
  var m, n, p, q, ip = ""; if (vpx && vpnlock) return ("0.0.0.0");

  for (n = 0; n < iplist.length; n += 2)
  {
    if ((p = iplist [n])[0] == ".")
    {
      if (p == "...") p = name; m = name.lastIndexOf (p);
      p = (m < 0 || m + p.length != name.length) ? p.substr (1) : name;
    }
    if (p == name) { ip = iplist [n + 1]; break; }
  }

  if (!ip) if (net.isIP (name)) ip = name; else
  {
    n = name.lastIndexOf ("."); p = name.substr (n + 1);
    if (p == "localhost") return (proxy_addr); if (n < 0) return ("0.0.0.0");

    if (p == "onion") ip = "TOR";
    if (p == "loki")  ip = "LOCAL";
    if (p == "snode") ip = "LOCAL";
    if (p == "i2p")   ip = "VPX:I2P";
  }

  if (ip == proxy_addr || ip == "::1" || ip == "LOCAL") return (ip);

  m = ""; p = ip.substr (0,3); q = ip ? ":" + ip : "";

  if ((n = ip.indexOf (" ")) > 0)
  {
    m = ip.substr (n); ip = ip.substr (0, n); if (vpx) m = "";
    if (m == " ") { m = p = ""; q = ip.substr (3); ip = q.substr (1); }
  }

  if (p == "TOR" || p == "VPN" || p == "VPX") ip = "@" + ip; else
    if (vpnlock) ip = "@VPN" + q; else if (proxy_flags & 4) ip = "@TOR" + q;

  if (vpx) ip = "@VPX" + (ip [0] == "@" ? ip.substr (4) : q); else
    if (p == "VPN" && !vpn_host) ip = "@vpn:" + ip.substr (5);

  return (ip ? ip + m : name);
}

////////////////////////////////
///// function: dns_lookup /////
////////////////////////////////

function dns_lookup (addr, host, func)
{
  var m, n, s, t, p = addr, q = host, is_local = p == "LOCAL";

  if (!is_local)
  {
    if (p[0] == "@" && p.length != 5) { p = p.substr (5) || q; q = ""; }
    if (!q || net.isIP (p) || net.isIP (p = q)) { func (p); return; }
  }

  if (!dns_count)
  {
    dns_time = Math.trunc (Date.now() / 1000);
    if (dnslist.length > 300) dnslist.splice (0, 20);
  }

  for (n = dnslist.length - 2; n >= 0; n -= 2) if (q == dnslist [n])
  {
    p = dnslist [n + 1].split (" ");
    q = p[0]; t = dns_time - (dns_count ? 300 : 0);
    if (p[1] * 1 < t) break; else { func (q); return; }
  }

  if (!q || dns_count > 3)
  {
    setTimeout (function() { dns_lookup (addr, host, func); }, 150); return;
  }

  if (q == host) q = "0.0.0.0";  // version 4c security fix

  dns_count++; dnslist.push (host, " "); n = dnslist.length - 1; p = Date.now();

  dns_master (host, is_local, function (err, ip, ttl)
  {
    t = Date.now(); if ((p = t - p) < 15) p = 15; t = Math.trunc (t / 1000);
    s = "<< " + (is_local ? "LOC" : (doh_address ? "DoH" : "DNS")) + ": ";
    if (err) m = err; else { m = q = ip; host += " (" + ttl + "s)"; }

    if (err || proxy_flags & 17) console.log (s + p + "ms - " + m + " - " + host);
    dnslist [n] = q + " " + (t + (err ? 5 : 300)); func (q); dns_count--;
  });
}

////////////////////////////////
///// function: dns_master /////
////////////////////////////////

function dns_master (name, is_local, func)
{
  if (is_local)
  {
    Dns.lookup (name, {family: 4}, function (err, addr, family)
    {
      if (err) func (err.code); else
        if (!addr) func ("ENODATA"); else func ("", addr, 0);
    });
    return;
  }

  if (!doh_address)
  {
    dns.resolve4 (name, { ttl:true }, function (err, list)
    {
      if (err) func (err.code); else
        if (!list.length) func ("ENODATA"); else func ("", list[0].address, list[0].ttl);
    });
    return;
  }

  var i, j, ans = ""; name = "?type=A&name=" + name;

  var options = {
    hostname: proxy_addr, port: http_port, path: '/!timeout:15|*https://' + doh_host + doh_path + name,
    headers: { host: '@' + doh_address, accept: 'application/dns-json', connection: 'keep-alive' }
  }

  var doh = http.get (options, function (res)
  {
    res.on ("data", function (data)
    {
      if (ans.length + data.length < 10000) ans += data.toString();
    });

    res.on ("end", function ()
    {
      try {
        ans = JSON.parse (ans); j = ans.Status; ans = ans.Answer;
        if (typeof (j) != "number") throw (""); i = j ? 0 : ans.length;

        for (; i > 0; i--) if (ans [i-1].type == 1)
        {
          ans = ans [i-1]; i = ans.data; j = ans.TTL;
          if (typeof (i) != "string" || !net.isIP (i)) throw ("");
          if (typeof (j) != "number") j = 0; break;
        }
      } catch { i = 0; j = 1; }

      if (i) func ("", i, j); else
      {
        ans = ["ENODATA", "EFORMERR", "ESERVFAIL", "ENOTFOUND"];
        func (j < 0 || j > 3 ? "ERROR (" + j + ")" : ans [j]);
      }
    });
  });

  doh.on ("error", function (err) { func (err.code); });
}

////////////////////////////////
///// function: stream_end /////
////////////////////////////////

function stream_end (stream, data)
{
  if (!stream.finished && !stream.writeableEnded) stream.end (data);
}

/////////////////////////////////////
///// function: default_handler /////
/////////////////////////////////////

function default_handler (response, error, local)
{
  var msg, err_msg, header = {}; if (response.headersSent) return;

  msg = "--------------------\n" +
        " Local Proxy Server \n" +
        "--------------------\n\n" +
        "Version Name: " + proxy_name + " [August 19, 2024]\n\n" +
        "HTTP at " + http_port + ", HTTPS at " + https_port + "\n" +
        "Socks5 Tunnel Proxy at " + socks_port + "\n\n" +
        "NODE.JS " + process.version + "\n";

  if (error != 200)
  {
    msg = "--Service Not Available--";
    if (error == 777) msg = " Local Request: Error";
    if (error == 888) msg = " Local Request: Invalid";
    if (error == 999) msg = "--Invalid Request--";
    if (local & 1) console.log (msg); msg = "";
  }

  if (error == 200) err_msg = "OK";
  if (error != 200) err_msg = "Deep State";
  if (error == 666) err_msg = "Illuminati";
  if (error == 999) err_msg = "Think Mirror";

  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";
  header ["access-control-allow-headers"] = "*";
  header ["access-control-expose-headers"] = "*";
  header ["accept-ranges"] = "bytes";

  header ["content-type"] = "text/plain";
  header ["content-length"] = (msg = Buffer.from (msg)).length;

  response.writeHead (error, err_msg, header); stream_end (response, msg);
}

///////////////////////////////
///// function: proc_done /////
///////////////////////////////

function proc_done (response, data, mime, local)
{
  var size, start, end, header = {}, msg = "OK";

  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";

  if (typeof (local) == "string")
  {
    header ["access-control-allow-credentials"] = "true";
    header ["access-control-allow-origin"] = local; local = 0;
  }

  header ["access-control-allow-headers"] = "*";
  header ["access-control-expose-headers"] = "*";
  header ["accept-ranges"] = "bytes";

  if (mime) header ["content-type"] = mime;
  if (mime) header ["x-content-type-options"] = "nosniff";

  if (!Array.isArray (data))
  {
    if (!Buffer.isBuffer (data)) data = Buffer.from (data);
    size = -1; header ["content-length"] = data.length;
  }
  else
  {
    size = data [0]; start = data [1]; end = data [2];
    if (data [3]) header ["last-modified"] = data [3];
    header ["content-length"] = end - start + 1;
    data = start < 0 ? Buffer.from ("") : "";
  }

  if (size < 0) response.writeHead (200, msg, header); else if (size > 0)
  {
    header ["content-range"] = "bytes " + start + "-" + end + "/" + size;
    response.writeHead (206, msg = "Partial Content", header);
  }
  else response.writeHead (304, msg = "Not Modified", header);

  if (data) stream_end (response, data);
  if (local & 1) console.log (" Local Request: " + msg);
}

//////////////////////////////////
///// function: options_proc /////
//////////////////////////////////

function options_proc (request, response)
{
  var header = {};

  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";
  header ["access-control-expose-headers"] = "*";

  var headers = request.headers ["access-control-request-headers"];
  var methods = request.headers ["access-control-request-method"];
  if (headers) header ["access-control-allow-headers"] = headers;
  if (methods) header ["access-control-allow-methods"] = methods;

  header ["accept-ranges"] = "bytes";
  header ["access-control-max-age"] = "30";
  header ["content-length"] = "0";

  response.writeHead (200, "OK", header); stream_end (response, "");
}

/////////////////////////////////
///// function: shadow_list /////
/////////////////////////////////

function shadow_list ()
{
  var n, m = Object.entries (shadow_host);
  var i, j, k, ii = 15, jj = 5, p = "", q = "";

  for (n of m) if (k = n[0]) if (k[0] != "@")
  {
    i = k.lastIndexOf (":"); j = k.length;
    if (i < 0) i = j; j -= i; if (++i > ii) ii = i; if (++j > jj) jj = j;
  }

  for (n of m) if (k = n[0]) if (k[0] != "@")
  {
    i = k.lastIndexOf (":"); j = k.length;
    if (i < 0) i = j; j -= i; i = ii - i; j = jj - j;
    p += " ".repeat (i) + k + " ".repeat (j) + "@" + n[1] + "\n";
  }
  else
  {
    i = k.length - 2; k = k.substr (1, i); j = ii + jj - i;
    if (k [i-1] == "/" || k.indexOf ("/") < 0) { k += "/"; j--; }
    q += k + " ".repeat (j < 2 ? 2 : j) + "@" + n[1] + "\n";
  }

  return (p + "\n" + q);
}

/////////////////////////////////
///// function: shadow_proc /////
/////////////////////////////////

function shadow_proc (x)
{
  var m, n, p, q, shadow;

  n = x[1] == shadow_secret ? 0 : 1; shadow = x[2].replace (/\s|%20/g, "");

  if (shadow.includes (".") || (tinfoil && x[1] != tinfoil)) n += 2;
  if (shadow.indexOf (":") != shadow.lastIndexOf (":")) n |= 2;
  if (shadow.substr (-1) == "+") n += 4;

  if (shadow.includes ("/")) { shadow = "@" + shadow; n += 8; }
  if (n & 8 && shadow.substr (-1) != "/") shadow += "/";

  m = x.length < 5 ? x[3] : x.slice (3).join ("@");

  if (n & 1 && n & 14) m = ">> need secret"; else if ((n & 12) == 4)
  {
    shadow = shadow.substr (0, shadow.length - 1); if (!m) m = "";
    n = add_resolver (shadow + "\n" + m); m = "[" + m + "] -- " + n;
  }
  else if (m != undefined)
  {
    p = m[0] != "@" ? 0 : m.indexOf ("@", 1) + 1;
    q = ""; if (p) { q = m.substr (0, p); m = m.substr (p); }

    if (m[0] == "$") n += 16; else if (!(n & 8) && m[0] != ";") m = ";" + m;
    if (!(n & 8) && !shadow.includes (":")) shadow += n & 16 ? ":443" : ":80";
    m = q + m + x[0]; shadow_host [shadow] = m; m = "= " + m;
  }
  else
  {
    m = shadow_host [shadow]; delete shadow_host [shadow];
    m = m == undefined ? "-- not found" : "-- removed";
  }

  return (shadow + " " + m);
}

/////////////////////////////////
///// function: shadow_port /////
/////////////////////////////////

function shadow_port (name)
{
  var s = shadow_host [name]; if (s) return (s);
  s = name.split ("."); if (s.length > 2) s.splice (0,1);
  return (shadow_host ["." + s.join (".")]);
}

/////////////////////////////////
///// function: safe_numero /////
/////////////////////////////////

function safe_numero (num)
{
  num = (typeof (num) != "string" || num.includes (".")) ? 0 : num * 1;
  if (num < 0) num = -num; return ((!num || num > 65535) ? 0 : num);
}

/////////////////////////////////
///// function: safe_decode /////
/////////////////////////////////

function safe_decode (uri)
{
  if (typeof (uri) != "string") return "";
  try { uri = decodeURIComponent (uri); } catch {}; return (uri);
}

///////////////////////////////
///// function: mime_type /////
///////////////////////////////

function mime_type (url)
{
  url = url.substr (url.lastIndexOf (".") + 1);
  return (mime_list [url.toLowerCase()] || "");
}

////////////////////////////////
///// function: local_data /////
////////////////////////////////

function local_data (name, data)
{
  if (name) if (data)
  {
    for (var n = local_files.length - 2; n > 1; n -= 2)
      if (local_files [n] == name) local_files.splice (n, 2);

    if (local_files.length > 200) local_files.splice (2, 20);
    if (data.length > 1) local_files.push (name, data);
  }
  else
  {
    for (var n = local_files.length - 2; n > 1; n -= 2)
      if (local_files [n] == name) return (local_files [n + 1]);
  }
  return ("");
}

////////////////////////////////
///// function: local_link /////
////////////////////////////////

function local_link (u, local)
{
  var m, n, p = "", q = (u[0] == "?") ? 1 : 0;
  if (q) { u = u.substr (1); if (u.includes ("@")) q += 2; }

  while (u.substr (-1) == "/") u = u.substr (0, u.length - 1);
  if (u [0] == "/" || u.substr (-1) == "." || u.includes ("./")) u = "";
  m = u.toLowerCase(); if (m == aliases || m == settings) u = "";

  if (u[0] != "+") { if (q && !u.includes ("/")) u = ""; } else
  {
    if (local_files [0] > (n = Date.now())) m = local_files [1]; else
    {
      m = fs.existsSync (aliases) ? fs.readFileSync (aliases, "utf8") : "";
      local_files [0] = n + 5000; local_files [1] = m;
    }
    n = u.indexOf ("/"); if (n > 0) { p = u.substr (n + 1); u = u.substr (0, n); }
    n = m.indexOf (u + ","); if (n < 0) { q |= 2; n = m.indexOf (u + "?,"); }

    if (n < 0) u = ""; else
    {
      u = m.substr (n + u.length, 300);
      if ((n = u.indexOf ("+")) < 0) u = ""; else u = u.substr (n + 1);
      if ((n = u.indexOf (";")) < 0) u = ""; else u = u.substr (0, n);
      if (u.substr (-1) == "/") u += p;
    }
    if (local & 1) console.log (" FILE: " + (u ? u : "none"));
  }

  if (u && q == 3) u = "?" + u; return (u);
}

//////////////////////////////
///// function: put_file /////
//////////////////////////////

function put_file (request, response, url, local)
{
  var append = url.substr (0, 2) == "++"; if (append) url = url.substr (1);
  if (url.substr (-1) == "+") { append = !append; url = url.substr (0, url.length - 1); }

  if ((url = local_link ("?" + url, local))[0] == "?")
    url = url.substr (1); else if (fs.existsSync (url)) url = "";

  if (!url) { default_handler (response, 777, local); return; }

  var range, size = fs.existsSync (url) ? fs.statSync (url).size : 0;

  if (!(range = request.headers ["range"]))
  {
    var stream = fs.createWriteStream (url, append ? { start: size, flags: "a" } : {});
    stream.on ("error", function() { default_handler (response, 777, local); });
    stream.on ("close", function() { proc_done (response, "", "", local); });
    stream.on ("open",  function() { request.pipe (stream, {end:true}); });
    return;
  }

  var buf = [], cnt = 0; range = range.substr (range.indexOf ("=") + 1).split ("-");
  var start = range[0] * 1 || 0, end = range[1] * 1 || 0, len = end - start + (append ? 0 : 1);

  if (start < 0 || start > end || start > size || len > 500000)
  {
    default_handler (response, 888, local); return;
  }

  request.on ("error", function() { default_handler (response, 777, local); return; });
  request.on ("data", function (d) { if ((cnt += d.length) <= len) buf.push (d); });

  request.on ("end", function() { if (cnt != len) request.emit ("error"); else
  {
    var file = fs.openSync (url, size ? 'r+' : 'w');
    fs.write (file, Buffer.concat (buf), 0, len, start, function (err)
    {
      if (err) request.emit ("error"); else
      {
        if (append) fs.ftruncateSync (file, end); proc_done (response, "", "", local);
      }
      fs.closeSync (file);
    });
  }});
}

//////////////////////////////
///// function: get_file /////
//////////////////////////////

function get_file (request, response, url, local)
{
  var data, stat, size = -1;
  if (url.substr (0,2) == "++") url = url.substr (1);
  if (url.substr (-1) == "+") url = url.substr (0, url.length - 1);
  if (fs.existsSync (data = local_link (url, local))) stat = fs.statSync (data);

  if (stat) url = data; else if (data = local_data (url, ""))
  {
    proc_done (response, data, mime_type (url), 0); return;
  }

  if (stat) if (!stat.isDirectory()) size = stat.size; else try
  {
    data = ""; stat = fs.readdirSync (url, { withFileTypes: true });
    stat.forEach (x => { if (x.isFile()) data += x.name + "\n" });
    proc_done (response, data, "text/plain", local); return;
  } catch { }  // in case read access is restricted

  if (size <= 0) { default_handler (response, 777, local); return; }

  var range, start = 0, end = size - 1, time = Math.trunc (stat.mtimeMs / 1000);

  if (!(range = request.headers ["range"])) size = -size; else
  {
    range = range.substr (range.indexOf ("=") + 1).split ("-");
    start = range [0] * 1 || 0; end = range [1] * 1 || 0;
    if (!range [0]) { start = size - end - 1; end = 0; }
    if (!end || end >= size) end = size - 1;
    if (start > end) start = end;
    if (end < start) end = start;
  }

  if ((data = request.headers ["if-modified-since"]) && time <= data)
  {
    proc_done (response, [0, -1, -2, time], mime_type (url), local); return;
  }

  var stream = fs.createReadStream (url, { start: start, end: end });
  stream.on ("error", function() { default_handler (response, 777, local); });

  stream.on ("open", function()
  {
    proc_done (response, [size, start, end, time], mime_type (url), local);
    stream.pipe (response, {end:true});
  });
}

//////////////////////////////
///// function: get_head /////
//////////////////////////////

function get_head (request, response, url, local)
{
  var stat, size = -1;
  if (url.substr (0,2) == "++") url = url.substr (1);
  if (url.substr (-1) == "+") url = url.substr (0, url.length - 1);
  if (fs.existsSync (url = local_link (url, local))) stat = fs.statSync (url);

  if (stat) if (!stat.isDirectory()) size = stat.size; else try
  {
    stat = fs.readdirSync (url, { withFileTypes: true });
    ++size; stat.forEach (x => { if (x.isFile()) ++size; });
  } catch { }  // in case read access is restricted

  if (size < 0) { default_handler (response, 777, local); return; }

  stat = Math.trunc (stat.mtimeMs / 1000) || "0123456789";
  proc_done (response, [-1, -1, size - 2, stat], mime_type (url), local);
}

/////////////////////////////////
///// function: socket_pool /////
/////////////////////////////////

function socket_pool (sock, conn, name, port, host)
{
  var s, t, m, n = socklist.length - 1;

  if (!sock)
  {
    // find a TLS session ticket
    if (name) for (; n > 0; n -= 3) if (name == socklist [n - 2])
      if ((m = socklist [n]).secure == 1) if (m = m.getSession()) return m;

    // remove outgoing socket and close incoming socket
    if (!name && conn) for (; n > 0; n -= 3)
    {
      if (s = socklist [n - 1], m = socklist [n], m == conn)
      {
        if (!m.idle || m.idle == 2) s.destroy(); m.idle = 3;
        if (s.destroyed) s = sock; else if (sock = s, s = null, !t)
          t = setTimeout (function() { socket_pool (null, conn); }, 15000);
      }
      if (s == sock && m.idle == 3) socklist.splice (n - 2, 3);
    }
    return null;
  }

  if (conn) // replace an existing socket (TLS upgrade)
  {
    for (; n > 0; n -= 3) if (sock == socklist [n]) { socklist [n] = conn; break; }
    conn.secure = 0; conn.time = sock.time; conn.timer = sock.timer; sock.timer = null;
  }
  else if (name && host)
  {
    for (; n > 0; n -= 3)
    {
      s = socklist [n - 1]; m = socklist [n];
      if (m.idle == 1 && name == socklist [n - 2]) conn = m;

      if (s == sock || s.destroyed) if (m == conn || m.share || m.idle == 3)
      {
        socklist.splice (n - 2, 3); if (m == conn) break; if (m.share) m.share--;
      }
    }

    if (!conn || conn.readyState != "open")
    {
      conn = net.createConnection (port ? port : socks_port, port ? host : proxy_addr);
      m = ".." + (socklist.length / 3) + Math.trunc (Math.random() * 10);
      conn.secure = 0; conn.time = Date.now() + (m).substr (-4);
    }
    else if (n < 0) conn.share = (conn.share || 0) + 1;

    socklist.push (name, sock, conn);
  }
  return conn;
}

//////////////////////////////////
///// function: http_handler /////
//////////////////////////////////

function http_handler (request, response)
{
  var refer, referral, head, head1, head2, head3, fix1, fix2;
  refer = referral = head = head1 = head2 = head3 = fix1 = fix2 = "";
  var m, n, p, q, proxy, port, portnum, local = 0, param = {};

  if (!response.socket) { response.end (""); return; }  // SMPlayer/mpv somehow does this

  var method = request.method, ssl = request.socket.encrypted;
  var localhost = "localhost:" + (ssl ? https_port : http_port);
  var shadow = request.headers ["host"] || localhost, shadow_on = shadow;

  var url = request.url; if ((n = url.indexOf ("#")) >= 0) url = url.substr (0, n);
  if ((n = url.indexOf ("?")) < 0) n = url.length; var query = url.substr (n);

  // substitute backslashes (sanity check)
  // Opera and Chrome convert vertical bar to %7C
  url = (url.substr (0, n)).replace (/\\/g, "/").replace (/%7C/g, "|");

  if (url [0] == "/") url = url.substr (1); else if (shadow [0] != "@")
    if (m = url.match (/\bhttp(s?):\/\/[^\/]*\/?(.*)/)) { ssl = m[1] != ""; url = m[2]; }

  if (shadow [0] == "[" && (n = shadow.indexOf ("]") + 1))
  {
    p = shadow.substr (1, n - 2); q = shadow.substr (n); n = q.lastIndexOf (":");
    shadow_on = p + ":" + (q.substr (n + 1) || (ssl ? "443" : "80"));
  }
  else if (!shadow.includes (":")) shadow_on += ssl ? ":443" : ":80";

  if (n = scratch.indexOf (" " + shadow_on) + 1) shadow_on = "?." + scratch [n];

  if (!n && net.isIP (shadow_on.substr (0, shadow_on.lastIndexOf (":"))))
  {
    p = request.socket; if (!(q = p.localAddress).indexOf ("::ffff:")) q = q.substr (7);
    shadow_on = (q + ":" + p.localPort == shadow_on) ? localhost : "?." + shadow_on;
  }

  if (url [0] == "@" && !shadow_on.includes ("."))
  {
    m = url.split ("@"); m[0] = query; n = m[1] == shadow_secret;

    if (url == "@" || m[2] == "") if (n) m = shadow_list(); else
    {
      console.log (shadow_host); m = " See the console for your info.";
    }
    else m = m.length < 3 ? "" : " " + shadow_proc (m);

    if (m) { proc_done (response, m, "text/plain", 0); return; }
  }

  if ((n = shadow_on.indexOf (".localhost:")) > 0)
    if (m = shadow_on.substr (0, n).split (".")[0]) shadow_on = m;

  if (url [0] == "$" && (n = url.indexOf ("$", 1) + 1) > 2)
  {
    p = url.substr (1, n - 2); q = url.substr (url [n] == "/" ? n + 1 : n);

    if (!p.includes (".") && !shadow_on.includes ("."))
    {
      shadow_on = p; url = q; shadow += "/$" + p + "$";  // for location header
    }
  }

  n = shadow_on; shadow_on = ""; if (!n.includes (":")) n += ssl ? ":443" : ":80";
  if (n[0] == "?") n = n.substr (2); if (shadow [0] == "@" || n == localhost) n = "";

  if (n) if (!(m = shadow_port (n)))
  {
    url = "*null*|*" + (ssl ? "https://" : "http://") + shadow + "/" + url;
    if (shadow.substr (-1) == "$") url = query = ""; else shadow = "@";
  }
  else
  {
    shadow_on = request.headers ["origin"] || "*";
    p = n.substr (0, n.indexOf (":")); q = "@" + p + "/" + url;
    if (q = shadow_host [q.substr (-1) == "/" ? q : q + "/"]) m = q;

    if (m[0] == "@" && (n = m.indexOf ("@", 1) + 1))
    {
      q = query.replace (m.substr (0, n), "$$" + shadow_secret + "$$");
      m = m.substr (n); if (q != query) { m = ""; query = q; }
    }
    if (m[0] == "$" || m[0] == ";") m = m.substr (1); if (m) local = 8;

    if (m[0] == "(" && m[1] == "/" && (n = m.indexOf (")") + 1))
    {
      q = m.substr (1, n - 2); if (q.substr (-1) != "/") q += "/";
      m = (shadow_host ["@" + q] || "") + m.substr (n);
    }
    if (m[0] == "(" && m[1] != "/" && (n = m.indexOf (")") + 1))
    {
      q = m.substr (1, n - 2); m = m.substr (n);
      if (q && url == "favicon.ico") { url = ""; m = q; }
    }
    if (m[0] == "/") { url = ""; m = m.substr (1); }

    if (n = m.indexOf ("?") + 1)
    {
      q = m.substr (n); m = m.substr (0, n - 1);
      query = query.length > 1 ? "&" + query.substr (1) : "";
      query = (!q || q[0] == "?") ? q : "?" + q + query;
    }

    if (m = m.replace (/\$\$\$/g, p).replace (/&&/g, "?"))
    {
      if (url && m.substr (-1) != "/") m += "/"; url = m + url;
    }
  }

  if (n = query.indexOf ("$" + (m = shadow_secret) + "$") + 1)
  {
    url = query.substr (n + m.length + 1); n = url.indexOf ("?");
    if (n < 0) n = url.length; query = url.substr (n); url = url.substr (0, n);

    if (url || query) { local = 0; shadow_on = ""; } else
    {
      m = request.headers ["cookie"]; n = request.headers ["origin"];
      proc_done (response, "**" + (m || "null"), "text/plain", n || "*"); return;
    }
  }

  if (!url)
  {
    proxy_command (request, response, query); return;
  }

  if (url [4] == "/") if (!url.indexOf ("ipfs") || !url.indexOf ("ipns"))  // IPFS local gateway
  {
    shadow = "@" + proxy_addr; url = "http://localhost:" + ipfs_port + "/" + url;
  }

  if (shadow [0] != "@")
  {
    shadow = (ssl ? "https://" : "http://") + shadow;
    if (local != 8 || shadow.substr (-1) == "$") local += 4;
    m = "~"; n = url[0] != m ? 0 : (url[1] != m ? 1 : (url[2] != m ? 2 : 3));
    local += (n + 1) & 3; referral = url.substr (0, n); url = url.substr (n);
  }

  if (method == "OPTIONS" && local & 4)
  {
    options_proc (request, response); return;
  }

  if (local & 1)
  {
    if ((m = url.length) > 200) m = 200;
    if ((n = query.length) + m > 220) n = 220 - m;
    p = url.substr (0, m); if (p.length < url.length) p += "...";
    q = query.substr (0, n); if (q.length < query.length) q += "...";
    console.log ((shadow_on ? "@" : ">") + method + " " + p + q);
  }

  if (url [0] == "*")
  {
    url = url.substr (1); n = url.indexOf ("*") + 1;
    if (n) { refer = url.substr (0, n - 1); url = url.substr (n); }
    referral += "*" + refer + "*"; if (!refer) refer = "*";
  }

  if ((n = url.indexOf ("|*")) >= 0)
  {
    head = url.substr (0, n).split ("|"); head.unshift ("|"); url = url.substr (n + 2);
  }
  else if ((n = url.indexOf ("~*")) >= 0)
  {
    head = url.substr (0, n).split ("~"); head.unshift ("~"); url = url.substr (n + 2);
  }
  if (url [0] == "/") url = url.substr (1);

  if (url [0] == "!")  // for DASH videos
  {
    if ((n = url.indexOf ("/")) < 0) n = url.length; q = url.substr (n + 1);
    if (p = local_data (url.substr (1, n - 1), "").replace (/[^\x21-\x7E]/g, ""))
    {
      if ((n = p.indexOf ("?")) < 0) n = p.length; url = p.substr (0, n);
      if (p = p.substr (n)) query = p + (query ? "&" + query.substr (1) : "");
      if (q.includes ("/")) url += q; else query += q;
    }
  }

  if (!url.includes (":") && (m = safe_decode (url)))
  {
    if (m.search (/[:?*\\]/) >= 0) default_handler (response, 888, local);
    else if (method == "GET")  get_file (request, response, m, local);
    else if (method == "HEAD") get_head (request, response, m, local);
    else if (method == "PUT")  put_file (request, response, m, local);
    else if (method == "POST") crazycat (request, response, m, local, shadow);
    else default_handler (response, 888, local); return;
  }

  if ((n = url.indexOf ("://") + 3) > 8 || n < 3) n = 0;
  var origin = url.substr (0, n), host = url.substr (n);

  if ((n = host.indexOf ("/")) < 0) n = host.length;
  url = "/" + host.substr (n + 1); host = host.substr (0, n); 

  if (shadow [0] != "@" && (n = host.indexOf ("@") + 1))
  {
    p = host.substr (n); host = host.substr (0, n - 1);
    if ((n = p.lastIndexOf ("+")) < 0) n = p.length; m = p.substr (0, n);
    n = safe_numero (p.substr (n + 1)); referral += " @" + p + " ";

    if (!(port = n)) port = m || undefined; else
    {
      url = origin + host + (m ? "@" + m : "") + url; ssl = origin = "";
    }
    if (!origin) origin = ssl ? "https://" : "http://";
    if (!host) host = "localhost:" + (n || (ssl ? https_port : http_port));
  }

  var myheader = request.headers, cookie = myheader ["accept"];
  if (local & 4) delete myheader ["cookie"]; else cookie = "";
  myheader ["host"] = host; p = origin; origin += host;

  if (host [0] == "[" && (n = host.indexOf ("]") + 1))
  {
    m = host.substr (n); host = host.substr (1, n - 2);
    portnum = safe_numero (m.substr (m.lastIndexOf (":") + 1));
  }
  else if (n = host.lastIndexOf (":") + 1)
  {
    portnum = safe_numero (host.substr (n)); host = host.substr (0, n - 1);
  }

  if (p == "http://")  { proxy = http;  portnum = portnum || 80; }
  if (p == "https://") { proxy = https; portnum = portnum || 443; }

  if (!host || !proxy)
  {
    default_handler (response, 999, local); return;
  }

  if (refer [0] == "~")  // remove all but critical headers
  {
    var h = myheader; myheader = {}; refer = refer.substr (1) || "*";

    for (n = 0; n < camel_case.length; n += 2)
      if ((p = camel_case [n]) && (q = h [p])) myheader [p] = q;
  }

  if (n = refer.indexOf (",") + 1)  // for m3u8 videos
  {
    m = refer.split (","); refer = m[0] || "*"; fix1 = m[1]; fix2 = m[2] || "";

    if (n = url.lastIndexOf (".") + 1) if (m = url.substr (n))
    {
      if (m.substr (0,3) == "m3u" || m == fix1) local += 16;
      if (m == fix1 || m == fix2) url = url.substr (0, n - 1);
      if (m = mime_list [m]) head3 += "content-type\n" + m + "\n";
      if (local & 16) myheader ["accept-encoding"] = "gzip";
    }
  }

  if (refer != "null")
  {
    p = q = (refer != "/" ? (refer != "*" ? refer : origin + "/") : "");
    n = p.indexOf ("/", p.indexOf ("//") + 2); if (n > 0) p = p.substr (0, n);
    if (p) { myheader ["origin"] = p; myheader ["referer"] = q; }
      else { delete myheader ["origin"]; delete myheader ["referer"]; }
  }

  if (!cookie || cookie.substr (0,2) != "**") cookie = ""; else
  {
    p = cookie.split ("**"); if (p.length > 2) p.shift(); q = p.shift() || "*/*";
    p = p.join ("**"); if (q == "/" && (q = "**" + p)) p = ""; if (!p) p = "null";
    if ((cookie = p) != "null") myheader ["cookie"] = p; myheader ["accept"] = q;
  }

  if (head) for (var i = head.length - 1, j, k, f, g, h; i > 0; i--)
  {
    f = head [i]; if (f[0] == "/") f = f.substr (1);
    if (!f) continue; head1 = f + head [0] + (head1 ? head1 : "*");
    j = f.indexOf ("="); k = f.indexOf (":"); if (k < 0) k = f.length;

    if (j < 0 || k < j) if (f.replace (/[\x21-\x7E]/g, "")) continue; else
    {
      if (f[0] != "!") head2 = f + (head2 ? ", " : "") + head2; else
      {
        g = f.substr (1, k - 1); h = f.substr (k + 1); param [g] = h;
      }
      continue;
    }

    g = f.substr (0, j); h = f.substr (j + 1);
    f = h[0] == "!" ? safe_decode (h.substr (1)) : h;

    if (f.replace (/[\x20-\x7E]/g, "") || !g) continue;
    if (g.replace (/[a-z\d\-\+\_\.\!\~\*\$\&\%]/gi, "")) continue;

    if (g[0] == "!") head3 = g.substr (1) + "\n" + h + "\n" + head3; else
      if (f) myheader [g] = f; else if (g != "host") delete myheader [g];
  }

  ssl = false; head = host; url += query; query = myheader ["content-length"] || 0;

  ///// CONNECTING TO THE INTERNET /////

  if (shadow [0] == "@")
  {
    // for IPFS or DNS-over-HTTPS (can also be used by non-browser apps)
    m = shadow.substr (1); shadow = refer = ""; if (m) { port = portnum; host = m; }
  }
  else
  {
    // access key (needed for shadow port but not shadow fork)
    n = (m = param ["key"]) ? url.match ("\\$" + m + "\\$(([^$]*)\\$)?/?") : "";
    if (n) url = url.replace (n[0], ""); else if (m != "" && !(local & 4)) shadow_on = "@";

    refer = (n ? n[2] : !(local & 8) && m) || "";  // for probing the socks5 port
    head1 = local & 8 ? (n ? n[0] : "") : referral + head1;  // for location header

    if (m && m[0] == "!") if (n = myheader ["cookie"]) local_data ("/" + m, "**" + n);

    if (typeof (port) != "string") { if (port) host = proxy_addr; } else
    {
      p = port; n = p.lastIndexOf (":"); port = safe_numero (q = p.substr (n + 1));
      ssl = true; host = (n < 0 ? (port ? proxy_addr : q) : p.substr (0, n)) || host;
    }

    // don't pass localhost through the socks5 port and check for shadow port loopback
    if (host == proxy_addr || host.substr (host.lastIndexOf (".") + 1) == "localhost")
    {
      host = proxy_addr; n = port || (port = portnum); ssl = !!refer;
      if (shadow_on) if (n == http_port || n == https_port) myheader ["host"] = localhost;
    }
  }

  if (m = param ["mock"])
  {
    n = parseInt (m) & 3; if (m.includes ("X")) n += 4;
    if (m.includes ("A")) n += 8; local += n << 5;
  }

  if (local & 96 && !(local & 128))
  {
    var h = {};

    if (local & 32) for (n = 0; n < camel_case.length; n += 2)
    {
      q = camel_case [n + 1]; p = camel_case [n];
      if (!q || (m = myheader [p]) == undefined) continue;
      delete myheader [p]; h [local & 128 ? p : q] = m;
    }
    if (local & 64) for (n = 0; n < request.rawHeaders.length; n += 2)
    {
      q = request.rawHeaders [n]; p = q.toLowerCase();
      if ((m = myheader [p]) == undefined) continue;
      delete myheader [p]; h [local & 128 ? p : q] = m;
    }
    myheader = Object.assign (h, myheader);
  }

  n = local & 1 ? ++reqcount : 0; m = param ["vpx"] || "";
  if (q = m) m = m.replace (m.includes ("+") ? /\+/g : /:/g, " ");

  p = " @" + (host == proxy_addr ? port : host + ":" + (port || portnum));
  var name = origin + "/" + refer + (port == undefined ? "" : p) + " " + q;
  var conn = socket_pool (request.socket, null, name, ssl ? 0 : port, host);

  var config = {
    count: n, method: method, host: origin, path: url, origin: shadow_on, shadow: shadow,
    cookie: cookie, headers: head1, exposes: head2, mimics: head3, fix1: fix1, fix2: fix2
  }

  var options = {
    method: method, path: url, headers: myheader, socket: conn, settings: {enablePush:false},
    servername: net.isIP (head) ? "" : head, rejectUnauthorized: m.substr (-1) == " "
  }
  if (local & 128) options.ALPNProtocols = ['h2', 'http/1.1'];
  if (local & 256) options.secureContext = secureContext;

  n = param ["timeout"]; if (n) n *= 1000; if (!n) n = -30000;
  if (n > 0 && n < 5000) n = 5000; if (n < 0 && n > -5000) n = -5000;

  if (!conn.connecting)
  {
    config.dnsr = "@"; init_request(); return;
  }

  conn.on ("close", function()
  {
    socket_pool (null, conn); clearTimeout (conn.timer); conn.destroy();
  });

  conn.timer = setTimeout (function() { oopsie(); }, n < 0 ? -n : n);

  if (port && !ssl)
  {
    config.dnsr = "LOCAL"; init_request(); return;
  }

  conn.write ("CONNECT " + host + ":" + (port || portnum) + " HTTP/!!! !" + refer + " " + m);

  conn.once ("data", function (d)
  {
    d = d.toString().split (" "); if (d[2] == "OK") d[2] = "";
    config.dnsr = d[2]; if (d[1] != "200") oopsie(); else init_request();
  });

  function init_request ()
  {
    if (conn.idle) create_request(); else if (proxy == https)
    {
      options.session = socket_pool (null, null, name);
      conn = socket_pool (conn, tls.connect (options));

      conn.once ("secureConnect", function()
      {
        p = program ["*" + head + ":" + portnum];
        q = p && conn.getPeerCertificate().pubkey;
        q = q && crypt.createHash('md5').update(q).digest();

        if (q && p.compare (q) && !options.rejectUnauthorized)
        {
          m = p.length ? "HTTPS certificate mismatch!" : q.toString ('hex');
          proc_done (response, m, "text/plain", local); conn.destroy(); return;
        }
        conn.secure = conn.alpnProtocol == "h2" ? 2 : 1; create_request();
      });

      conn.on ("error", function() { if (conn.idle == undefined) oopsie(); });
    }
    else
    {
      conn.on ("error", function() { if (conn.idle == undefined) oopsie(); });

      if (!conn.connecting) create_request(); else
        conn.once ("connect", function() { create_request(); });
    }
  }

  function create_request ()
  {
    clearTimeout (conn.timer); options.createConnection = function() { return conn; }

    try { if (conn.secure < 2) proxy = proxy.request (options); else
      {
        if (!(proxy = conn.session))
        {
          proxy = conn.session = http2.connect (origin, options); proxy.on ("error", function() { });
        }
        Object.assign (myheader, {
          ':method': method, ':path': url, ':authority': head + ":" + portnum, ':scheme': "https" });

        delete myheader ["host"]; delete myheader ["connection"];
        if (proxy.count) proxy.count++; else proxy.count = 1; proxy = proxy.request (myheader);
      }
    } catch(e) { console.log ("@ " + e.message); oopsie(); return; }

    proxy.on ("response", function (res)
    {
      if (conn.session)
      {
        proxy.statusCode = res [":status"]; delete res [":status"];
        proxy.statusMessage = ""; proxy.headers = res; res = proxy;
      }

      res.on ("end", function()
      {
        if (!conn.session || !--conn.session.count) if (!conn.destroyed)
          { conn.idle = 1; conn.timer = setTimeout (function() { conn.end(); }, 30000); }
      });

      proc_handler (response, res, config, local);
    });

    proxy.on ("upgrade", function (res, xx, buf)  // for websocket
    {
      var sock = response.socket; if (buf.length) conn.unshift (buf);
      conn.idle = 2; proc_handler (response, res, config, local + 1024);
      conn.pipe (sock, {end:true}); sock.pipe (conn, {end:true});
    });

    proxy.on ("error", function() { oopsie(); });
    proxy.setTimeout (n > 0 ? n : 180000, function() { oopsie(); });
    response.on ("close", function() { if (!conn.idle) oopsie(); });
    conn.idle = conn.session ? 1 : 0; request.pipe (proxy, {end:true});

    if (config.key = refer) program ["?" + refer] = query;
    if (local & 4) { keepheaders = myheader; keeprequest = origin + url; }
  }

  function oopsie ()
  {
    default_handler (response, 666, local); conn.destroy();
  }
}

//////////////////////////////////
///// function: proc_handler /////
//////////////////////////////////

function proc_handler (response, res, config, local)
{
  var m, n, s, v, header = {}, status = res.statusCode, message = res.statusMessage;

  if (!config.shadow)  // IPFS or DNS-over-HTTPS
  {
    response.writeHead (status, message, res.headers);
    res.pipe (response, {end:true}); return;
  }

  if (local & 1)
  {
    last_time = 0; n = config.count; s = (s = config.dnsr) ? " - " + s : "";
    console.log (" Request " + n + " - Status " + status + " (" + message + ")" + s);
  }
  else
  {
    passthru++; m = Date.now() / 1000; n = last_pass == config.host ? 30 : 20;

    if (last_time <= m - n)
    {
      last_time = m; last_pass = config.host; s = config.dnsr;
      console.log ("<Passthrough " + passthru + " - " + last_pass + (s ? " - " + s : ""));
    }
  }

  if (local & 1024)  // websocket
  {
    response.writeHead (status, message, res.headers); stream_end (response, ""); return;
  }

  if (local & 2 || config.method == "OPTIONS") Object.assign (header, res.headers); else
  {
    var header_name = [
      "connection", "date", "location", "accept-ranges",
      "access-control-allow-origin", "access-control-allow-credentials",
      "content-type", "content-encoding", "content-length", "content-range",
      "zz-location", "zz-set-cookie" ];

    v = config.exposes.replace (/\s/g, "");
    if (v) header_name = header_name.concat (v.split (","));
    for (s of header_name) if (v = res.headers [s]) header [s] = v;
  }

  if (config.mimics)
  {
    m = config.mimics.split ("\n");
    for (n = 0; n < m.length; n++) if (s = m[n++])
    {
      if ((v = m[n])[0] == "!") v = safe_decode (v.substr (1));
      if (v) header [s] = v; else delete header [s];
    }
  }

  if ((v = config.origin) != "@")
  {
    header ["zz-proxy-server"] = proxy_name;
    header ["access-control-allow-origin"] = v = v || "*";
    if (v != "*") header ["access-control-allow-credentials"] = "true";
  }

  if (v = header [s = "location"])
  {
    var x = config.host, y = v.substr (0,2), z = config.shadow + "/";
    if (y [0] == "/") v = (y != "//" ? x : x.substr (0, x.indexOf (y))) + v;

    if (v.indexOf ("http:") && v.indexOf ("https:"))
    {
      y = config.path.split ("?")[0].split ("/");
      y [y.length - 1] = v; v = x + y.join ("/");
    }

    if (!(local & 4))
    {
      if ((n = v.indexOf ("?")) < 0) n = v.length; y = v.substr (0, n).split ("/");
      z += y.slice (3).join ("/") + v.substr (n); y = y.slice (0,3).join ("/");
      if (x != y) z = v; else { v = z; z += config.headers; }
    }
    else if ((y = config.headers.split (" ")).length < 3) z += y[0] + v; else
    {
      x = v.split ("/"); x[2] += y[1]; z += y[0] + y[2] + x.join ("/");
    }

    x = local & 16 ? config.fix1 : config.fix2;
    if (x) { y = z.split ("?"); y[0] += "." + x; z = y.join ("?"); }

    if (!config.cookie) header [s] = z; else
      { delete header [s]; header ["zz-location"] = v; }
  }

  s = "set-cookie"; if (local & 4) delete header [s];
  if (config.cookie && (v = res.headers [s])) header ["zz-set-cookie"] = v;
  if (config.key) program ["?" + config.key] = header ["content-length"] || 0;

  s = "access-control-expose-headers"; v = header [s] || "";
  if (config.cookie)  v = v + (v ? ", " : "") + "zz-location, zz-set-cookie";
  if (config.exposes) v = v + (v ? ", " : "") + config.exposes; if (v) header [s] = v;

  if (!(local & 16))
  {
    response.writeHead (status, message, header);
    res.pipe (response, {end:true}); return;
  }

  var proc = res; m = []; n = 0; v = header ["content-encoding"];
  if (v == "gzip") { proc = zlib.createGunzip(); res.pipe (proc); }

  proc.on ("error", function () { default_handler (response, 777, local); });

  proc.on ("data", function (data)
  {
    if ((n += data.length) < 3000000) m.push (data);
  });

  proc.on ("end", function ()
  {
    m = tweak_m3u8 (Buffer.concat (m), config);
    header ["content-encoding"] = "identity"; header ["content-length"] = m.length;
    response.writeHead (status, message, header); stream_end (response, m);
  });
}

///////////////////////////////////
///// function: proxy_command /////
///////////////////////////////////

function proxy_command (request, response, cmd)
{
  var m, n, p, q, msg, str, xtra, setdns = "";

  n = request.method == "GET"; cmd = cmd.replace (/\s|%20/g, "");

  if (n && cmd && request.headers ["upgrade"] == "websocket")
  {
    websocket (request, response, cmd.substr (1)); return;
  }

  m = (cmd.substr (1) + "==").split ("="); cmd = m[0]; str = m[1]; xtra = m[2];
  m = cmd.split ("+"); cmd = m[0]; msg = "Command: " + cmd + " " + str + " " + xtra;

  if (!n || !cmd || (tinfoil && tinfoil != "+" + (m[1] || "")))
  {
    default_handler (response, n ? 200 : 888, 0); return;
  }

  if (cmd == "vpn")
  {
    cmd = ""; m = str.split (str.includes ("+") ? "+" : ":");

    if (!vpnlock || xtra == shadow_secret) if (str)
    {
      vpn_host = m[0]; vpn_port = safe_numero (m[1]);
      if (!net.isIP (vpn_host) || !vpn_port) vpn_host = vpn_port = "";
      vpn_name = safe_decode (m[2]); vpn_pass = safe_decode (m[3]);
    }

    if (!vpn_host) { vpnlock = false; str = "VPN - invalid or none"; } else
    {
      if (xtra == shadow_secret) vpnlock = true;
      m = " (" + vpn_name + ":" + vpn_pass + ")" + (vpnlock ? " LOCKED" : "");
      str = "VPN - " + vpn_host + " - port " + vpn_port + m;
    }
  }

  if (cmd == "restart")
  {
    if (str.search (/[:?*/]/) < 0) cmd = "";
    m = (str + "+").replace (/,/g, "+").split ("+");
    if (!cmd) console.log ("@ " + (str = start_servers (m[0], m[1])));
  }

  if (cmd == "probe")
  {
    if ((p = str) != shadow_secret)
    {
      if (q && program ["?" + p] != undefined) program ["?" + p] = q;
      q = program ["#" + p] || 0; p = program ["?" + p] || 0;
      msg = " " + q + " " + p + " = sent/total";
    }
    else
    {
      msg = str = ""; if (keeprequest) msg = " " + keeprequest + "\n\n";
      for (m in keepheaders) msg += " " + m + ": " + keepheaders [m] + "\n";

      for (n = 0; n < socklist.length; n += 3) if (m = socklist [n + 2])
        str += " [" + (m.idle == undefined ? "-" : m.idle) + "] " + m.time + " " + socklist [n] + "\n";

      msg = " Sockets: " + socklist.length / 3 + "\n\n" + str + (str ? "\n" : "") + msg;
    }

    proc_done (response, msg, "text/plain", 0); return;
  }

  if (cmd == "flags")
  {
    cmd = ""; n = safe_numero (str); //console.log (global);
    if (str) { proxy_flags = n & 31; if (xtra == shadow_secret) proxy_flags += 32; }

    str = "Console output is " + (proxy_flags & 1 ? "enabled" : "disabled");
    if (proxy_flags & 16) str += "\n> showing " + (proxy_flags & 1 ? "socket" : "DNS/DoH") + " activity";
    str += "\n\nExpecting TOR at port " + (proxy_flags & 2 ? tor2_port : tor1_port);
    if (proxy_flags & 4) str += "\n> TOR is enabled for ALL"; if (vpnlock) str += "\n> VPN is LOCKED";
  }

  if (cmd == "reload")
  {
    cmd = "="; if (!str) str = settings; n = profile_count;
    console.log ("@ " + init_settings (str) + " (" + str + ")");
    if (n != profile_count) add_resolver ("");
  }

  if (cmd == "activate")
  {
    cmd = "="; p = str.replace (/,/g, "+").split ("+");
    for (q of p) if (q || !str) add_resolver (q);
  }

  if (cmd == "servers") { setdns = str; cmd = "="; }

  if (cmd == "dnslookup" && xtra) { setdns = str; str = xtra; }

  p = dns_servers (setdns); q = doh_address ? "\n DoH  " + doh_address + "\n" : "\n";
  if (!p.length) q = " DNS lookup in progress!\n   Please try again...\n";
  for (n = 0; n < p.length; n++) q += " DNS" + (n + 1) + " " + p[n] + "\n";

  p = "_".repeat ((n = msg.length) < 25 ? 25 : n);
  msg += "\n" + p + "\n" + q + p + "\n";

  if (cmd == "=")
  {
    cmd = ""; str = init_fetch() + "\n\n";

    for (n = 0; n < iplist.length; n += 2)
    {
      p = iplist [n + 1]; if (!p) p = "FETCH";
      q = p.split (" "); p = q.splice (0,1)[0]; q = q.join ("+");
      m = 30 - p.length; m = " " + p + " " + (m > 0 ? '-'.repeat (m) : "");
      str += m + "-- " + iplist [n] + (q ? " [" + q + "]" : "") + "\n";
    }

    if (xtra == shadow_secret) str += "\nShadow Ports:\n\n" + shadow_list(); else
    {
      p = ""; q = Object.entries (program);
      for (m of q) if (m[0][0] == "*") p += " " + m[1].toString ('hex') + "  " + m[0].substr (1) + "\n";
      str += "\nCertificates Pinned:" + (p ? "\n\n" + p : " none\n");
    }
  }

  if (cmd == "dnslookup")
  {
    if ((n = str.indexOf ("//")) >= 0) str = str.substr (n + 2);
    if ((n = str.indexOf ("/"))  >= 0) str = str.substr (0, n);

    if (cmd = "", str)
    {
      function res (err, addr)
      {
        if (!err) for (n of addr) cmd += " " + n + "\n";
        n = m; m = 1; if (n && !cmd) cmd += " Not resolved\n";
        if (n) proc_done (response, msg + cmd, "text/plain", 0);
      }

      if (m = net.isIP (str)) dns.reverse (str, res); else
        { dns.resolve4 (str, res); dns.resolve6 (str, res); }

      msg += "\n " + str + "\n\n"; return;
    }
  }

  proc_done (response, msg + "\n" + (cmd ? "What?" : str) + "\n", "text/plain", 0);
}

///////////////////////////////////
///// function: proxy_handler /////
///////////////////////////////////

function proxy_handler (sock)
{
  var m, n, p, q, host, port, addr, conn, data, done = 5, time = 0;
  var vpn, nix, http, vhost = "", vport = "", vname = "", vpass = "";
  var key, ssl, pin, chain, socket = ++sockets_count; ++sockets_open;

  sock.on ("error", function() { });
  sock.on ("close", function() { socks_report (0, 1, --sockets_open); socks_abort(); });
  sock.on ("end",   function() { });  // this callback is needed for the "close" event

  sock.once ("data", function (r) { socks_phase_1 (r); });

  function socks_abort ()
  {
    if (nix)
    {
      n = scratch.indexOf (nix); if (n >= 0) scratch.splice (n, 2); nix = "";
    }

    if (!done && time && key)
    {
      clearInterval (time); delete program ["#" + key]; delete program ["?" + key];
    }

    if (!done || sock.readyState != "open")
    {
      if (conn) conn.destroy(); sock.destroy(); done = 0; return;
    }

    if (time < Date.now())
    {
      if (done == 1) m = Buffer.from ("\5\4\0\0"); else
      if (done >= 2) m = "HTTP/1.1 500 No Connection\r\n\r\n"; else m = "";

      sock.end (m); sock.destroy(); return;
    }

    // kickstart a stubborn server but just this once
    setTimeout (function() { socks_phase_4 (""); }, 3000);

    time = 1; conn.destroy(); conn = null; socks_report (0, 3, vhost + ":" + vport);
  }

  function socks_phase_1 (d)
  {
    // if (d.length == 3 && d[0] == 5 && d[1] == 1 && d[2] == 0)
    // version 5a: changed because curl sends \5\2\0\1 (browser sends \5\1\0)

    if (d.length > 2 && d[0] == 5 && d[1] == d.length - 2)
    {
      sock.once ("data", function (r) { socks_phase_2 (r); });
      done = 1; sock.write (Buffer.from ("\5\0")); return;
    }

    p = d.toString().match (/(.*) (.*) (HTTP\/[^ ]*) ?(.*)/);
    q = (p && p[2]) ? p[2].split ("/") : [""]; host = q[0];
    if (host.substr (-1) == ":") host = q[2] || "";

    if (host [0] == "[" && (n = host.indexOf ("]") + 1))
    {
      m = host.substr (n); host = host.substr (1, n - 2);
      port = safe_numero (m.substr (m.lastIndexOf (":") + 1));
    }
    else if (n = host.lastIndexOf (":") + 1)
    {
      port = safe_numero (host.substr (n)); host = host.substr (0, n - 1);
    }

    if (!host || !p[1] || !p[3]) { socks_abort(); return; }

    if (p[1] != "CONNECT") { done = 4; data = d; port = port || 80; } else
    {
      m = p[4] ? p[4].split (" ") : [""];
      port = port || 443; done = p[3] == "HTTP/!!!" ? 2 : 3;
      key = (done == 2 && m[0][0] == "!") ? m[0].substr (1) : "";

      if (m[1] || m[2]) if (done == 2)
      {
        vport = safe_numero (m[2]); if (m[5] || m[6]) chain = m.slice (4);
        if (!net.isIP (vhost = m[1]) || !vport) { socks_abort(); return; }
        vname = safe_decode (m[3]); vpass = safe_decode (m[4]);
      }
    }

    socks_phase_3 ("");
  }

  function socks_phase_2 (d)
  {
    if (d.length > 7 && d[0] == 5 && d[1] == 1)
    {
      if (d[3] == 1 && (n = 8) < d.length - 1) host = d[4] + "." + d[5] + "." + d[6] + "." + d[7];
      if (d[3] == 3 && (n = d[4] + 5) < d.length - 1) host = d.toString ('utf8', 5, n);
      if (d[3] == 4 && d.length > 21) for (n = 4; n < 20; n += 2)
        host = (host ? host + ":" : "") + d.readUInt16BE (n).toString (16);
    }

    if (!host || !(port = d.readUInt16BE (n))) socks_abort(); else socks_phase_3 ("");
  }

  function socks_phase_3 (d)
  {
    m = done == 2 ? "" : host + ":" + port;

    if (m) if (pin = program ["*" + m], m = shadow_port (m))
    {
      if (m[0] == "@" && (n = m.indexOf ("@", 1) + 1))
      {
        p = m.substr (1, n - 2); m = m.substr (n);
        if (p[0] == "$") { p = p.substr (1); ssl = m[0] == "$"; }
        n = p.lastIndexOf (":"); vport = safe_numero (q = p.substr (n + 1));
        p = n < 0 ? q : p.substr (0, n); if (net.isIP (p)) vhost = p;
      }

      m = m[0] == "$" ? https_port : http_port;
      vport = vport || (vhost ? port : m); vhost = vhost || proxy_addr;
      socks_report (0, 0, vpn = "@SHD"); socks_phase_4 (d); return;
    }
    else if (done == 4 || proxy_flags & 32 || (pin && !pin.length))
    {
      vhost = "0.0.0.0"; vport = http_port;
      socks_report (0, 0, vpn = "@SHD"); socks_phase_4 (d); return;
    }

    if ((addr = dns_resolve (host, vhost && vport)).includes (" "))
    {
      m = addr.split (" "); addr = m[0];

      if (m[1] || m[2])
      {
        vhost = m[1]; vport = safe_numero (m[2]);
        if (!net.isIP (vhost) || !vport) { socks_abort(); return; }
        vname = safe_decode (m[3]); vpass = safe_decode (m[4]);
      }
      else { addr = addr.substr (5); if (done != 2 && m[3] == "") http = false; }
    }

    socks_report (0, 0, addr); vpn = addr [0] == "@" ? addr.substr (1,3) : "";
    dns_lookup (addr, host, function (ip) { addr = ip; socks_phase_4 (d); });
  }

  function socks_phase_4 (d)
  {
    if (addr && (p = shadow_host [q = addr + ":$"]))
    {
      vpn = "NIX"; nix = " " + host + ":" + port; scratch.push (nix, q);
      vhost = "0.0.0.0"; vport = http_port; if (p.length < 2) addr = vhost;
    }

    if (sockmon && !time) socks_report ("sockmon");
    if (addr == "0.0.0.0" || addr == "0.0.0.1") { socks_abort(); return; }
    if (!time) time = Date.now() + 12000;

    if (d = "", !vpn || vpn == "vpn") { vhost = addr; vport = port; } else
    {
      if (vpn == "TOR")
      {
        vhost = proxy_addr; vport = proxy_flags & 2 ? tor2_port : tor1_port;
      }
      if (vpn == "VPN")
      {
        vhost = vpn_host; vport = vpn_port; vname = vpn_name; vpass = vpn_pass;
      }
      if (addr == "I2P")
      {
        vhost = "0.0.0.1"; vport = i2p_port; vpn = addr;
      }

      if (vhost == "0.0.0.0" || (vname == "!" && vpass == "!"))
      {
        http = true; if (vhost == "0.0.0.0") vhost = proxy_addr; ssl = false;
      }
      if (vhost == "0.0.0.1" || (vname == "!" && vpass == "$"))
      {
        http = true; if (vhost == "0.0.0.1") vhost = proxy_addr; ssl = done != 2;
      }

      if (!http && vpn != "@SHD") make_addr (addr, port);
    }

    if (chain)
    {
      p = chain [1]; q = (chain [0] = d) ? safe_numero (chain [2]) : 0;
      make_addr (p, q); if (!net.isIP (p) || !q) { time = 0; socks_abort(); return; }
    }

    conn = net.createConnection (vport, vhost, function() { socks_phase_5 (d); });
    conn.on ("error", function (e) { socks_report (e.code, addr == host ? "" : addr, host); });
    conn.on ("close", function ( ) { if (conn == this) { socks_report (0, 2); socks_abort(); }});
    conn.on ("end",   function ( ) { });  // this callback is needed for the "close" event

    function make_addr (addr, port)
    {
      if (!net.isIP (addr))
      {
        d = Buffer.from ("\5\1\0\3\0" + addr + "\0\0");
        n = addr.length; d[4] = n; d.writeInt16BE (port, n + 5);
      }
      else if (addr.includes ("."))  // ipv4
      {
        m = addr; d = Buffer.from ("\5\1\0\1\0\0\0\0\0\0"); d.writeUInt16BE (port, 8);
        if ((n = m.lastIndexOf (":")) > 0) m = m.substr (n + 1); m = m.split (".");
        d[4] = m[0] * 1; d[5] = m[1] * 1; d[6] = m[2] * 1; d[7] = m[3] * 1;
      }
      else  // ipv6
      {
        d = Buffer.alloc (22); m = addr.split (":"); n = m.length;
        if (n < 8) m = addr.replace ("::", ":".repeat (10 - n)).split (":");
        for (n = 0; n < 8; n++) d.writeUInt16BE (parseInt (m[n], 16), n + n + 4);
        d[0] = 5; d[1] = 1; d[3] = 4; d.writeUInt16BE (port, 20);
      }
    }
  }

  function socks_phase_5 (d)
  {
    // check for loopback (addresses are equal if outgoing socket is local)
    // this accounts for 127.0.0.1, ::1, 192.168.x.x, whatever
    // enable TLS bridge for IP host, disable otherwise

    if (conn.localAddress == conn.remoteAddress)
    {
      m = vport == https_port; n = m || vport == http_port;
      if (n) { n = done == 2; pin = ""; ssl = m && net.isIP (host); }
      if (n || vport == socks_port) { time = 0; socks_abort(); return; }
    }

    if (!d) { socks_phase_6 (""); return; }

    if (p = vname, q = vpass, chain)
    {
      socks_report (0, 2, "VPX chain link " + ((m = chain [0]) ? "1" : "2"));
      if (!m) { p = safe_decode (chain [3]); q = safe_decode (chain [4]); }
    }

    if (p[0] == "$" && q[0] == "$")
    {
      if (done != 2) http = false; p = p.substr (1); q = q.substr (1);
    }

    if (!p && !q)
    {
      conn.write (Buffer.from ("\5\1\0"));
      conn.once ("data", function (r)
      {
        if (r.length != 2 || r[0] != 5 || r[1] != 0) socks_abort(); else
        {
          conn.write (d); conn.once ("data", function (r) { socks_phase_6 (r); });
        }
      });
      return;
    }

    // username and password stuff

    conn.write (Buffer.from ("\5\1\2"));
    conn.once ("data", function (r)
    {
      if (r.length != 2 || r[0] != 5 || r[1] != 2) { socks_abort(); return; }

      r = Buffer.from ("\1\0" + p + "\0" + q);
      n = r [1] = p.length; r [n + 2] = q.length; conn.write (r);

      conn.once ("data", function (r)
      {
        if (r.length != 2 || r[0] != 1 || r[1] != 0) socks_abort(); else
        {
          conn.write (d); conn.once ("data", function (r) { socks_phase_6 (r); });
        }
      });
    });
  }

  function socks_phase_6 (d)
  {
    if (d) if (d.length < 3 || d[0] != 5 || d[1] != 0 || d[2] != 0) { socks_abort(); return; }

    if (chain && (d = chain [0])) { chain [0] = ""; socks_phase_5 (d); return; }

    if (done == 1) sock.write (Buffer.from ("\5\0\0\1\0\0\0\0\0\0"));
    if (done == 2) sock.write ("HTTP/!!! 200 " + (vpn ? vpn : "OK"));
    if (done == 3) sock.write ("HTTP/1.1 200 OK" + "\r\n\r\n");

    done = time = 0; if (data || http == undefined) { socks_phase_7 (data); return; }

    sock.once ("readable", function ()
    {
      d = sock.read(); if (!d || !d.length) return;

      if (!http) { ssl = d[0] == 0x16; socks_phase_7 (d); return; }

      q = host; m = addr || q; if (nix) m = q; if (m.includes (":")) m = "[" + m + "]";

      if (d[0] == 0x16 || !(p = d.toString().match (/(.*) (.*) HTTP\//)))
      {
        if (q.includes (":")) q = "[" + q + "]"; if (port != 443) q += ":" + port;
        conn.write ("CONNECT " + m + ":" + port + " HTTP/1.1\r\nHost: " + q + "\r\n\r\n");
        conn.once ("data", function() { socks_phase_7 (d); }); return;
      }

      if (p[2][0] == "/")
      {
        m = "http://" + m + (port != 80 ? ":" + port : "");
        n = p[1].length + 1; m = Buffer.from (p[1] + " " + m);
        d = Buffer.concat ([m, d.subarray (n)]);
      }
      ssl = false; socks_phase_7 (d);
    });
  }

  function socks_phase_7 (d)
  {
    if (d) sock.unshift (d); d = conn;

    if (pin || ssl) try
    {
      m = create_certificate (host, 0); if (!m) throw (""); n = net.isIP (host);
      sock = new tls.TLSSocket (sock, { isServer: true, key: m[0], cert: m[1] });
      m = { socket: conn, rejectUnauthorized: false, servername: n ? "" : host };
      d = tls.connect (m); d.on ("error", function() { });
    }
    catch { ssl = false; if (pin) { socks_abort(); return; } }

    if (pin) d.once ("secureConnect", function()
    {
      m = this.getPeerCertificate().pubkey;
      m = crypt.createHash('md5').update(m).digest();
      if (m.compare (pin)) socks_abort();
    });

    if (key)
    {
      time = setInterval (socks_probe, 1000);
      program ["#" + key] = program ["?" + key] = 0;
      conn.on ("data",  function() { program ["#" + key] = -conn.bytesRead; });
      conn.on ("drain", function() { program ["#" + key] = conn.bytesWritten; });
    }

    d.pipe (sock, {end:true}); sock.pipe (d, {end:true});
  }

  function socks_probe ()
  {
    if (program ["?" + key] == "!!!") socks_abort();
  }

  function socks_report (err, i, j, msg)
  {
    if (err == "sockmon")
    {
      i = !vpn || vpn == "vpn" || addr == "0.0.0.0" || addr == "0.0.0.1";
      j = vhost == proxy_addr || vhost == "0.0.0.0" || vhost == "0.0.0.1";
      msg = ": " + host + " " + port + " " + (i ? addr : (j ? vport : "proxied"));
      send_message (sockmon, msg); return;
    }
    msg = ">> " + ((proxy_flags & 17) == 17 ? socket + " - " : "");

    if (!(proxy_flags & 1)) return; else if (err)
    {
      console.log (msg + "ERR: " + err + (i ? " - " + i : "") + " - " + j); return;
    }
    err = (pin ? " (" : " <") + port + (pin ? ") " : "> ");
    if (i == 0) { console.log (msg + host + err + (j == host ? "" : j)); return; }
    if (!(proxy_flags & 16)) return;

    if (i == 1) msg = " @ " + socket + " - " + j + " - " + host + (conn ? "" : " (cancelled)");
    if (i == 2) msg = " : " + socket + " - " + (j ? j : (done ? "server fail" : sock.readyState));
    if (i == 3) msg = " : " + socket + " - server retry - " + j; console.log (msg);
  }
}

///////////////////////////////
///// function: websocket /////
///////////////////////////////

function websocket (request, response, name)
{
  var m, n, p, q, key, start, opcode, size, msg;
  var headers = { Connection: 'upgrade', Upgrade: 'websocket' };

  if (key = request.headers ["sec-websocket-key"])
  {
    key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    key = crypt.createHash('sha1').update(key).digest('base64');
    headers ["Sec-WebSocket-Accept"] = key;
  }

  response.writeHead (101, "Switching Protocols", headers);
  var sock = response.socket; response.end ("");

  key = name == "?" + shadow_secret;
  if (name.search (/[?:\s]/) >= 0) name = key ? "??" : "";
  if (name && program ["@" + name]) { msg = name + " is taken"; name = ""; }
  if (name) { program ["@" + name] = sock; msg = "Kraker Proxy says hello." }

  console.log ("@ opened websocket " + name); if (msg) send_message (sock, msg);

  sock.on ("close", function()
  {
    sock.destroy(); if (sock == sockmon) sockmon = null;
    console.log ("@ closed websocket " + name); delete program ["@" + name];
  });

  sock.on ("data", function (buf)
  {
    start = 2; opcode = buf [0] & 15; size = buf [1] & 127;
    if (size == 127 || (opcode != 0 && opcode != 1)) size = -1;
    if (size == 126) { start = 4; size = buf.readUInt16BE(2); }
    if (size < 0 || size > 10000) { sock.destroy(); return; }

    msg = take_message (buf, start, size, buf [1] & 128);
    if (msg [0] != "?") { send_message (sock, msg); return; }

    n = msg.indexOf (":"); if (n < 0) n = 0;
    m = msg.substr (1, n - 1).trim(); msg = msg.substr (n + 1).trim();

    if (!n)  // upload/download progress monitor
    {
      msg = msg.split ("="); p = msg [0]; q = msg [1];
      if (q && program ["?" + p] != undefined) program ["?" + p] = q;
      q = program ["#" + p] || 0; p = program ["?" + p] || 0;
      m = " " + q + " " + p + " = sent/total";
      send_message (sock, m); return;
    }

    if (!m || !name) return; else if (!key)  // chat channel
    {
      q = program ["@" + m]; msg = name + ": " + msg;
      send_message (q || sock, q ? msg : m + " is offline");
      return;
    }

    if (m == "sockmon")
    {
      m = ""; sockmon = sock; q = "Socks5 monitor enabled.";
    }

    send_message (sock, m ? m + " is not an option." : q);
  });
}

function send_message (sock, msg)
{
  var m = Buffer.from (msg), n = m.length;
  var x = Buffer.from (n < 126 ? [129, n] : [129, 126, n >> 8, n & 255]);
  if (sock) { sock.write (x); sock.write (m); }
}

function take_message (buf, start, size, mask)
{
  if (!mask) mask = start; else
  {
    mask = start + 4; var i = mask, j = buf.length, k = 0;
    for (; i < j; i++, k++) buf [i] ^= buf [(k & 3) + start];
  }
  return (buf.toString ('utf8', mask, mask + size));
}

/*
Problem with this; the XOR on a 32-bit integer can go negative and crash Node

function take_message (buf, start, mask)
{
  if (mask)
  {
    mask = buf.readUInt32LE (start); start += 4; var i = start, j = buf.length;
    for (; i < j - 3; i += 4) buf.writeUInt32LE (buf.readUInt32LE (i) ^ mask, i);
    for (; i < j; i++) { buf [i] ^= mask & 255; mask = mask >> 8; }
  }
  return (buf.toString ('utf8', start));
}
*/

////////////////////////////////
///// function: tweak_m3u8 /////
////////////////////////////////

function tweak_m3u8 (data, config)
{
  var str = data.toString();
  if (str.substr (0,30).indexOf ("#") < 0) return (data);

  var prefix = (config.headers + "  ").split (" ");
  prefix = config.shadow + "/" + prefix [0] + prefix [2];

  var extfix = str.substr (0,900).includes ("#EXT-X-STREAM-INF:");
  extfix = extfix ? config.fix1 : config.fix2;

  var regex = /\n(.*URI="|\s*)(http|\/|)([^#?"\s]+)/g;
  return (Buffer.from (str.replace (regex, fixit)));

  function fixit (x, a, b, c)
  {
    if (b) b = prefix + (b == "/" ? config.host : "") + b;
    if (extfix) c += "." + extfix; return ("\n" + a + b + c);
  }
}

//////////////////////////////
///// function: crazycat /////
//////////////////////////////

function crazycat (request, response, url, local, host)
{
  var mode = 0, buf = [], n = 0;

  if (url == "wanna_boot_dash") mode = 1;
  if (url == "wanna_boot_dash_live") mode = 2;

  if (!url.indexOf ("wanna_scratch="))   { mode = 3; url = url.substr (14); }
  if (!url.indexOf ("gotta_birdcage="))  { mode = 4; url = url.substr (15); }
  if (!url.indexOf ("gotta_pussyfoot=")) { mode = 5; url = url.substr (16); }

  if (!mode) { default_handler (response, 888, local); return; }

  request.on ("data", function (data)
  {
    if ((n += data.length) < (mode < 5 ? 10000 : 100000)) buf.push (data); else mode = 0;
  });

  request.on ("end", function ()
  {
    if (!mode) { default_handler (response, 777, local); return; }
    buf = Buffer.concat (buf); if (mode < 5) buf = buf.toString();

    if (mode == 3)
    {
      local_data (url, buf); proc_done (response, "", "", 0); return;
    }
    if (mode == 4) { _birdcage (response, url, buf); return; }
    if (mode == 5) { _pussyfoot (response, url, buf); return; }

    var name = mode == 1 ? "_blank_dash_mpd.txt" : "_blank_live_mpd.txt";
    var data = fs.existsSync (name) ? fs.readFileSync (name, "utf8") : "";

    if (!data) default_handler (response, 777, local); else
    {
      _boot_dash (data, buf, url, host); proc_done (response, "", "", 0);
    }
  });
}

////////////////////////////////
///// function: _boot_dash /////
////////////////////////////////

function _boot_dash (data, cmdstr, url, host)
{
  var sub = cmdstr.split ("|"); if (sub.length < 9) return;
  var dat = sub[5].split (","); if (dat.length < 4) return;

  var target = data.toString(), name = "_" + url + "_" + sub[6];

  target = target.replace ("~run_time~"  , sub[0]);
  target = target.replace ("~aud_mime~"  , sub[1]);
  target = target.replace ("~aud_codec~" , sub[2]);
  target = target.replace ("~vid_mime~"  , sub[3]);
  target = target.replace ("~vid_codec~" , sub[4]);

  target = target.replace ("~aud_init~"  , dat[0]);
  target = target.replace ("~aud_index~" , dat[1]);
  target = target.replace ("~vid_init~"  , dat[2]);
  target = target.replace ("~vid_index~" , dat[3]);

  target = target.replace (/~seg_num~/g  , dat[0]);
  target = target.replace (/~seg_ofs~/g  , dat[1]);
  target = target.replace (/~seg_dur~/g  , dat[2]);

  dat = sub.slice (9).join ("|") || "/~";
  if (dat[0] == "/") dat = host + dat;

  var aud_url = name + "-aud", vid_url = name + "-vid";

  target = target.replace ("~aud_url~", dat + "!" + aud_url);
  target = target.replace ("~vid_url~", dat + "!" + vid_url);

  local_data (name, target);
  local_data (aud_url, sub[7]);
  local_data (vid_url, sub[8]);
}

///////////////////////////////
///// function: _birdcage /////
///////////////////////////////

function _birdcage (response, cmd, data)
{
  cmd = cmd.split ("="); data = data.split ("<--->");
  var n, pem = data [0], m = cmd [1] || ""; cmd = cmd [0];

  var data1 = Buffer.from ((data [1] || "").replace (/\s/g, ""), 'hex');
  var data2 = Buffer.from ((data [2] || "").replace (/\s/g, ""), 'hex');

  if (cmd == "PUDDYTAT")
  {
    cmd = {
      publicKeyEncoding:  { type: 'pkcs1', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs1', format: 'pem' }, modulusLength: m * 1 }

    try { crypt.generateKeyPair ('rsa', cmd, function (err, public, private)
          { proc_done (response, err ? "" : private + public, "text/plain", 0); });
        } catch { proc_done (response, "", "", 0); }
  }

  else if (cmd == "CANARY")
  {
    try { cmd = crypt.sign ("sha" + m, data1, pem).toString ('hex');
        } catch { cmd = ""; }

    for (m = "", n = 0; n < cmd.length; n += 64) m += cmd.substr (n, 64) + "\n";
    proc_done (response, m, "text/plain", 0);
  }

  else if (cmd == "TWEETY")
  {
    try { cmd = crypt.verify ("sha" + m, data1, pem, data2) ? "ok" : "meow";
        } catch { cmd = crypt.verify ? "tweet" : ""; }

    proc_done (response, cmd, "text/plain", 0);
  }

  else if (cmd == "SYLVESTER")
  {
    if (m == "encrypt-public")  cmd = crypt.publicEncrypt;  else
    if (m == "encrypt-private") cmd = crypt.privateEncrypt; else
    if (m == "decrypt-public")  cmd = crypt.publicDecrypt;  else
    if (m == "decrypt-private") cmd = crypt.privateDecrypt; else cmd = null;

    m = pem.indexOf ("-----BEGIN RSA PRIVATE KEY-----");
    n = pem.indexOf ("-----END RSA PRIVATE KEY-----");
    if (m >= 0) pem = pem.substr (m, n + 29 - m);

    try { cmd = cmd (pem, data1).toString ('hex'); } catch { cmd = ""; }

    for (m = "", n = 0; n < cmd.length; n += 64) m += cmd.substr (n, 64) + "\n";
    proc_done (response, m, "text/plain", 0);
  }

  else default_handler (response, 888, 0);
}

////////////////////////////////
///// function: _pussyfoot /////
////////////////////////////////

function _pussyfoot (response, cmd, buf)
{
  cmd = (cmd + "===").split ("="); var m, n, pf, bits = cmd [1], iv = cmd [2];
  var key = cmd [3], xx = iv [0] != "!", yy = key [0] == "!"; cmd = cmd [0];
  if (!xx) iv = iv.substr (1); if (yy) key = key.substr (1);

  n = iv.replace (/[a-f0-9A-F]/g, ""); m = (n ? "\0" : "0").repeat (32);
  iv = Buffer.from (iv + m, n ? 'utf8' : 'hex').subarray (0,16);

  if (key.replace (/[a-f0-9A-F]/g, "")) key = cmd = "";
  key = Buffer.from (key + "0".repeat (64), 'hex');

  if (bits == "128") key = key.subarray (0,16); else
    if (bits == "192") key = key.subarray (0,24); else
      if (bits == "256") key = key.subarray (0,32); else cmd = "";

  function aes ()
  {
    if (!m) m = xx ? crypt.randomBytes (16) : Buffer.alloc (16);
    for (n = 16; n > 0;) iv [--n] ^= m [n]; bits = "aes-" + bits + "-cbc";
    if (yy) for (n = 16; n > 0;) key [key.length - n] ^= iv [--n];
  }

  function gcm ()
  {
    pf = !m || xx; aes(); bits = bits.replace ("cbc", pf ? "gcm" : "ctr");
    if (!xx) iv.copy (m); iv.writeInt32BE (2,12); if (pf) iv = iv.subarray (0,12);
  }

  if (cmd == "AES-ENCRYPT") try
  {
    m = ""; aes(); n = ""; pf = crypt.createCipheriv (bits, key, iv);
    if (xx) n = crypt.createHash('md5').update(buf).digest(); else m = iv;
    buf = Buffer.concat ([ m, pf.update (n), pf.update (buf), pf.final() ]);
  }
  catch { pf = null }

  if (cmd == "AES-DECRYPT") try
  {
    m = buf.subarray (0,16); aes(); pf = crypt.createDecipheriv (bits, key, iv);
    buf = Buffer.concat ([ pf.update (buf.subarray (16)), pf.final() ]);

    if (xx) { m = buf.subarray (0,16); buf = buf.subarray (16); }
    if (xx && crypt.createHash('md5').update(buf).digest().compare(m)) throw ("");
  }
  catch { pf = null }

  if (cmd == "AES-ENC-GCM") try
  {
    m = ""; gcm(); pf = crypt.createCipheriv (bits, key, iv);
    buf = Buffer.concat ([ m, m, pf.update (buf), pf.final() ]);
    pf.getAuthTag().copy (buf, 16, 0, 16);
  }
  catch { pf = null }

  if (cmd == "AES-DEC-GCM") try
  {
    m = buf.subarray (0,16); gcm(); pf = crypt.createDecipheriv (bits, key, iv);
    if (xx) pf.setAuthTag (buf.subarray (16,32)); buf = buf.subarray (32);
    buf = Buffer.concat ([ pf.update (buf), pf.final() ]);
  }
  catch { pf = null }

  if (pf === undefined) default_handler (response, 888, 0); else
    proc_done (response, pf ? buf : "", "application/octet-stream", 0);
}

///////////////////////////////
///// Certificate forgery /////
///////////////////////////////

function add_num (p, r, q)
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

function add_str (p, r, q)
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

function new_certificate (state, auth)
{
  var a, b, m, n, p, q, issuer = [], subject = [], altnames = [];
  var items = [['2.5.4.6'],['2.5.4.10'],['2.5.4.11'],['2.5.4.3'],['2.5.29.17'],['2.5.29.19']];

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

    if (m[0] != "#")
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
      for (a = 0; a < 4; a++) m[a] = (m[a] * 1) & 255;
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

  state.certificate = m;
}

function create_certificate (host, context)
{
  var m, n, p, q; if (!state) return null;

  if (net.isIP (host)) host = "#" + host; else if (context < 0) return null; else
  {
    q = "*." + host.split (".").slice (1).join (".");
    m = context ? null : [ https_server.key, https_server.cert ];
    if (p = state.names) if (p.includes (host) || p.includes (q)) return (m);
  }

  if (!(m = state.altnames)) return null; else if (!m.includes (host))
  {
    if (m.length > 29) m.shift(); m.push (host); new_certificate (state);

    try { n = crypt.sign ("sha" + state.algo [0], Buffer.from (state.certificate), state.key);
        } catch { m.pop(); return null; }

    m = add_str (state.certificate, 0x30, add_num ([], 6, state.algo [1]).concat ([5,0]));
    m = add_str ([], 0x30, add_str (m, 3, [0].concat (Array.from (n))));

    p = Buffer.from (m).toString ('base64'); q = "-----BEGIN CERTIFICATE-----";
    for (n = 0; n < p.length; n += 64) q += "\n" + p.substr (n, 64);
    state.cert = Buffer.from (q + "\n-----END CERTIFICATE-----\n");
  }

  if (context < 1) return ([ state.key, state.cert ]);
  return (tls.createSecureContext ({ key: state.key, cert: state.cert }));
}

///// End of file /////

/*
https://scrapfly.io/web-scraping-tools/http2-fingerprint
http://localhost:8080/!mock:X|*https://tools.scrapfly.io/api/fp/akamai?extended=1
*/

/*
The secureContext was stolen from here (thanks, Tim):
https://github.com/httptoolkit/mockttp/blob/main/src/rules/passthrough-handling.ts
Not using secureOptions because won't work correctly and doesn't make a diff anyway

This does not perfectly mimic Firefox (about 90%).
Whether this works with Cloudflare depends on the level of the threat assessment. 
It appears that CF does not cross-check the User-Agent with the TLS fingerprint.

Additional info:
https://wiki.openssl.org/index.php/List_of_SSL_OP_Flags
https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
https://lwthiker.com/reversing/2022/02/17/curl-impersonate-firefox.html

These links should load without the bot challenge:
view-source:http://localhost:8080/!mock:1A|*https://banned.video
view-source:http://localhost:8080/!mock:1A|*https://www.retailmenot.com
view-source:http://localhost:8080/!mock:1A|*https://www.crunchyroll.com
Note: banned.video mostly won't work but sometimes it will

TLS fingerprints:
http://localhost:8080/!mock:A|*https://client.tlsfingerprint.io
http://localhost:8080/!mock:A|*https://tls.browserleaks.com/json
http://localhost:8080/!mock:A|*https://check.ja3.zone

https://tlsfingerprint.io/
https://browserleaks.com/ssl
https://ja3.zone

The ordering of the extensions cannot be changed. It is possible to enable
the "application_layer_protocol_negotiation" extension by including ALPNProtocols: ['http/1.1']
in the "options" object in http_handler but that won't accomplish anything since there are
also these four other extensions in Firefox which cannot be implemented:

renegotiation_info (0xff01)
status_request (0x0005)
delegated_credentials (0x0022)
record_size_limit (0x001c)

Firefox ciphers:
TLS_AES_128_GCM_SHA256 (0x1301) 19,1
TLS_CHACHA20_POLY1305_SHA256 (0x1303) 19,3
TLS_AES_256_GCM_SHA384 (0x1302) 19,2
ECDHE-ECDSA-AES128-GCM-SHA256 (0xc02b) 192,43
ECDHE-RSA-AES128-GCM-SHA256 (0xc02f) 192,47
ECDHE-ECDSA-CHACHA20-POLY1305 (0xcca9) 204,169
ECDHE-RSA-CHACHA20-POLY1305 (0xcca8) 204,168
ECDHE-ECDSA-AES256-GCM-SHA384 (0xc02c) 192,44
ECDHE-RSA-AES256-GCM-SHA384 (0xc030) 192,48
ECDHE-ECDSA-AES256-SHA (0xc00a) 192,10
ECDHE-ECDSA-AES128-SHA (0xc009) 192,9
ECDHE-RSA-AES128-SHA (0xc013) 192,19
ECDHE-RSA-AES256-SHA (0xc014) 192,20
AES128-GCM-SHA256 (0x009c) 0,156
AES256-GCM-SHA384 (0x009d) 0,157
AES128-SHA (0x002f) 0,47
AES256-SHA (0x0035) 0,53

IANA cipher names:
TLS_AES_128_GCM_SHA256 (0x1301) 19,1
TLS_CHACHA20_POLY1305_SHA256 (0x1303) 19,3
TLS_AES_256_GCM_SHA384 (0x1302) 19,2
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b) 192,43
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f) 192,47
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9) 204,169
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8) 204,168
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c) 192,44
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030) 192,48
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a) 192,10
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009) 192,9
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013) 192,19
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014) 192,20
TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c) 0,156
TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d) 0,157
TLS_RSA_WITH_AES_128_CBC_SHA (0x002f) 0,47
TLS_RSA_WITH_AES_256_CBC_SHA (0x0035) 0,53
*/

/*
Below is the cipher list when using "ciphers: 'HIGH'".
The TLS fingerprint matches Cluster #33 (https://tlsfingerprint.io/cluster/a0c7d616ebdc8b4c).
Still cannot get past CloudFlare's "Bot Fight Mode" which is currently active at banned.video (September 22, 2020).
Why in the hell is CloudFlare blocking Kraker?

http://localhost:8080/https://ja3er.com/json
https://ja3er.com/search/fb7fad0594b51a29cbc9e96c3232c590
https://www.openssl.org/docs/man1.0.2/man1/ciphers.html
https://testssl.sh/openssl-iana.mapping.html

TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c) 192,44
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030) 192,48
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x009f) 0,159
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9) 204,169
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8) 204,168
TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xccaa) 204,170
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b) 192,43
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f) 192,47
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x009e) 0,158
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0xc024) 192,36
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xc028) 192,40
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x006b) 0,107
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xc023) 192,35
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xc027) 192,39
TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x0067) 0,103
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a) 192,10
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014) 192,20
TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039) 0,57
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009) 192,9
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013) 192,19
TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033) 0,51
TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d) 0,157
TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c) 0,156
TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003d) 0,61
TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003c) 0,60
TLS_RSA_WITH_AES_256_CBC_SHA (0x0035) 0,53
TLS_RSA_WITH_AES_128_CBC_SHA (0x002f) 0,47
TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff) 0,255
*/
