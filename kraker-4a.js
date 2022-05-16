/*
Local Proxy Server for Alleycat Player

Improvements from version 1c to version 2a:

- handle double-slash at start of "location" response header
- handle rare case where "?" immediately follows host name without a slash
- do not strip byte-range headers in non-passthrough mode (problem with seeking on mp4 videos)
- handle socket disconnection error (ECONNRESET) in default_handler (crash issue)
- handle ".well-known/http-opportunistic" request coming from Firefox for 123tvnow.com streams
- delete request headers "origin" and "referer" if set to blank
- complete rewrite of local GET and PUT; security model via _aliases.txt

Improvements from version 2a to version 2b:

- added gzip decompression for m3u8 handler
- added ability to replace response headers (indicated with "!")
- added crash check in case SSL files are missing
- added Socks5 proxy server for DNS and TOR support

Improvements from version 2b to version 2c:

- updated init_settings to not invoke DNS "default" on reload
- updated proxy_handler to correctly destroy sockets (memory leak)
- added reporting system to track socket disposition
- added dns_lookup in http_handler and proxy_handler

Improvements from version 2c to version 3a:

- updated dns_lookup to report timing and IP address
- updated dns_lookup to handle four simultaneous lookups
- updated http_handler to destroy network connection (memory leak)
- added special cases "LOCAL" and "0.0.0.0"
- added DNS over HTTPS (JSON format only)

Improvements from version 3a to version 3b:

- modified options_proc to look for non-blank "access-control-request-method"
- tor4all corrected to exclude LOCAL or 0.0.0.0
- removed request.on callback in http_handler due to incompatibility with Node.js v16

Improvements from version 3b to version 4a:

- HTTP (8080) and HTTPS (8081) merged via http_handler
- added HTTP support on 8088 ("CONNECT" method for SSL)
- connections through 8080/8081 are now routed to 8088
- added restart command for HTTPS server
- added shadow ports and cookie stealer
- added "vpx" and "timeout" parameters
- added support for i2p and IPFS
- DoH routed through port 8080 for socket reuse
- updated dns_resolve to handle wildcard domains

*/

const fs    = require ('fs');
const http  = require ('http');
const https = require ('https');
const zlib  = require ('zlib');

const dns   = require ('dns');
const net   = require ('net');
const tls   = require ('tls');

var aliases = "_aliases.txt", settings = "_settings.txt";  // do not use uppercase

var http_port = 8080, https_port = 8081, socks_port = 8088, ipfs_port = 8089;
var tor1_port = 9050,  tor2_port = 9150,   i2p_port = 4444;

var proxy_name = "Kraker-4a", proxy_host = "http://localhost:" + http_port + "/";

var reqcount = passthru = last_time = 0, last_pass = "", local_files = [];

var mime_list = {
  txt: "text/plain", htm: "text/html", html: "text/html", js: "application/javascript", json: "application/json",
  gif: "image/gif", jpeg: "image/jpeg", jpg: "image/jpeg", png: "image/png", mp3: "audio/mpeg", mp4: "video/mp4",
  webm: "video/webm", mpd: "application/dash+xml", m3u8: "application/x-mpegurl", ts: "video/mp2t"
};

http.createServer (http_handler).listen (http_port);
net.createServer (proxy_handler).listen (socks_port);
var ssl_server = start_ssl_server ("", "");

var proxy_flags = profile_count = 0, server = [], profile = [], dnslist = [], socklist = [];
var sockets_open = 0, sockets_count = 9, dns_count = 0, doh_address = doh_host = doh_path = "";
var vpn_host = vpn_port = vpn_name = vpn_pass = "";

var shadow_secret = "", shadow_host = {'shadow:80': "", 'shadow:443': "$"};

console.log ("=-----------------------------------------------------------------------------=");
console.log (" Kraker (version 4a) Local Proxy Server - waiting on port " + http_port + ", ctrl-C to exit ");
console.log ("=-----------------------------------------------------------------------------=");

console.log (">> Commands list: activate, dnslookup, flags, reload, servers");
console.log (">> " + init_settings (settings) + " (" + settings + ")");

///// End of Setup /////

//////////////////////////////////////
///// function: start_ssl_server /////
//////////////////////////////////////

function start_ssl_server (keyfile, crtfile)
{
  if (!keyfile) keyfile = "_https_key.pem";
  if (!crtfile) crtfile = "_https_crt.pem";

  var ssl_key = null; try { ssl_key = fs.readFileSync (keyfile); } catch(e) {};
  var ssl_crt = null; try { ssl_crt = fs.readFileSync (crtfile); } catch(e) {};

  var ssl = { key: ssl_key, cert: ssl_crt, requestCert: false, rejectUnauthorized: false };

  return (https.createServer (ssl, http_handler).listen (https_port));
}

///////////////////////////////////
///// function: init_settings /////
///////////////////////////////////

function init_settings (name)
{
  var i, j, k, data, sub, msg = "Settings file: ";

  if (!name || name.search (":|/") >= 0) return (msg + "INVALID NAME");
  data = fs.existsSync (name) ? fs.readFileSync (name, "utf8") : "";
  if (!data) return (msg + "NOT FOUND");

  if ((i = data.indexOf ("$end$")) >= 0) data = data.substr (0, i);

  sub = data.match (/\$shadow_secret=(.*)\$/); shadow_secret = sub ? sub [1] : "";

  server = []; profile = [];

  for (i = k = 0; (j = data.indexOf ("[", i) + 1) > 0; i = j)
  {
    if (j < k) return (msg + "ERROR"); k = data.indexOf ("]", j);
    sub = data.substr (j, k - j).replace (/\s+/gm, " ").trimEnd();
    if (sub.length > 5 && !sub.search ("#|\\?|\\+")) profile.push (sub);
  }

  if (!profile_count) dns_servers ("default"); add_resolver ("");

  if (!profile_count || data.includes ("$fmodify=1$"))
  {
    proxy_flags = 0;
    if (data.includes ("$console=1$")) proxy_flags |= 1;
    if (data.includes ("$altport=1$")) proxy_flags |= 2;
    if (data.includes ("$tor4all=1$")) proxy_flags |= 4;
    if (data.includes ("$showdns=1$")) proxy_flags |= 16;
  }

  profile_count++; return (msg + "parsed and loaded");
}

//////////////////////////////////
///// function: add_resolver /////
//////////////////////////////////

function add_resolver (name)
{
  var i, j, k, n, p, q, r, s, data, sub;

  for (i = 0; i < profile.length; i++)
  {
    data = profile[i].split (" ");
    if (data.length < 2 || data[0] != "?" + name) continue;
    sub = data[1].split ("|");

    for (j = 0; j < sub.length; j++) if (p = sub[j])
    {
      if (data.length < 3) q = ""; else
      {
        r = ""; q = data [Math.trunc (Math.random() * (data.length - 2)) + 2];
        n = q.indexOf ("+"); if (n >= 0 && n < 4) r = q.substr (n) + " ";

        if (r) for (k = 0; k < profile.length; k++)
        {
          if (profile[k].indexOf (r)) continue;
          s = (profile[k]).split(" "); if (s.length < 2) continue;
          r = s [Math.trunc (Math.random() * (s.length - 1)) + 1];
          q = (n ? q.substr (0, n) + ":" : "") + r; break;
        }
      }

      r = (q.length < 4 || q[3] == ":") ? q.substr (0,3) : "";

      if (r == "SHD")
      {
        if (!p.includes (":")) p += ":" + (q [4] == "$" ? "443" : "80");
        shadow_host [p] = q.substr (4); continue;
      }

      if (server.includes (p)) for (k = 0; k < server.length; k += 2)
        if (p == server[k]) { server.splice (k, 2); break; }

      if (r == "TOR" || r == "VPN")
      {
        r = q.substr (4); if (r && !net.isIP (r)) continue;
      }
      else if (q && q != "LOCAL" && !net.isIP (q)) continue;

      server.push (p); server.push (q);
    }
  }
}

//////////////////////////////////
///// function: init_servers /////
//////////////////////////////////

function init_servers ()
{
  var i, j = k = 0;

  for (i = 1; i < server.length; i += 2) if (server[i]) j++; else k++;
  console.log (">> + " + j); for (i = 0; i < server.length; i += 2) init_lookup (i);
  console.log (">> - " + k); return (j + " " + k);
}

function init_lookup (num)
{
  var name = server [num], ip = server [num + 1], count = profile_count;

  if (ip) { console.log (">> " + name + " [" + ip + "]"); return; }

  dns.resolve4 (name, function (err, list)
  {
    if (err || !list.length) console.log (">> DNS (failure) " + name); else
    {
      ip = list [Math.trunc (Math.random() * addr.length)];
      if (count != profile_count) ip = "CANCEL"; else server [num + 1] = ip;
      console.log (">> DNS (success) " + name + " [" + ip + "]");
    }
  });
}

/////////////////////////////////
///// function: dns_servers /////
/////////////////////////////////

function dns_servers (name)
{
  var n, s, t; if (dns_count && name) return ([]);

  if (name) doh_address = ""; if (!this.original) this.original = dns.getServers();

  if (name == "reset") dns.setServers (this.original); else if (name)
  {
    for (n = 0, s = "#" + name + " "; n < profile.length; n++)
    {
      t = profile [n]; if (t.indexOf (s)) continue;
      s = t.substr (s.length); s = s.split (" ");

      if (s.length > 1 && s[1].includes ("/"))
      {
        if (!net.isIP (s[0])) break; doh_address = s[0]; s = s[1].split ("/"); 
        doh_host = s[0]; doh_path = "/" + s[1] + "?type=A&name=";
      }
      else try { dns.setServers (s); } catch (e) { };

      name = ""; break;
    }

    if (name == "default") dns.setServers (this.original);
  }

  return dns.getServers();
}

/////////////////////////////////
///// function: dns_resolve /////
/////////////////////////////////

function dns_resolve (name, vpx)
{
  var m, n, p, ip = "";

  for (n = 0; n < server.length; n += 2)
  {
    if ((p = server [n]) [0] == ".")
    {
      m = name.lastIndexOf (p);
      p = (m < 0 || m + p.length != name.length) ? p.substr (1) : name;
    }
    if (p == name) { ip = server [n + 1]; break; }
  }

  if (!ip)
  {
    n = name.lastIndexOf ("."); if (n < 0) return ("LOCAL");
    p = name.substr (n + 1); if (p == "localhost") return ("127.0.0.1");

    if (p == "onion") ip = "TOR";
    if (p == "loki")  ip = "LOCAL";
    if (p == "snode") ip = "LOCAL";
    if (p == "i2p")   ip = "VPX:i2p";
  }

  if ((p = ip.substr (0,3)) == "TOR" || p == "VPN" || p == "VPX")
    ip = ":" + ip; else if (proxy_flags & 4 && ip != "LOCAL" && ip != "0.0.0.0")
      ip = (vpn_host == "0.0.0.0" ? ":VPN" : ":TOR") + (ip ? ":" + ip : "");

  if (p == "VPN" && !vpn_host) ip = ":vpn" + ip.substr (4);

  if (vpx) { if (ip [0] == ":") ip = ip.substr (5); ip = ":VPX:" + ip; }

  return (ip ? ip : name);
}

////////////////////////////////
///// function: dns_lookup /////
////////////////////////////////

function dns_lookup (addr, host, func)
{
  var m, n, s, t, p = addr, q = host;

  if (p [0] == ":" && (p.length == 4 || p.length > 5)) { func (p.substr (5)); return; }

  if (net.isIP (p)) { func (p); return; }
  if (net.isIP (q) || p == "LOCAL") { func (q); return; }

  if (!dns_count)
  {
    time_now = Math.trunc (Date.now() / 1000);
    if (dnslist.length > 300) dnslist.splice (0, 20);
  }

  for (n = dnslist.length - 2; n >= 0; n -= 2) if (q == dnslist [n])
  {
    p = dnslist [n + 1].split (" ");
    q = p [0]; t = time_now - (dns_count ? 300 : 0);
    if (p [1] * 1 < t) break; else { func (q); return; }
  }

  if (!q || dns_count > 3)
  {
    setTimeout (function() { dns_lookup (addr, host, func); }, 150); return;
  }

  dns_count++; dnslist.push (host); dnslist.push (" ");
  n = dnslist.length - 1; p = Date.now();

  dns_master (host, function (err, ip, ttl)
  {
    t = Date.now(); if ((p = t - p) < 15) p = 15; t = Math.trunc (t / 1000);
    if (err) m = err; else { m = q = ip; host += " (" + ttl + "s)"; }
    s = "<< " + (doh_address ? "DoH" : "DNS") + ": ";

    if (err || proxy_flags & 17) console.log (s + p + "ms - " + m + " - " + host);
    dnslist [n] = q + " " + (t + (err ? 60 : 300)); func (q); dns_count--;
  });
}

function dns_master (name, func)
{
  if (!doh_address)
  {
    dns.resolve4 (name, { ttl:true }, function (err, list)
    {
      if (err) func (err.code); else
        if (!list.length) func ("BLANK"); else func ("", list[0].address, list[0].ttl);
    });
    return;
  }

  var ans = "", i = j = k = 0;

  var options = {
    hostname: 'localhost', port: http_port, path: '/https://' + doh_host + doh_path + name,
    headers: { host: '@' + doh_address, accept: 'application/dns-json', connection: 'keep-alive' }
  }

  var doh = http.get (options, function (res)
  {
    res.on ("data", function (d)
    {
      if (ans.length < 10000) ans += d.toString();
    });

    res.on ("end", function ()
    {
      try {
        ans = JSON.parse (ans); k = ans.Status; ans = ans.Answer;
        if (k == undefined) k = -1; if (k == 0) i = ans.length; } catch(e) {}

      for (; i > 0; i--) if (ans[i-1].type == 1)
      {
        ans = ans[i-1]; i = ans.data; if (!(j = ans.TTL)) j = 0; break;
      }
      if (!i) func ("ERROR (" + k + ")"); else func ("", i, j);
    });
  });

  doh.on ("error", function (err) { func (err.code); });
}

/////////////////////////////////////
///// function: default_handler /////
/////////////////////////////////////

function default_handler (response, error, local)
{
  var msg, err_msg, header = {};

  if (response._header)  // socket error while streaming
  {
    if (local) console.log ("--Unexpected disconnection--"); return;
  }

  msg = "--------------------\n" +
        " Local Proxy Server \n" +
        "--------------------\n\n" +
        "Version Name: " + proxy_name + " [May 15, 2022]\n\n" +
        "HTTP at " + http_port + ", HTTPS at " + https_port + "\n" +
        "Socks5 Tunnel Proxy at " + socks_port + "\n\n" +
        "NODE.JS " + process.version + "\n";

  if (error != 200)
  {
    msg = "--Service Not Available--";
    if (error == 777) msg = " Local Request: Error";
    if (error == 888) msg = " Local Request: Invalid";
    if (error == 999) msg = "--Invalid Request--";
    if (local > 0) console.log (msg); msg = "";
  }

  // aggressive connection closure
  if (!error) { response.connection.destroy(); return; }

  if (error == 200) err_msg = "OK";
  if (error != 200) err_msg = "Deep State";
  if (error == 666) err_msg = "Illuminati";
  if (error == 999) err_msg = "Think Mirror";

  header ["content-type"] = "text/plain";
  header ["content-length"] = msg.length;
  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";

  response.writeHead (error, err_msg, header);
  response.end (msg);
}

//////////////////////////////////
///// function: options_proc /////
//////////////////////////////////

function options_proc (request, response, local)
{
  var header = {}, okay = true;

  var headers = request.headers ["access-control-request-headers"];
  var methods = request.headers ["access-control-request-method"];

  if (!methods) if (headers != "accept" && headers != "range") return false;

  if (headers) header ["access-control-allow-headers"] = headers;
  if (methods) header ["access-control-allow-methods"] = methods;

  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";
  header ["access-control-max-age"] = "30";
  header ["content-length"] = "0";

  response.writeHead (200, "OK", header);
  response.end ();
  return true;
}

///////////////////////////////
///// function: proc_done /////
///////////////////////////////

function proc_done (response, data, mime, local)
{
  var header = {};
  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";
  header ["access-control-allow-headers"] = "range";
  header ["access-control-expose-headers"] = "content-length, content-range, content-type";
  header ["accept-ranges"] = "bytes";

  if (mime) header ["content-type"] = mime;
  if (mime.substr (0,5) != "text/") header ["cache-control"] = "no-store";

  if (local > 0) console.log (" Local Request: OK");

  if (typeof (data) != "object")
  {
    header ["content-length"] = data.length;
    response.writeHead (200, "OK", header);
    response.end (data);
    return;
  }

  var size = data[0], start = data[1], end = data[2];
  header ["content-length"] = end - start + 1;

  if (size <= 0) response.writeHead (200, "OK", header); else
  {
    header ["content-range"] = "bytes " + start + "-" + end + "/" + size;
    response.writeHead (206, "Partial Content", header);
  }
}

///////////////////////////////
///// function: mime_type /////
///////////////////////////////

function mime_type (url)
{
  var u = url.split ("."), n = u.length - 1; if (n < 0) return ("");
  var mime = mime_list [u[n]]; return (mime ? mime : "");
}

////////////////////////////////
///// function: local_data /////
////////////////////////////////

function local_data (name, data)
{
  if (name) if (data)
  {
    for (var n = local_files.length - 1; n >= 0; n--)
      if (local_files [n]['name'] == name) local_files.splice (n,1);

    if (local_files.length > 50) local_files.splice (0,3);
    local_files.push ({'name': name, 'data': data});
  }
  else
  {
    for (var n = local_files.length - 1; n >= 0; n--)
      if (local_files [n]['name'] == name)
        return (local_files [n]['data']);
  }
  return "";
}

////////////////////////////////
///// function: local_link /////
////////////////////////////////

function local_link (url, local)
{
  if (url [0] == "+")
  {
    var dat = fs.existsSync (aliases) ? fs.readFileSync (aliases, "utf8") : "";
    var n = dat.indexOf (url + ","); if (n < 0) n = dat.indexOf (url + "?,");

    if (n < 0) url = ""; else
    {
      url = dat.substr (n + url.length + 1, 300);
      url = url.substr (url.indexOf ("+") + 1);
      url = url.substr (0, url.indexOf (";"));
      if (url && local > 0) console.log (" FILE: " + url);
    }
  }
  var x = url.toLowerCase(); return ((x == aliases || x == settings) ? "" : url);
}

//////////////////////////////
///// function: put_file /////
//////////////////////////////

function put_file (request, response, url, local)
{
  var append = url.substr (0,2) == "++"; if (append) url = url.substr (1);

  if (url [0] != "+" || !(url = local_link (url + "?", local)))
  {
    if (append || fs.existsSync (url)) { default_handler (response, 777, local); return; }
  }

  append = (append && fs.existsSync (url)) ? fs.statSync (url).size : 0;

  var stream = fs.createWriteStream (url, append ? { start: append, flags: "a" } : {});

  stream.on ("error", function () { default_handler (response, 777, local); });

  stream.on ("open", function()
  {
    proc_done (response, "", "", local);
    request.pipe (stream, { end:true });
  });
}

//////////////////////////////
///// function: get_file /////
//////////////////////////////

function get_file (request, response, url, local)
{
  var data = local_data (url, ""), size = 0;

  if (!data) url = local_link (url, local); else
  {
    proc_done (response, data, mime_type (url), 0); return;
  }

  if (fs.existsSync (url)) size = fs.statSync (url).size;
  if (!size) { default_handler (response, 777, local); return; }
  var start = 0, end = size - 1, range = request.headers ["range"];

  if (!range) size = -size; else
  {
    range = range.substr (range.indexOf ("=") + 1);
    range = range.split ("-"); end = range[1] ? range[1] * 1 : 0;
    if (range[0]) start = range[0] * 1; else { start = size - end - 1; end = 0; }
    if (!end || end >= size) end = size - 1;
    if (start > end) start = end;
    if (end < start) end = start;
  }

  var stream = fs.createReadStream (url, { start: start, end: end });

  stream.on ("error", function (e) { default_handler (response, 777, local); });

  stream.on ("open", function()
  {
    proc_done (response, [size, start, end], mime_type (url), local);
    stream.pipe (response, { end:true });
  });
}

/////////////////////////////////
///// function: socket_pool /////
/////////////////////////////////

function socket_pool (sock, conn, name, port, host)
{
  var m, n = socklist.length - 1;

  if (!sock)
  {
    // find a TLS session ticket
    if (name) for (; n >= 0; n -= 3) if (name == socklist [n - 2])
      if ((m = socklist [n]).secure) if (m = m.getSession()) return m;

    // close HTTPS sockets ("restart" command)
    if (!name && !conn) for (; n >= 0; n -= 3)
      if ((sock = socklist [n - 1]).encrypted) sock.destroy();

    // remove outgoing socket and close incoming socket
    if (!name && conn) for (; n >= 0; n -= 3) if (conn == socklist [n])
    {
      if (!sock && (sock = socklist [n - 1]) && !conn.idle) sock.destroy();
      socklist.splice (n - 2, 3);
    }

    return null;
  }

  if (conn) // replace an existing socket (TLS upgrade)
  {
    for (; n >= 0; n -= 3) if (sock == socklist [n]) socklist [n] = conn;
    conn.timer = sock.timer;
  }
  else
  {
    for (; n >= 0; n -= 3) if (name == socklist [n - 2] && socklist [n].idle)
    {
      if (!conn) conn = socklist [n]; m = socklist [n - 1];
      if (m == sock || (conn == socklist [n] && m.destroyed)) socklist.splice (n - 2, 3);
    }

    if (!port) { port = socks_port; host = "localhost"; }
    if (!conn) conn = net.createConnection (port, host);

    socklist.push (name); socklist.push (sock); socklist.push (conn);
  }

  return conn;
}

//////////////////////////////////
///// function: http_handler /////
//////////////////////////////////

function http_handler (request, response)
{
  var m, n, local = portnum = port = 0;
  var proxy, shadow_on = origin = host = refer = "", param = [];
  var referral = head = head1 = head2 = head3 = m3ufix1 = m3ufix2 = "";

  var method = request.method, ssl = request.socket.encrypted;
  var url = request.url, shadow = request.headers ["host"] || "";

  if ((m = shadow.split (".")).length == 3 && m [1] == "shadow")
    if (m [2].split (":")[0] == "localhost") shadow = m [0] + ":80";

  // substitute backslashes (sanity check)
  n = url.indexOf ("?"); if (n < 0) n = url.length;
  url = url.substr (0, n).replace (/\\/g, "/") + url.substr (n);

  if (url [0] != "/")
  {
    n = url.indexOf ("//") + 2; url = url.substr (url.indexOf ("/", n));
  }

  url = url.substr (1).replace (/%7C/g, "|");  // Opera and Chrome convert vertical bar to %7C

  if (url [0] == "@" && !shadow.includes (".")) if (url.length == 1)
  {
    proc_done (response, " See the console for your info.", "text/plain", 0);
    console.log (shadow_host); return;
  }
  else if ((m = url.split ("@")).length > 2)
  {
    if ((n = m [1]) != shadow_secret) n = ""; if (m [2]) shadow = m [2]; m = m [3];

    if (!n && shadow.includes (".")) m = ">> need secret"; else if (m == undefined)
    {
      m = (shadow_host [shadow] == undefined) ? ">> not found" : ">> removed";
      delete shadow_host [shadow];
    }
    else if (!n && (m [0] == "+" || m [1] == "+")) m = ">> need secret"; else
    {
      if (!shadow.includes (":")) shadow += ":" + (m [0] == "$" ? "443" : "80");
      if (m.substr (-1) == "/") m = m.substr (0, m.length - 1);
      shadow_host [shadow] = m; m = '= "' + m + '"';
    }

    proc_done (response, " " + shadow + " " + m, "text/plain", 0); return;
  }

  if ((m = url.indexOf ("$")) >= 0 && (n = url.indexOf ("$", m + 1)) > 0)
  {
    m = url.substr (m + 1, n - m - 1); n = url.substr (n + 1);

    if (m && m == shadow_secret) if (n) url = "\\" + n; else
    {
      m = (m = request.headers ["cookie"]) ? m : " no cookie";
      proc_done (response, "**" + m, "text/plain", 0); return;
    }
    else if (url [0] == "$" && !(m + shadow).includes ("."))
      { shadow_on = m; url = n; }
  }

  if (url [0] == "\\") url = url.substr (1); else if (shadow [0] != "@")
  {
    n = shadow_on || shadow; if (!n.includes (":")) n += ":" + (ssl ? "443" : "80");

    if ((m = shadow_host [n]) == undefined) shadow_on = ""; else
    {
      shadow_on = n.split (":")[0]; if (m [0] == "$") m = m.substr (1);
      if (m [0] == "+") { shadow_on = "."; m = m.substr (1); }
      if (m) url = m + (url ? "/" + url : "");
    }
  }

  if (shadow [0] != "@") if (url [0] != "~") local = 1; else
  {
    local = -1; url = url.substr (1); referral = "~";
  }

  if (url [0] == "?")
  {
    proxy_command (response, url.substr (1), ssl); return;
  }

  if (!url || url [0] == ".")  // filter out ".well-known"
  {
    default_handler (response, 200, 0); return;
  }

  if (!url.indexOf ("ipfs/") || !url.indexOf ("ipns/"))  // IPFS local gateway
  {
    local = 0; url = "http://localhost:" + ipfs_port + "/" + url;
  }

  if (method == "OPTIONS" && options_proc (request, response, local)) return;

  if (local > 0) console.log ((shadow_on ? "@" : ">") + method + " " + url);

  if (shadow_on == "." || url.search (":|/") < 0)
  {
    url = decodeURIComponent (url);
    if (url [0] == "!") url = url.substr (1);
    n = url.indexOf ("?"); if (n >= 0) url = url.substr (0, n);

    if (!url) default_handler (response, 888, local);
    else if (method == "GET") get_file (request, response, url, local);
    else if (method == "PUT") put_file (request, response, url, local);
    else if (method == "POST") handle_special (request, response, url, local);
    else default_handler (response, 888, local);
    return;
  }

  if (url [0] == "*")
  {
    url = url.substr (1); n = url.indexOf ("*");
    if (n >= 0) { refer = url.substr (0, n); url = url.substr (n + 1); }
    referral = referral + "*" + refer + "*"; if (!refer) refer = "*";
  }

  if ((n = url.indexOf ("|*")) >= 0)
  {
    head = url.substr (0, n).split ("|"); url = url.substr (n + 2);
  }

  if ((n = refer.indexOf (",")) >= 0)
  {
    m3ufix1 = refer.substr (n + 1); if (!(refer = refer.substr (0, n))) refer = "*";

    if ((n = m3ufix1.indexOf (",")) >= 0)
    {
      if (n >= 0) { m3ufix2 = m3ufix1.substr (n + 1); m3ufix1 = m3ufix1.substr (0, n); }
      
      if ((n = url.indexOf (".m3u")) > 0)
      {
        m = url.indexOf ("?"); if (m < 0) m = url.length;
        if (m > n + 3 && m < n + 7) local += local;
      }
    }
  }

  if (url [0] == "!")  // for DASH videos
  {
    n = url.indexOf ("/"); m = url.substr (n + 1);
    url = local_data (url.substr (1, n - 1), "") + m;
  }

  n = url.indexOf (":");
  if (n < 0 || n > 5) { url = refer + url; n = url.indexOf (":"); }
  if (n > 0 && n < 6) { origin = url.substr (0, n + 3); host = url.substr (n + 3); }

  url = "/"; n = host.indexOf ("/");
  if (n > 0) { url = host.substr (n); host = host.substr (0, n); }

  if ((n = host.indexOf ("?")) > 0)  // check for unusual case of ? after domain name
  {
    url = "/" + host.substr (n) + url; host = host.substr (0, n);
  }

  var myheader = request.headers, cookie = myheader ["accept"];
  myheader ["host"] = host; m = origin; origin += host;

  if ((n = host.indexOf (":")) >= 0)
  {
    portnum = host.substr (n + 1) * 1; host = host.substr (0, n);
  }

  if (m == "http://") { proxy = http; if (!portnum) portnum = 80; }
  if (m == "https://") { proxy = https; if (!portnum) portnum = 443; }

  if (!host || !proxy)
  {
    default_handler (response, 999, local); return;
  }

  if (!cookie || cookie.substr (0,2) != "**") cookie = ""; else
  {
    myheader ["accept"] = "*/*";
    cookie = cookie.substr (2); if (!cookie) cookie = "null";
    if (cookie != "null") myheader ["cookie"] = cookie;
  }

  if (refer == "null") refer = myheader ["referer"]; else
  {
    if (refer == "*") refer = origin + "/";
    if (refer) myheader ["origin"] = myheader ["referer"] = refer; else
      { delete myheader ["origin"]; delete myheader ["referer"]; }
  }
  if (!refer) refer = "null";

  if (head) for (var i = head.length - 1, j, f, g, h; i >= 0; i--)
  {
    f = head[i]; j = f.indexOf ("=");
    if (!head1) head1 = "*"; head1 = f + "|" + head1;

    if (f && j) if (j > 0)
    {
      g = f.substr (0, j); h = f.substr (j + 1);
      if (g [0] == "!") head3 = head3 + "|" + g.substr(1) + "|" + h; else
        { myheader [g] = decodeURIComponent (h); if (!h) delete myheader [g]; }
    }
    else if (f [0] != "!") head2 = f + (head2 ? ", " : "") + head2; else
    {
      j = f.indexOf (":"); if (j < 0) j = f.length;
      g = f.substr (j + 1); f = f.substr (1, j - 1); param [f] = g;
    }
  }

  //  deprecated because does not work with some servers
  //  if (local < -1 || local > 1) myheader ["accept-encoding"] = "identity";   // no compression

  if (!m3ufix1 && m3ufix2) url = url.replace ("\.ts", "." + m3ufix2);  // for misleading mpeg-2 extension

  ///// CONNECTING TO THE INTERNET /////

  if (local > 0) n = ++reqcount; else n = 0;
  if (m = param ["vpx"]) m = ":" + m; else m = "";

  // for DNS-over-HTTPS (can also be used by non-browser apps)
  if (shadow [0] == "@") { port = portnum; host = shadow.substr (1); shadow = ""; }

  // this is for redirection (HTTP "location" header)
  if (shadow) shadow = shadow_on ? (ssl ? "https" : "http") + "://" + shadow + "/" : proxy_host;

  // don't pass localhost through the socks5 port and don't redirect back to here
  if (host == "localhost" || host == "127.0.0.1") { shadow = "@"; port = portnum; }

  var conn = socket_pool (response.socket, null, origin + m, port, host);
  shadow_on = myheader ["host"]; conn.idle = false; if (conn.timer) clearTimeout (conn.timer);

  var config = {
    method: method, host: origin, refer: refer, referral: referral, cookie: cookie, count: n,
    shadow: shadow, fix1: m3ufix1, fix2: m3ufix2, headers: head1, exposes: head2, mimics: head3
  }

  var options = {
    method: method, hostname: shadow_on, port: portnum, path: url,
    headers: myheader, requestCert: false, rejectUnauthorized: m.substr (-1) == ":",
    servername: shadow_on, socket: conn, createConnection: function() { return conn; }
  }

  if (net.isIP (shadow_on)) options.servername = "";  // prevent runtime warning
  if (m == "::" || m == ":::") m = "";  // allow !vpx to be used to force authentication

  n = param ["timeout"]; if (n) n *= 1000; if (!n) n = 30000; if (n < 5000) n = 5000;

  if (!conn.connecting)
  {
    config.dnsr = "@"; create_request (false); return;
  }

  conn.on ("close", function()
  {
    socket_pool (null, conn); conn.destroy(); clearTimeout (conn.timer);
  });

  conn.on ("end", function() { });  // just in case; seems to be important in proxy_handler

  if (port)
  {
    config.dnsr = "LOCAL"; create_request (true); return;
  }

  conn.write ("CONNECT " + host + " HTTP/!!!\nhost: " + host + ":" + portnum + m + "\n");
  conn.timer = setTimeout (function() { oopsie(); }, n);

  conn.once ("data", function (d)
  {
    d = d.toString().match (/ (.*) (.*)/); config.dnsr = d[2] != "OK" ? d[2] : "";
    if (d[1] != "200") { clearTimeout (conn.timer); oopsie(); } else create_request (true);
  });

  function create_request (connecting)
  {
    if (connecting) if (proxy != https) clearTimeout (conn.timer); else
    {
      // grab a TLS session ticket from another socket
      options.session = socket_pool (null, null, origin + m);
      conn = socket_pool (conn, tls.connect (options));

      // IMPORTANT: wait for this event so we can flag the session ticket as safe to use
      // symptom: internal call by Node.js to getTLSTicket() will sometimes cause a hard crash
      conn.once ("secureConnect", function() { clearTimeout (conn.timer); conn.secure = true; });
      conn.on   ("error", function() { });  // to catch TLS errors
    }

    proxy = proxy.request (options, function (res)
    {
      res.on ("end", function() { if (!conn.destroyed)
      {
        conn.idle = true; conn.timer = setTimeout (function() { conn.end(); }, 15000);
      }});
      proc_handler (response, res, config, local); 
    });

    proxy.on ("error",   function() { oopsie(); });
  //proxy.setTimeout (n, function() { conn.destroy(); });
    request.pipe (proxy, { end:true });
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
  var m, n, s, v, buffer = "", header = {};
  var status = res.statusCode, message = res.statusMessage;

  if (!config.shadow)
  {
    response.writeHead (status, message, res.headers);
    res.pipe (response, { end:true });
    return;
  }

  if (local > 0)
  {
    last_time = 0; n = config.count; s = (s = config.dnsr) ? " - " + s : "";
    console.log (" Request " + n + " - Status " + status + " (" + message + ")" + s);
  }
  else if (local <= 0)
  {
    var the_time = Date.now() / 1000; passthru++;
    var delay = (last_pass == config.host) ? 30 : 20;
    v = config.refer; if (v == last_pass) v = ""; else v = " - " + v;

    if (last_time <= the_time - delay)
    {
      last_time = the_time; last_pass = config.host;
      console.log ("<Passthrough " + passthru + " - " + last_pass + v);
    }
  }

  if (local <= 0 || config.method == "OPTIONS") header = res.headers; else
  {
    var header_name = [
      "connection", "date", "content-type", "content-length", "content-encoding",
      "content-range", "accept-ranges"
    ];

    v = config.exposes.replace (/\s/g, "");
    if (v) header_name = header_name.concat (v.split (","));

    for (n = 0; n < header_name.length; n++)
    {
      s = header_name [n]; v = res.headers [s]; if (v) header [s] = v;
    }
  }

  if (config.mimics)
  {
    var i, j, k = config.mimics.split ("|");
    for (n = 1; n < k.length; n += 2)
    {
      i = k [n]; j = k [n + 1]; if (!i) continue;
      if (j) header [i] = j; else delete header [i];
    }
  }

  if (local < 0 && config.shadow.includes ("."))
  {
    response.writeHead (status, message, header);
    res.pipe (response, { end:true });
    return;
  }

  if (config.shadow != "@" && (v = res.headers [s = "location"]))
  {
    var x = config.host, y = v.substr (0,2), z = config.shadow;
    if (y [0] == "/") { if (y == "//") x = x.substr (0, x.indexOf (y)); v = x + v; }

    if (z == proxy_host) z += config.referral + config.headers; else
    {
      n = v.indexOf ("//"); if ((n = v.indexOf ("/", n + 2)) < 0) n = v.length;
      y = v.substr (0, n); if (y == config.host) v = z + v.substr (n + 1); z = "";
    }

    if (!config.cookie) header [s] = z + v; else
      { delete header [s]; header ["zz-location"] = v; }
  }

  if (config.cookie && (v = res.headers ["set-cookie"])) header ["zz-set-cookie"] = v;

  s = "access-control-expose-headers"; v = res.headers [s]; if (!v) v = "";
  if (config.cookie)  v = v + (v ? ", " : "") + "zz-location, zz-set-cookie";
  if (config.exposes) v = v + (v ? ", " : "") + config.exposes;
  if (v) header [s] = v;

  header ["access-control-allow-origin"] = "*";
  header ["zz-proxy-server"] = proxy_name;

  if (local > -2 && local < 2)
  {
    response.writeHead (status, message, header);
    res.pipe (response, { end:true });
    return;
  }

  var proc = null; v = header ["content-encoding"];
  if (v == "gzip") proc = zlib.createGunzip();
  if (proc) res.pipe (proc); else proc = res;

  proc.on ("error", function () { default_handler (response, 777, local); });

  proc.on ("data", function (data)
  {
    if (buffer.length < 250000) buffer = buffer + data.toString();
  });

  proc.on ("end", function ()
  {
    if (local == -2 || local == 2)
    {
      var mydata = tweak_m3u8 (buffer, config);
      header ["content-encoding"] = "identity";
      header ["content-length"] = mydata.length;
      response.writeHead (status, message, header);
      response.end (mydata);
    }
  });
}

///////////////////////////////////
///// function: proxy_command /////
///////////////////////////////////

function proxy_command (response, cmd, ssl)
{
  var n, p, q, msg, str = setdns = ""; cmd = decodeURIComponent (cmd);

  if ((n = cmd.indexOf ("=")) > 0) { str = cmd.substr (n + 1); cmd = cmd.substr (0, n); }

  cmd = cmd.trim(); str = str.trim(); msg = "Command: " + cmd + (str ? " " + str : "");

  if (cmd == "flags")
  {
    cmd = ""; n = parseInt (str) || 0; if (str) proxy_flags = n & 31;
    str = "Console output is " + (proxy_flags & 1 ? "enabled" : "disabled");
    if (proxy_flags & 16) str += "\n> showing " + (proxy_flags & 1 ? "socket" : "DoH/DNS") + " activity";
    str += "\n\nExpecting TOR at port " + (proxy_flags & 2 ? tor2_port : tor1_port);
    if (proxy_flags & 4) str += "\n> TOR is enabled for ALL";
  }

  if (cmd == "reload")
  {
    if (!str) str = settings; str = init_settings (str) + " (" + str + ")";
    cmd = ""; console.log (">> " + str);  //setdns = "default";
  }

  if (cmd == "activate")
  {
    cmd = ""; if (!str) add_resolver (""); p = str.split (",");
    for (n = 0; n < p.length; n++) if (q = p[n].trim()) add_resolver (q);

    p = init_servers().split(" "); q = '-'.repeat (31);
    q = q + "\nsee console for progress report\n" + q;
    str = " Resolved = " + p[0] + "\n\n  Pending = " + p[1] + "\n\n" + q;
  }

  if (cmd == "servers")
  {
    setdns = str; str = cmd = "";
    for (n = 0; n < server.length; n += 2)
    {
      if (!(p = server [n + 1])) p = "NO ADDRESS";
      str += " " + p + ' '.repeat (21 - p.length) + "> " + server[n] + "\n";
    }
  }

  if (cmd == "dnslookup" && (n = str.indexOf ("=")) >= 0)
  {
    setdns = str.substr (0, n); str = str.substr (n + 1);
  }

  p = dns_servers (setdns); q = doh_address ? " DoH  " + doh_address + "\n" : "";
  if (!p.length) q = " DNS lookup in progress!\n   Please try again...\n";
  for (n = 0; n < p.length; n++) q += " DNS" + (n+1) + " " + p[n] + "\n";

  p = "_".repeat ((n = msg.length) < 25 ? 25 : n);
  msg += "\n" + p + "\n\n" + q + p + "\n";

  if (cmd == "dnslookup" && str)
  {
    if ((n = str.indexOf ("//")) >= 0) str = str.substr (n + 2);
    if ((n = str.indexOf ("/")) >= 0) str = str.substr (0, n);
    if ((n = str.indexOf (":")) >= 0) str = str.substr (0, n);

    var func; p = str.replace (/\d|\./g, ""); msg += "\n " + str + "\n\n";
    if (p) func = dns.resolve4; else if (net.isIP (str)) func = dns.reverse;

    if (func) func (str, function (err, addr)
    {
      if (err) str = " Not resolved\n"; else
        for (n = 0, str = ""; n < addr.length; n++) str += " " + addr [n] + "\n";

      proc_done (response, msg + str, "text/plain", 0);
    });
    if (func) return;
  }

  if (cmd == "vpn")
  {
    cmd = ""; p = str.split (":"); vpn_host = p [0]; vpn_port = parseInt (p [1]);
    if (!net.isIP (vpn_host) || !(vpn_port > 0 && vpn_port <= 65535)) vpn_host = "";

    vpn_name = p [2] || ""; vpn_pass = p [3] || "";
    p = (p [2] || p [3]) ? " (" + p [2] + ":" + p [3] + ")" : "";

    if (!vpn_host) str = "VPN - invalid or not specified"; else
      str = " " + vpn_host + " port " + vpn_port + p;
  }

  if (cmd == "restart") if (ssl) { cmd = ""; str = "Bad idea"; } else
  {
    ssl_server.close (function()
    {
      str = (str + ",").split (",");
      ssl_server = start_ssl_server (str[1].trim(), str[0].trim());
      proc_done (response, msg + "\nHTTPS server restarted.\n", "text/plain", 0);
    });

    socket_pool (null, null); return;
  }

  if (cmd) str = "What??"; proc_done (response, msg + "\n" + str + "\n", "text/plain", 0);
}

///////////////////////////////////
///// function: proxy_handler /////
///////////////////////////////////

function proxy_handler (sock)
{
  var m, n, p, q, host, port, addr, conn, data, done = 5, time = 0;
  var vpn, vhost = "", vport = "", vname = "", vpass = "";
  var socket = ++sockets_count; ++sockets_open;

  sock.on ("error", function() { });
  sock.on ("close", function() { socks_report (0, 1, --sockets_open); socks_abort(); });
  sock.on ("end",   function() { });  // this callback is needed for the "close" event

  sock.once ("data", function (d) { socks_phase_1 (d); });

  function socks_abort ()
  {
    if (!done || sock.readyState != "open")
    {
      if (conn) conn.destroy(); sock.destroy(); return;
    }

    if (time < Date.now())
    {
      if (done == 1) m = (Buffer.from ("\5\4\0\0")); else
      if (done >= 2) m = ("HTTP/1.1 502 Bad Gateway\r\n\n"); else m = "";

      sock.end (m); return;
    }

    if (conn.readyState != "closed") { conn.end(); return; }

    // kickstart a stubborn server but just this once
    setTimeout (function() { socks_phase_4 (""); }, 3000);

    time = 1; conn.destroy(); conn = null; socks_report (0, 3, vhost + ":" + vport);
  }

  function socks_phase_1 (d)
  {
    if (d.length == 3 && d[0] == 5 && d[1] == 1 && d[2] == 0)
    {
      sock.once ("data", function (r) { socks_phase_2 (r); });
      done = 1; sock.write (Buffer.from ("\5\0")); return;
    }

    data = d.toString(); p = data.match (/(.*) (.*) (HTTP\/.*)/);
    q = data.match (/\bhost: (.*)/i); if (q) q = q[1]; else q = "";
    q = q.split (":"); host = q[0]; port = parseInt (q[1]);
    if (!(port > 0 && port <= 65535)) port = 0;

    if (!p || !host || p.length < 4) { socks_abort(); return; }

    if (p[1] == "CONNECT")
    {
      done = p[3] == "HTTP/!!!" ? 2 : 3; if (!port) port = 443;

      if (q.length > 2)
      {
        if (!net.isIP (vhost = q[2])) vhost = ""; vport = parseInt (q[3]);
        if (!vhost || !(vport > 0 && vport <= 65535)) { socks_abort(); return; }
        vname = q[4] || ""; vpass = q[5] || "";
      }
    }
    else
    {
      done = 4; if (!port) port = 80; q = p[2];
      n = q.indexOf ("//"); if (n >= 0) q = q.substr (n + 2);
      n = q.indexOf ("/"); q = n < 0 ? "/" : q.substr (n);

      // this is needed because some servers want ONLY the path string
      data = p[1] + " " + q + " " + data.substr (data.indexOf (p[3]));
    }

    socks_phase_3 (d);
  }

  function socks_phase_2 (d)
  {
    if (d.length > 7 && d[0] == 5 && d[1] == 1)
    {
      if (d[3] == 3 && (n = d[4] + 5) < d.length - 1) host = d.toString ('utf8', 5, n);
      if (d[3] == 1 && (n = 8) < d.length - 1) host = d[4] + "." + d[5] + "." + d[6] + "." + d[7];
    }

    if (!host) socks_abort(); else
    {
      port = d.readUInt16BE (n); socks_phase_3 ("");
    }
  }

  function socks_phase_3 (d)
  {
    if (done != 2 && (p = shadow_host [host + ":" + port]) != undefined)
    {
      socks_report (0, 0, "SHD"); port = p[0] == "$" ? https_port : http_port;
      addr = "localhost"; socks_phase_4 (d); return;
    }

    m = addr = dns_resolve (host, vhost && vport);
    if (vpn = (m [0] == ":") ? m.substr (1,3) : "") m = m.substr (1);

    socks_report (0, 0, m); if (addr == "0.0.0.0") { socks_abort(); return; }

    dns_lookup (addr, host, function (ip) { addr = ip ? ip : host; socks_phase_4 (d); });
  }

  function socks_phase_4 (d)
  {
    if (!vpn || vpn == "vpn") { vhost = addr; vport = port; p = ""; } else
    {
      if (!net.isIP (addr))
      {
        p = Buffer.from ("\5\1\0\3\0" + addr + "\0\0");
        n = addr.length; p [4] = n; p.writeInt16BE (port, n + 5);
      }
      else
      {
        p = Buffer.from ("\5\1\0\1\0\0\0\0\0\0");
        p.writeUInt16BE (port, 8); m = addr.split ("."); 
        p[4] = m[0] * 1; p[5] = m[1] * 1; p[6] = m[2] * 1; p[7] = m[3] * 1;
      }

      if (vpn == "VPN")
      {
        vhost = vpn_host; vport = vpn_port; vname = vpn_name; vpass = vpn_pass;
      }
      else if (vpn == "TOR")
      {
        vhost = "localhost"; vport = proxy_flags & 2 ? tor2_port : tor1_port;
      }
      else if (addr == "i2p")
      {
        vhost = "0.0.0.0"; vport = i2p_port;
      }
    }

    if (vhost == "0.0.0.0")
    {
      vhost = "localhost"; addr = "i2p"; data = d; p = "";
    }

    if (vhost != "localhost" && vhost != "127.0.0.1")
      { if (!time && addr != "LOCAL") time = Date.now() + 12000; } else
        if (vport == socks_port) { socks_abort(); return; }

    conn = net.createConnection (vport, vhost, function() { socks_phase_5 (p); });
    conn.on ("error", function (e) { socks_report (e.code, addr == host ? "" : addr, host); });
    conn.on ("close", function ( ) { socks_report (0, 2, sock.readyState); socks_abort(); });
    conn.on ("end",   function ( ) { });  // this callback is needed for the "close" event
  }

  function socks_phase_5 (d)
  {
    if (!d) { socks_phase_6 (""); return; }

    if (!vname && !vpass)
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

      r = Buffer.from ("\1\0" + vname + "\0" + vpass);
      n = r [1] = vname.length; r [n + 2] = vpass.length;

      conn.write (r);
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
    if (d && (d.length < 3 || d[0] != 5 || d[1] != 0 || d[2] != 0)) { socks_abort(); return; }

    // HTTP responses MUST have two line breaks
    if (done == 1) sock.write (Buffer.from ("\5\0\0\1\0\0\0\0\0\0"));
    if (done == 2) sock.write ("HTTP/!!! 200 " + (vpn ? vpn : "OK") + "\r\n\n");
    if (done == 3) sock.write ("HTTP/1.1 200 OK" + "\r\n\n");
    if (done == 4) conn.write (data);

    if (done == 4 || addr != "i2p") { socks_phase_7 (""); return; }

    sock.once ("data", function (r)
    {
      data = r.toString(); p = data.match (/(.*) (.*) (HTTP\/.*)/);

      if (!p || p.length < 4)  // maybe an SSL connection
      {
        conn.once  ("data", function (d)
        {
          conn.write (r); socks_phase_7 ("");
        });

        conn.write ("CONNECT " + host + " HTTP/1.1\nhost: " + host + ":" + port + "\r\n\n");
        return;
      }

      q = data.match (/\bhost: (.*)/i);
      q = (p[2][0] == "/") ? (q ? q[1] : "") + p[2] : p[2];
      if (q.substr [0,4] != "http") q = "http://" + q;

      data = p[1] + " " + q + " " + data.substr (data.indexOf (p[3]));

      conn.write (data); socks_phase_7 ("");
    });
  }

  function socks_phase_7 (d)
  {
    done = 0; conn.pipe (sock, { end:true }); sock.pipe (conn, { end:true });
  }

  function socks_report (err, data1, data2)
  {
    var msg = ">> " + ((proxy_flags & 17) == 17 ? socket + " - " : "");

    if (!(proxy_flags & 1)) return; else if (err)
    {
      console.log (msg + "ERR: " + err + (data1 ? " - " + data1 : "") + " - " + data2);
      return;
    }

    if (data1 == 0) console.log (msg + host + " <" + port + "> " + (data2 == host ? "" : data2));

    if (!(proxy_flags & 16)) return;
    if (data1 == 1) console.log (" @ " + socket + " - " + data2 + (conn ? "" : " (cancelled)"));
    if (data1 == 2) console.log (" : " + socket + " - " + (done ? "server fail" : data2));
    if (data1 == 3) console.log (" : " + socket + " - server retry - " + data2);
  }
}

////////////////////////////////
///// function: tweak_m3u8 /////
////////////////////////////////

function tweak_m3u8 (data, config)
{
  var regx, fix1 = config.fix1, fix2 = config.fix2;

  if (data.substr (0,5).indexOf ("#") < 0) return (data);

  if (!fix1 && fix2)
  {
    regx = RegExp ("\." + fix2 + "\n", 'g');
    data = data.replace (regx, ".ts" + "\n");
  }

  if (!fix1) fix1 = fix2 = "/"; if (!fix2) fix2 = fix1;
  var myfix = proxy_host + config.referral + config.headers;

  if (fix1.substr (0,4) != "http")
  {
    regx = RegExp ("\nhttp", 'g');
    data = data.replace (regx, "\n" + myfix + "http");
    regx = RegExp ('URI="http', 'g');
    data = data.replace (regx, 'URI="' + myfix + "http");
  }

  if (fix1.substr (0,1) == "/") myfix = myfix + config.host;

  regx = RegExp ("\n" + fix1, 'g');
  data = data.replace (regx, "\n" + myfix + fix2);
  regx = RegExp ('URI="' + fix1, 'g');
  data = data.replace (regx, 'URI="' + myfix + fix2);

  return (data);
}

////////////////////////////////////
///// function: handle_special /////
////////////////////////////////////

function handle_special (request, response, url, local)
{
  var mode = 0, buffer = "";

  if (url == "wanna_boot_dash") mode = 1;
  if (url == "wanna_boot_dash_live") mode = 2;

  if (url.substr (0, 14) == "wanna_scratch=") mode = 3;

  if (!mode) { default_handler (response, 888, local); return; }

  request.on ("data", function (data)
  {
    if (buffer.length < 10000) buffer = buffer + data.toString();
  });

  request.on ("end", function ()
  {
    if (mode == 3)
    {
      local_data (url.substr (14), buffer);
      proc_done (response, "", "", 0); return;
    }

    var name = mode == 1 ? "_blank_dash_mpd.txt" : "_blank_live_mpd.txt";
    var data = fs.existsSync (name) ? fs.readFileSync (name, "utf8") : "";

    if (!data) default_handler (response, 777, local); else
    {
      handle_boot_dash (data, buffer, url); proc_done (response, "", "", 0);
    }
  });
}

//////////////////////////////////////
///// function: handle_boot_dash /////
//////////////////////////////////////

function handle_boot_dash (data, buffer, url)
{
  var sub = buffer.split ("|"); if (sub.length < 9) return;
  var dat = sub[5].split (","); if (dat.length < 4) return;

  var target = data.toString(); var name = "_" + url + "_" + sub[6];

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

  var aud_url = name + "-aud";
  var vid_url = name + "-vid";

  target = target.replace ("~aud_url~", proxy_host + "~!" + aud_url);
  target = target.replace ("~vid_url~", proxy_host + "~!" + vid_url);

  local_data (name, target);
  local_data (aud_url, sub[7]);
  local_data (vid_url, sub[8]);
}

///// End of file /////

/*
if (host == "www.retailmenot.com" || host == "ja3er.com") myheader =
{
  'Host': host,
  'User-Agent': 'test',
  'Accept-Language': 'en-US,en;q=0.5',
  'Accept-Encoding': 'gzip, deflate',
}

var Ciphers =
  "ECDHE-ECDSA-AES128-GCM-SHA256:" +
  "ECDHE-RSA-AES128-GCM-SHA256:" +
  "ECDHE-ECDSA-CHACHA20-POLY1305:" +
  "ECDHE-RSA-CHACHA20-POLY1305:" +
  "ECDHE-ECDSA-AES256-GCM-SHA384:" +
  "ECDHE-RSA-AES256-GCM-SHA384:" +
  "ECDHE-ECDSA-AES256-SHA:" +
  "ECDHE-ECDSA-AES128-SHA:" +
  "ECDHE-RSA-AES128-CBC-SHA:" +
  "ECDHE-RSA-AES128-SHA:" +
  "ECDHE-RSA-AES256-SHA:" +
  "AES128-GCM-SHA256:" +
  "AES256-GCM-SHA384:" +
  "AES128-SHA:" +
  "AES256-SHA";
*/

/*
Below is the cipher list when using "ciphers: 'HIGH'".
With Wireshark, I took a pcap of the node.js TLS handshake.
The TLS fingerprint matches Cluster #33 (https://tlsfingerprint.io/cluster/a0c7d616ebdc8b4c).
Normally, node.js matches https://tlsfingerprint.io/id/6dc4898ff8f86cfb which does not compare with any browser.
Still cannot get past CloudFlare's "Bot Fight Mode" which is currently active at banned.video (September 22, 2020).
Why in the hell is CloudFlare blocking Kraker?

fb7fad0594b51a29cbc9e96c3232c590
ea1e67125a350e006b01e31a96aad448
http://localhost:8080/https://ja3er.com/json
https://ja3er.com/search/fb7fad0594b51a29cbc9e96c3232c590
view-source:http://localhost:8080/https://www.retailmenot.com/
https://www.openssl.org/docs/man1.0.2/man1/ciphers.html
https://testssl.sh/openssl-iana.mapping.html

771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,
  0-23-65281-10-11-35-16-5-13-28-21,,
771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-255,
  0-11-10-35-22-23-13,29-23-1035-25-24,0-1-2
771,49196-49200-163-159-52393-52392-52394-49327-49325-49315-49311-49245-49249-49239-49235-49195-49199-162-158-49326-49324-49314-49310-49244-49248-49238-49234-49188-49192-107-106-49267-49271-196-195-49187-49191-103-64-49266-49270-190-189-49162-49172-57-56-136-135-49161-49171-51-50-69-68-157-49313-49309-49233-156-49312-49308-49232-61-192-60-186-53-132-47-65-255,
  0-11-10-35-22-23-13,29-23-1035-25-24,0-1-2

TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b) 49195
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f) 49199
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9) 52393
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8) 52392
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c) 49196
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030) 49200
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a) 49162
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009) 49161
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013) 49171
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014) 49172
TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c) 156
TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d) 157
TLS_RSA_WITH_AES_128_CBC_SHA (0x002f) 47
TLS_RSA_WITH_AES_256_CBC_SHA (0x0035) 53
TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a) 10

TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x009f)
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xccaa)
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x009e)
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0xc024)
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xc028)
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x006b)
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xc023)
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xc027)
TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x0067)
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)
TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)
TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)
TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003d)
TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003c)
TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff
*/
