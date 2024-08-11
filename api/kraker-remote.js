/*
Remote Proxy Server based on Kraker Local Proxy Server
*/

// for Vercel cloud server
module.exports = (req, res) { http_handler (req, res); }

const net   = require ('net');
const tls   = require ('tls');
const http  = require ('http');
const https = require ('https');

var proxy_name = "Kraker", website = "https://8chananon.github.io/";

var server_path = "https://kraker-remote.vercel.app/?url=";

var camel_case = [
  'host', "Host", 'user-agent', "User-Agent", 'accept', "Accept",
  'accept-language', "Accept-Language", 'accept-encoding', "Accept-Encoding",
  'connection', "Connection", 'content-type', "", 'content-length', "", 'range', ""
];

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
});

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

function default_handler (response, error, err_msg)
{
  var msg, header = {}; if (response.headersSent) return;

  msg = "---------------------\n" +
        " Kraker Remote Proxy \n" +
        "---------------------\n\n" +
        "Deployed on the 9th day of January in the year 2023 (v2).\n\n" +
        "Usage: " + server_path + "<url>\n\nWebsite: " + website + "\n\n" +
        "NODE.JS " + process.version + "\n";

  if (error != 200) msg = "";

  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";
  header ["access-control-allow-headers"] = "*";
  header ["access-control-expose-headers"] = "*";
  header ["accept-ranges"] = "bytes";

  header ["content-type"] = "text/plain";
  header ["content-length"] = (msg = Buffer.from (msg)).length;

  if (!error)
  {
    header ["location"] = err_msg;
    error = 301; err_msg = "Moved Permanently";
  }

  response.writeHead (error, err_msg, header); stream_end (response, msg);
}

//////////////////////////////////
///// function: options_proc /////
//////////////////////////////////

function options_proc (request, response)
{
  var header = {};

  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";
  header ["access-control-max-age"] = "30";
  header ["accept-ranges"] = "bytes";
  header ["content-length"] = "0";

  var headers = request.headers ["access-control-request-headers"];
  var methods = request.headers ["access-control-request-method"];
  if (headers) header ["access-control-allow-headers"] = headers;
  if (methods) header ["access-control-allow-methods"] = methods;

  response.writeHead (200, "OK", header); stream_end (response, "");
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
  try { uri = decodeURIComponent (uri); } catch (e) { } return (uri);
}

//////////////////////////////////
///// function: make_address /////
//////////////////////////////////

function make_address (addr, port, d, m, n)
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
  return (d);
}

//////////////////////////////////
///// function: http_handler /////
//////////////////////////////////

function http_handler (request, response)
{
  var refer, referral, head, head1, head2, head3;
  refer = referral = head = head1 = head2 = head3 = "";
  var m, n, p, q, proxy, conn, port, portnum, local, param = {};

  var method = request.method, shadow = server_path;

  // this url processing is specific to Vercel (because it mangles everything)

  var url = request.url, query = request.query.url || "";
  n = url.indexOf ("?"); if (n < 0) n = url.length;

  if (m = url.substr (1, n - 1)) { url = m; query = ""; } else
  {
    n = query.indexOf ("?"); m = n < 0 ? query : query.substr (0, n);
    n = url.indexOf ("%3F"); query = n < 0 ? "" : "?" + url.substr (n + 3);
    url = m; query = query.replace ("%3D", "=");
  }

  console.log ("[" + url + "]\n[" + query + "]");

  if (!(url = url.replace (/%7C/g, "|")))
  {
    proxy_command (request, response, query); return;
  }

  if (method == "GET")
  {
    if (url == "avatar")      url = website + "toadstool.jpg";
    if (url == "favicon.ico") url = website + url;
    if (url == "headers")     url = "http://www.xhaus.com/headers";
    if (url == "ipcheck")     url = "http://ip-api.com/json";

    if (url == "website") { default_handler (response, 0, website); return; }
  }

  if (method == "OPTIONS")
  {
    options_proc (request, response); return;
  }

  if (url [0] != "~") local = 5; else
  {
    local = 6; referral = "~"; url = url.substr (1);
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

  if ((n = url.indexOf ("://") + 3) > 8 || n < 3) n = 0;
  var origin = url.substr (0, n), host = url.substr (n);

  if ((n = host.indexOf ("/")) < 0) n = host.length;
  url = "/" + host.substr (n + 1); host = host.substr (0, n); 

  if ((n = host.indexOf ("@")) >= 0)
  {
    port = host.substr (n + 1); host = host.substr (0, n);
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

  if (p == "http://")  { proxy = http;  if (!portnum) portnum = 80; }
  if (p == "https://") { proxy = https; if (!portnum) portnum = 443; }

  if (!host || !proxy)
  {
    default_handler (response, 400, "Bad Request"); return;
  }

  if (refer [0] == "~")  // remove all but critical headers
  {
    var h = myheader; myheader = {}; if (!(refer = refer.substr (1))) refer = "*";

    for (n = 0; n < camel_case.length; n += 2)
      if ((p = camel_case [n]) && (q = h [p])) myheader [p] = q;
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
    n = cookie.indexOf ("**", 2); p = cookie.substr (n < 0 ? 2 : n + 2) || "null";
    if ((q = cookie.substr (2, n - 2) || "*/*") == "/") { q = "**" + p; p = "null"; }
    if ((cookie = p) != "null") myheader ["cookie"] = p; myheader ["accept"] = q;
  }

  // strip off the headers added in by Vercel
  m = Object.entries (myheader); delete myheader ["forwarded"]; delete myheader ["x-real-ip"];
  m.forEach (function (x) { if (x[0].search ("-vercel-|-forwarded-") > 0) delete myheader [x[0]]; });

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

  ///// CONNECTING TO THE INTERNET /////

  head = host; head1 = referral + head1;
  if (port && net.isIP (port)) host = port;

  if (m = param ["mock"])
  {
    n = parseInt (m) & 3; if (m.includes ("X")) n += 4;
    if (m.includes ("A")) n += 8; local += n << 5;
  }

  if (local & 96)
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

  var config = {
    method: method, host: origin, cookie: cookie, shadow: shadow,
    headers: head1, exposes: head2, mimics: head3
  }

  var options = {
    method: method, hostname: host, port: portnum, path: url + query,
    headers: myheader, rejectUnauthorized: false, servername: net.isIP (head) ? "" : head
  }
  //if (local & 128) options.ALPNProtocols = ['h2', 'http/1.1'];
  if (local & 256) options.secureContext = secureContext;

  create_request();

/*
  if (!(m = param ["vpx"])) create_request(); else
  {
    m = m.split (m.includes ("+") ? "+" : ":"); head = m[0]; port = safe_numero (m[1]);
    p = safe_decode (m[2]); q = safe_decode (m[3]); m = make_address (host, portnum);

    if (!(net.isIP (head)) || !port) socks_abort(); else
    {
      conn = net.createConnection (port, head, function() { socks_phase_1 (m); });
      conn.on ("close", function() { socks_abort(); }); conn.on ("error", function() { });
    }
  }

  function socks_phase_1 (d)
  {
    if (!p && !q)
    {
      conn.write (Buffer.from ("\5\1\0"));
      conn.once ("data", function (r)
      {
        if (r.length != 2 || r[0] != 5 || r[1] != 0) socks_abort(); else
        {
          conn.write (d); conn.once ("data", function (r) { socks_phase_2 (r); });
        }
      });
      return;
    }

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
          conn.write (d); conn.once ("data", function (r) { socks_phase_2 (r); });
        }
      });
    });
  }

  function socks_phase_2 (d)
  {
    if (d.length < 3 || d[0] != 5 || d[1] != 0 || d[2] != 0) socks_abort(); else
    {
      options.socket = conn; if (proxy == https) conn = tls.connect (options);
      options.createConnection = function() { return conn; }; create_request();
    }
  }
*/

  function create_request ()
  {
    proxy = proxy.request (options, function (res)
    {
      if (conn) res.on ("end", function() { conn.idle = true; conn.end(); });
      proc_handler (response, res, config, local);
    });

    proxy.on ("error", function() { socks_abort(); });
    if (conn) response.on ("close", function() { socks_abort(); });
    request.pipe (proxy, {end:true});
  }

  function socks_abort ()
  {
    if (!conn || !conn.destroy() || !conn.idle) default_handler (response, 502, "Bad Gateway");
  }
}

//////////////////////////////////
///// function: proc_handler /////
//////////////////////////////////

function proc_handler (response, res, config, local)
{
  var m, n, s, v, header = {}, status = res.statusCode, message = res.statusMessage;

  if (local & 2 || config.method == "OPTIONS") Object.assign (header, res.headers); else
  {
    var header_name = [
      "connection", "date", "location", "accept-ranges",
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

  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";

  if (v = res.headers [s = "location"])
  {
    var x = config.host, y = v.substr (0,2), z = config.shadow;
    if (y [0] == "/") v = (y != "//" ? x : x.substr (0, x.indexOf (y))) + v;

    if (v.indexOf ("http:") && v.indexOf ("https:"))
    {
      y = config.path.split ("?")[0].split ("/");
      y [y.length - 1] = v; v = x + y.join ("/");
    }

    if (!config.cookie) header [s] = z + config.headers + v; else
      { delete header [s]; header ["zz-location"] = v; }
  }

  s = "set-cookie"; if (local & 4) delete header [s];
  if (config.cookie && (v = res.headers [s])) header ["zz-set-cookie"] = v;

  s = "access-control-expose-headers"; v = res.headers [s] || "";
  if (config.cookie)  v = v + (v ? ", " : "") + "zz-location, zz-set-cookie";
  if (config.exposes) v = v + (v ? ", " : "") + config.exposes; if (v) header [s] = v;

  response.writeHead (status, message, header); res.pipe (response, {end:true});
}

function proxy_command (request, response, cmd)
{
  default_handler (response, 200, "OK");
}

///// End of file /////

