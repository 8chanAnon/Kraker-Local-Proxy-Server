/*
Remote Proxy Server based on Kraker Local Proxy Server
*/

// for Vercel cloud server
export default function kraker (req, res) { http_handler (req, res); }

const net   = require ('net');
const http  = require ('http');
const https = require ('https');

var proxy_name = "Kraker", website = "https://8chananon.github.io/";

var server_path = "https://kraker-remote.vercel.app/?url=";

var camel_case = [
  'host', "Host", 'user-agent', "User-Agent", 'accept', "Accept",
  'accept-language', "Accept-Language", 'accept-encoding', "Accept-Encoding",
  'connection', "Connection", 'content-type', "", 'content-length', "", 'range', ""
];

const secureContext = require ('tls').createSecureContext
({
  secureOptions: (1 << 19) | require ('crypto').SSL_OP_ALL,
  ecdhCurve: [ 'X25519', 'prime256v1', 'secp384r1', 'secp521r1' ].join (':'),

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

/////////////////////////////////////
///// function: default_handler /////
/////////////////////////////////////

function default_handler (response, error, err_msg)
{
  var msg, header = {}; if (response.headersSent) return;

  msg = "---------------------\n" +
        " Kraker Remote Proxy \n" +
        "---------------------\n\n" +
        "Deployed on the 9th day of January in the year 2023.\n\n" +
        "Usage: " + server_path + "<url>\n\n" +
        "NODE.JS " + process.version + "\n";

  if (error != 200) msg = "";

  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";
  header ["content-length"] = (msg = Buffer.from (msg)).length;
  header ["content-type"] = "text/plain";

  if (!error)
  {
    header ["location"] = err_msg;
    error = 301; err_msg = "Moved Permanently";
  }
  response.writeHead (error, err_msg, header);
  response.end (msg);
}

//////////////////////////////////
///// function: options_proc /////
//////////////////////////////////

function options_proc (request, response)
{
  var header = {};

  header ["accept-ranges"] = "bytes";
  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";
  header ["access-control-max-age"] = "30";
  header ["content-length"] = "0";

  var headers = request.headers ["access-control-request-headers"];
  var methods = request.headers ["access-control-request-method"];
  if (headers) header ["access-control-allow-headers"] = headers;
  if (methods) header ["access-control-allow-methods"] = methods;

  response.writeHead (200, "OK", header); response.end ("");
}

/////////////////////////////////
///// function: safe_numero /////
/////////////////////////////////

function safe_numero (str)
{
  var p = parseInt (str) || 0; return ((p < 0 || p > 65535) ? 0 : p);
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
///// function: http_handler /////
//////////////////////////////////

function http_handler (request, response)
{
  var m, n, portnum, proxy, param = {}, local = 0;
  var host, origin, referral, refer, head, head1, head2, head3;
  host = origin = referral = refer = head = head1 = head2 = head3 = "";

  var method = request.method, shadow = server_path;
  var url = request.url, query = request.query.url || "";
  n = url.indexOf ("?"); m = n < 0 ? url : url.substr (1, n - 1);

  if (m) { url = m; query = ""; } else
  {
    n = query.indexOf ("?"); m = n < 0 ? query : query.substr (0, n);
    n = url.indexOf ("%3F%"); query = n < 0 ? "" : "?" + url.substr (n + 3);
    url = m; query = query.replace ("%3D", "=");
  }

  console.log("[" + url + "]\n[" + query + "]");

  if (!(url = url.replace (/%7C/g, "|")))
  {
    proxy_command (request, response, query); return;
  }

  if (method == "GET")
  {
    if (url == "favicon.ico") url = website + url;
    if (url == "ipcheck")     url = "http://ip-api.com/json";
    if (url == "headers")     url = "http://www.xhaus.com/headers";
    if (url == "avatar")      url = website + "toadstool.jpg";

    if (url == "website") { default_handler (response, 0, website); return; }
  }

  if (method == "OPTIONS")
  {
    options_proc (request, response); return;
  }

  if (url [0] != "~") local = 1; else
  {
    local = 2; referral = "~"; url = url.substr (1);
  }

  if (url [0] == "*")
  {
    url = url.substr (1); n = url.indexOf ("*");
    if (n >= 0) { refer = url.substr (0, n); url = url.substr (n + 1); }
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

  if ((n = url.indexOf ("://") + 3) < 3) n = 0;
  origin = url.substr (0, n); host = url.substr (n);

  if ((n = host.indexOf ("/")) < 0) n = host.length;
  url = "/" + host.substr (n + 1); host = host.substr (0, n); 

  if ((n = host.indexOf ("@")) >= 0) host = host.substr (0, n);

  var myheader = request.headers, cookie = myheader ["accept"];
  m = origin; origin += host; myheader ["host"] = host; delete myheader ["cookie"];

  if ((n = host.indexOf (":")) >= 0)
  {
    portnum = safe_numero (host.substr (n + 1)); host = host.substr (0, n);
  }

  if (m == "http://") { proxy = http; if (!portnum) portnum = 80; }
  if (m == "https://") { proxy = https; if (!portnum) portnum = 443; }

  if (!host || !proxy)
  {
    default_handler (response, 400, "Bad Request"); return;
  }

  if (refer [0] == "!")  // remove all but critical headers
  {
    var p, q, h = myheader; myheader = {}; refer = refer.substr (1);

    for (n = 0; n < camel_case.length; n += 2)
      if ((p = camel_case [n]) && (q = h [p])) myheader [p] = q;
  }

  if (refer != "null")
  {
    if (refer == "*") refer = origin + "/"; m = n = refer;
    if (m.substr (-1) == "/") m = m.substr (0, m.length - 1);
    if (m) myheader ["origin"] = m; else delete myheader ["origin"];
    if (n) myheader ["referer"] = n; else delete myheader ["referer"];
  }

  if (!cookie || cookie.substr (0,2) != "**") cookie = ""; else
  {
    if ((n = cookie.indexOf ("**", 2)) < 0) n = 0;
    myheader ["accept"] = (n ? cookie.substr (2, n - 2) : "") || "*/*";
    cookie = cookie.substr (n + 2); if (!cookie) cookie = "null";
    if (cookie != "null") myheader ["cookie"] = cookie;
  }

  // strip off the headers added in by Vercel
  m = Object.entries (myheader); delete myheader ["forwarded"]; delete myheader ["x-real-ip"];
  m.forEach (function (x) { if (x[0].search ("-vercel-|-forwarded-") > 0) delete myheader [x[0]]; });

  if (head) for (var i = head.length - 1, j, k, f, g, h; i > 0; i--)
  {
    f = head [i]; head1 = f + head [0] + (head1 ? head1 : "*");
    j = f.indexOf ("="); k = f.indexOf (":"); if (k < 0) k = f.length;

    if (j < 0 || k < j) if (f.replace (/[\x21-\x7E]/g, "")) continue; else
    {
      if (f && f [0] != "!") head2 = f + (head2 ? ", " : "") + head2; else
      {
        g = f.substr (1, k - 1); h = f.substr (k + 1); param [g] = h;
      }
      continue;
    }

    g = f.substr (0, j); h = f.substr (j + 1);
    f = h [0] == "!" ? safe_decode (h.substr (1)) : h;

    if (f.replace (/[\x20-\x7E]/g, "") || !g) continue;
    if (g.replace (/[a-z\d\-\+\_\.\!\~\*\$\&\%]/gi, "")) continue;

    if (g [0] == "!") head3 = "\n" + g.substr (1) + "\n" + h + head3; else
      if (f) myheader [g] = f; else delete myheader [g];
  }

  ///// CONNECTING TO THE INTERNET /////

  head1 = referral + head1; head = referral = myheader ["Host"] || host;
  if ((n = referral.indexOf (":")) > 0) referral = referral.substr (0, n);

  if (m = param ["mock"])
  {
    n = safe_numero (m); if (m.includes ("A")) n += 4; local += (n & 7) << 5;
  }

  if (local & 96)
  {
    var p, q, h = {};

    if (local & 32) for (n = 0; n < camel_case.length; n += 2)
    {
      p = camel_case [n]; q = camel_case [n + 1]; m = myheader [p];
      if (q && m != undefined) { delete myheader [p]; h [q] = m; }
    }
    if (local & 64) for (n = 0; n < request.rawHeaders.length; n += 2)
    {
      q = request.rawHeaders [n]; p = q.toLowerCase(); m = myheader [p];
      if (m != undefined) { delete myheader [p]; h [q] = m; }
    }
    myheader = Object.assign (h, myheader);
  }

  var config = {
    method: method, host: origin, cookie: cookie, shadow: shadow,
    headers: head1, exposes: head2, mimics: head3
  }

  var options = {
    method: method, hostname: head, port: portnum, path: url + query,
    headers: myheader, requestCert: false, rejectUnauthorized: false,
    servername: net.isIP (referral) ? "" : referral
  }
  if (local & 128) options.secureContext = secureContext;

  proxy = proxy.request (options, function (res) { proc_handler (response, res, config, local); });

  proxy.on ("error", function() { default_handler (response, 502, "Bad Gateway"); });

  request.pipe (proxy, { end:true });
}

//////////////////////////////////
///// function: proc_handler /////
//////////////////////////////////

function proc_handler (response, res, config, local)
{
  var m, n, s, v, header = {};
  var status = res.statusCode, message = res.statusMessage;

  if (local & 2) header = Object.assign (res.headers); else
  {
    var header_name = [
      "connection", "date", "location", "accept-ranges",
      "content-type", "content-encoding", "content-length", "content-range" ];

    v = config.exposes.replace (/\s/g, "");
    if (v) header_name = header_name.concat (v.split (","));

    for (n = 0; n < header_name.length; n++)
    {
      s = header_name [n]; v = res.headers [s]; if (v) header [s] = v;
    }
  }

  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";

  if (config.mimics)
  {
    var i, j, k = config.mimics.split ("\n");
    for (n = 1; n < k.length; n += 2)
    {
      i = k [n]; j = k [n + 1]; if (!i) continue;
      if (j [0] == "!") j = safe_decode (j.substr (1));
      if (j) header [i] = j; else delete header [i];
    }
  }

  if (v = res.headers [s = "location"])
  {
    var x = config.host, y = v.substr (0,2), z = config.shadow;
    if (y [0] == "/") { if (y == "//") x = x.substr (0, x.indexOf (y)); v = x + v; }

    if (!config.cookie) header [s] = z + config.headers + v; else
      { delete header [s]; header ["zz-location"] = v; }
  }

  s = "set-cookie"; v = res.headers [s];
  if (config.cookie && v) header ["zz-set-cookie"] = v;
  delete header [s];

  s = "access-control-expose-headers"; v = res.headers [s] || "";
  if (config.cookie)  v = v + (v ? ", " : "") + "zz-location, zz-set-cookie";
  if (config.exposes) v = v + (v ? ", " : "") + config.exposes;
  if (v) header [s] = v;

  response.writeHead (status, message, header);
  res.pipe (response, { end:true });
}

function proxy_command (request, response, cmd)
{
  default_handler (response, 200, "OK");
}

///// End of file /////

