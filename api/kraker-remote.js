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
  "host", "Host", "user-agent", "User-Agent", "accept", "Accept",
  "accept-encoding", "Accept-Encoding", "accept-language", "Accept-Language",
  "connection", "Connection", "cookie", "Cookie"
];

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
  header ["access-control-max-age"] = "3600";
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
  var p = parseInt (str); return ((p < 0 || p > 65535) ? 0 : p);
}

/////////////////////////////////
///// function: safe_decode /////
/////////////////////////////////

function safe_decode (uri)
{
  try { uri = decodeURIComponent (uri); } catch (e) { } return uri;
}

//////////////////////////////////
///// function: http_handler /////
//////////////////////////////////

function http_handler (request, response)
{
  var m, n, portnum, proxy, query, param = {}, local = 0;
  var host, origin, referral, refer, head, head1, head2, head3;
  host = origin = referral = refer = head = head1 = head2 = head3 = "";

  var method = request.method, shadow = server_path;
  var url = request.query.url || "", query = request.url;

  // redirects

  if (method == "GET")
  {
    if (query == "/favicon.ico") url = website + query;
    if (query == "/ipcheck")     url = "http://ip-api.com/json";
    if (query == "/headers")     url = "http://www.xhaus.com/headers";
    if (query == "/avatar")      url = website + "toadstool.jpg";

    if (query == "/website") { default_handler (response, 0, website); return; }
  }

  // this url handling is specific to Vercel

  if ((n = url.indexOf ("?")) < 0) query = ""; else
  {
    m = query.indexOf ("&"); m = m < 0 ? "" : query.substr (m);
    query = url.substr (n) + m; url = url.substr (0, n);
  }

  console.log ("[" + url + "]\n[" + query + "]");
  if (url [0] == "~") { local = 1; url = url.substr (1); }

  if (!url || url [0] == ".")  // filter out ".well-known"
  {
    default_handler (response, 200, "OK"); return;
  }

  if (method == "OPTIONS") { options_proc (request, response); return; }

  if (url [0] == "*")
  {
    url = url.substr (1); n = url.indexOf ("*");
    if (n >= 0) { refer = url.substr (0, n); url = url.substr (n + 1); }
    referral += "*" + refer + "*"; if (!refer) refer = "*";
  }

  if ((n = url.indexOf ("|*")) >= 0)
  {
    head = url.substr (0, n).split ("|"); url = url.substr (n + 2);
  }
  else if ((n = url.indexOf ("~*")) >= 0)
  {
    head = url.substr (0, n).split ("~"); url = url.substr (n + 2);
  }

  if ((n = url.indexOf ("://") + 3) > 2)
    { origin = url.substr (0, n); host = url.substr (n); }

  if ((n = host.indexOf ("/")) < 0) url = "/"; else
    { url = host.substr (n); host = host.substr (0, n); }

  var myheader = request.headers;
  myheader ["host"] = host; m = origin; origin += host;
  var cookie = myheader ["accept"];

  if ((n = host.indexOf (":")) >= 0)
    { portnum = safe_numero (host.substr (n + 1)); host = host.substr (0, n); }

  if (m == "http://") { proxy = http; if (!portnum) portnum = 80; }
  if (m == "https://") { proxy = https; if (!portnum) portnum = 443; }

  if (!host || !proxy)
  {
    default_handler (response, 400, "Bad Request"); return;
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
    myheader ["accept"] = n ? cookie.substr (2, n - 2) : "*/*";
    cookie = cookie.substr (n + 2); if (!cookie) cookie = "null";
    if (cookie != "null") myheader ["cookie"] = cookie;
  }

  // strip off the headers added in by Vercel
  m = Object.entries (myheader); delete myheader ["forwarded"]; delete myheader ["x-real-ip"];
  m.forEach (function (x) { if (x[0].search ("-vercel-|-forwarded-") > 0) delete myheader [x[0]]; });

  if (head) for (var i = head.length - 1, j, f, g, h; i >= 0; i--)
  {
    f = head [i]; if (!head1) head1 = "*"; head1 = f + "|" + head1;

    if ((j = f.indexOf ("=")) < 0)
    {
      if (f [0] != "!") head2 = f + (head2 ? ", " : "") + head2; else
      {
        j = f.indexOf (":"); if (j < 0) j = f.length;
        g = f.substr (j + 1); f = f.substr (1, j - 1); param [f] = g;
      }
      continue;
    }

    g = f.substr (0, j); h = f.substr (j + 1);
    f = g.replace (/[a-z\d\-\+\_\.\!\~\*\$\&\%]/gi, ""); if (f || !g) continue;

    if (g [0] == "!") head3 = head3 + "|" + g.substr(1) + "|" + h; else
    {
      if (h [0] == "!") h = safe_decode (h.substr (1));
      if (h) myheader [g] = h; else delete myheader [g];
    }
  }

  ///// CONNECTING TO THE INTERNET /////

  for (n = 0, head = {}; n < camel_case.length; n += 2)
  {
    m = myheader [camel_case [n]]; if (m == undefined) continue;
    delete myheader [camel_case [n]]; head [camel_case [n + 1]] = m;
  }
  myheader = Object.assign (head, myheader); head = myheader ["Host"];

  var config = {
    method: method, host: origin, cookie: cookie, shadow: shadow,
    headers: referral + head1, exposes: head2, mimics: head3
  }

  var options = {
    method: method, hostname: head, port: portnum, path: url + query,
    headers: myheader, requestCert: false, rejectUnauthorized: false,
    servername: net.isIP (head) ? "" : head
  }

  proxy = proxy.request (options, function (res) { proc_handler (response, res, config, local); });

  proxy.on ("error", function() { default_handler (response, 502, "Bad Gateway"); });

  response.on ("close", function() { proxy.destroy(); });

  request.pipe (proxy, { end:true });
}

//////////////////////////////////
///// function: proc_handler /////
//////////////////////////////////

function proc_handler (response, res, config, local)
{
  var m, n, s, v, header = {};
  var status = res.statusCode, message = res.statusMessage;

  if (local) header = Object.assign (res.headers); else
  {
    var header_name = [
      "connection", "date", "content-type", "content-length",
      "content-encoding", "content-range", "accept-ranges" ];

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
    var i, j, k = config.mimics.split ("|");
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
  delete header [s]; if (v) header ["zz-set-cookie"] = v;

  s = "access-control-expose-headers"; v = res.headers [s] || ""; m = config.exposes;
  header [s] = v + (v ? ", " : "") + "zz-location, zz-set-cookie" + (m ? ", " : "") + m;

  response.writeHead (status, message, header);
  res.pipe (response, { end:true });
}

///// End of file /////

