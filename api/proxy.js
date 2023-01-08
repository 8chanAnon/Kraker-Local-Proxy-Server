/*
Remote Proxy Server based on Kraker Local Proxy Server
*/

export default function proxythis (req, res) { http_handler (req, res); }

const fs    = require ('fs');
const http  = require ('http');
const https = require ('https');

const net   = require ('net');
const tls   = require ('tls');

process.on ("uncaughtException", function (error, origin)
{
  console.log (error.stack);
  fs.writeFile ("_crashlog.txt", error.stack, function() { process.exit (1); });
});

var proxy_name = "Kraker-rv1", server_name = "kraker-remote.vercel.app";

var mime_list = {
  txt: "text/plain", htm: "text/html", html: "text/html", js: "application/javascript", json: "application/json",
  gif: "image/gif", jpeg: "image/jpeg", jpg: "image/jpeg", png: "image/png", mp3: "audio/mpeg", mp4: "video/mp4",
  webm: "video/webm", mpd: "application/dash+xml", m3u8: "application/x-mpegurl", ts: "video/mp2t"
};

var camel_case = [
  "host", "Host", "user-agent", "User-Agent", "accept", "Accept",
  "accept-encoding", "Accept-Encoding", "accept-language", "Accept-Language",
  "connection", "Connection", "cookie", "Cookie"
];

//http.createServer (http_handler).listen (8082);

console.log ("Kraker Remote Proxy Server");

/////////////////////////////////////
///// function: default_handler /////
/////////////////////////////////////

function default_handler (response, error, local)
{
  var msg, err_msg, header = {};

  if (response.headersSent)  // socket error while streaming
  {
    return;  //if (local) console.log ("--Unexpected disconnection--");
  }

  msg = "---------------------\n" +
        " Kraker Proxy Server \n" +
        "---------------------\n\n" +
        " NODE.JS " + process.version + "\n";

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

  header ["accept-ranges"] = "bytes";
  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";
  header ["access-control-allow-headers"] = "*";
  header ["access-control-expose-headers"] = "*";

  header ["content-type"] = "text/plain";
  header ["content-length"] = (msg = Buffer.from (msg)).length;

  response.writeHead (error, err_msg, header);
  response.end (msg);
}

///////////////////////////////
///// function: proc_done /////
///////////////////////////////

function proc_done (response, data, mime, local)
{
  var header = {};

  header ["accept-ranges"] = "bytes";
  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";
  header ["access-control-allow-headers"] = "*";
  header ["access-control-expose-headers"] = "*";

  if (typeof (local) == "string")
  {
    header ["access-control-allow-credentials"] = "true";
    header ["access-control-allow-origin"] = local; local = 0;
  }

  var msg = "OK"; if (mime) header ["content-type"] = mime;

  if (typeof (data) != "object")
  {
    if (local & 1) console.log (" Local Request: " + msg);
    header ["content-length"] = (data = Buffer.from (data)).length;
    response.writeHead (200, msg, header);
    response.end (data); return;
  }

  var size = data[0], start = data[1], end = data[2];
  if (data [3]) header ["last-modified"] = data [3];
  header ["content-length"] = end - start + 1;

  if (size > 0)
  {
    header ["content-range"] = "bytes " + start + "-" + end + "/" + size;
    msg = "Partial Content"; response.writeHead (206, msg, header);
  }
  else if (size < 0) response.writeHead (200, msg, header); else
  {
    msg = "Not Modified"; response.writeHead (304, msg, header);
  }
  if (local & 1) console.log (" Local Request: " + msg);
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
  try { uri = decodeURIComponent (uri); } catch (e) { } return uri;
}

///////////////////////////////
///// function: mime_type /////
///////////////////////////////

function mime_type (url)
{
  var n = url.lastIndexOf (".");
  url = url.substr (n + 1).toLowerCase();
  return ((url = mime_list [url]) ? url : "");
}

//////////////////////////////////
///// function: http_handler /////
//////////////////////////////////

function http_handler (request, response)
{
  var m, n, portnum, proxy, local = 0;
  var host, origin, referral, refer, head, head1, head2, head3;
  host = origin = referral = refer = head = head1 = head2 = head3 = "";

  var method = request.method, shadow = "https://" + request.headers ["host"];

  // get the path string and split off the query string
  var url = request.url; n = url.indexOf ("?");
  if (n < 0) n = url.length; var query = url.substr (n);

  // substitute backslashes (sanity check)
  // Opera and Chrome convert vertical bar to %7C
  url = (url.substr (0, n)).replace (/\\/g, "/").replace (/%7C/g, "|");

  if (url [0] == "/") url = url.substr (1);

  if (!url || url [0] == ".")  // filter out ".well-known"
  {
    default_handler (response, 200, 0); return;
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
  if (url [0] == "/") url = url.substr (1);

  if ((n = url.indexOf ("://") + 3) > 2)
  {
    origin = url.substr (0, n); host = url.substr (n);
  }

  if ((n = host.indexOf ("/")) < 0) url = "/"; else
  {
    url = host.substr (n); host = host.substr (0, n);
  }

  var myheader = request.headers;
  myheader ["host"] = host; m = origin; origin += host;
  var cookie = myheader ["accept"];

  if ((n = host.indexOf (":")) >= 0)
  {
    portnum = safe_numero (host.substr (n + 1)); host = host.substr (0, n);
  }

  if (m == "http://") { proxy = http; if (!portnum) portnum = 80; }
  if (m == "https://") { proxy = https; if (!portnum) portnum = 443; }

  if (!host || !proxy)
  {
    default_handler (response, 999, local); return;
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
    method: method, host: origin, origin: localhost, cookie: cookie, shadow: shadow,
    headers: referral + head1, exposes: head2, mimics: head3
  }

  var options = {
    method: method, hostname: head, port: portnum, path: url + query,
    headers: myheader, requestCert: false, rejectUnauthorized: false,
    servername: net.isIP (head) ? "" : head
  }

  proxy = proxy.request (options, function (res) { proc_handler (response, res, config, local); });

  proxy.on ("error", function () { default_handler (response, 666, local); });

  request.pipe (proxy, { end:true });
}

//////////////////////////////////
///// function: proc_handler /////
//////////////////////////////////

function proc_handler (response, res, config, local)
{
  var m, n, s, v, buffer = "", header = {};
  var status = res.statusCode, message = res.statusMessage;

  var header_name = [
    "connection", "date", "access-control-allow-credentials", "access-control-allow-origin",
    "content-type", "content-length", "content-encoding", "content-range", "accept-ranges" ];

  v = config.exposes.replace (/\s/g, "");
  if (v) header_name = header_name.concat (v.split (","));

  for (n = 0; n < header_name.length; n++)
  {
    s = header_name [n]; v = res.headers [s]; if (v) header [s] = v;
  }

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
    var x = config.host, y = v.substr (0,2), z = config.shadow + "/";
    if (y [0] == "/") { if (y == "//") x = x.substr (0, x.indexOf (y)); v = x + v; }

    if (!config.cookie) header [s] = z + config.headers + v; else
      { delete header [s]; header ["zz-location"] = v; }
  }

  s = "set-cookie"; v = res.headers [s];
  delete header [s]; if (v) header ["zz-set-cookie"] = v;

  s = "access-control-expose-headers"; v = res.headers [s] || "";
  if (config.cookie)  v = v + (v ? ", " : "") + "zz-location, zz-set-cookie";
  if (config.exposes) v = v + (v ? ", " : "") + config.exposes;
  if (v) header [s] = v;

  response.writeHead (status, message, header);
  res.pipe (response, { end:true });
}

///// End of file /////

