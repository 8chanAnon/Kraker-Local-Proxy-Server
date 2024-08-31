/*
Kraker Mockery Server
*/

const fs    = require ('fs');
const net   = require ('net');
const http  = require ('http');
const https = require ('https');
const zlib  = require ('zlib');
const crypt = require ('crypto');

process.on ("uncaughtException", function (error, origin)
{
  console.log (error.stack);
  fs.writeFile ("_crashlog.txt", error.stack, function() { process.exit (1); });
});

http.globalAgent = new http.Agent ({ keepAlive:true });
https.globalAgent = new https.Agent ({ keepAlive:true });

var proxy_name = "kraker-mockery", proxy_addr = "127.0.0.1";

var http_host = 8080, http_port = 8082, https_port = 8083, bridge_port = 8084;

var mocksock, reqcount = {}, local = 0, settings = { name: "", shadow: false };

var mime_list = [
  'txt', "text/plain", 'htm', "text/html", 'html', "text/html", 'css', "text/css",
  'js', "text/javascript", 'js', "application/javascript", 'json', "application/json", 'ico', "image/x-icon",
  'gif', "image/gif", 'png', "image/png", 'jpeg', "image/jpeg", 'jpg', "image/jpeg", 'webp', "image/webp",
  'mpd', "application/dash+xml", 'm3u8', "application/vnd.apple.mpegurl", 'm3u8', "application/x-mpegurl"
];

console.log ("=---------------------------------------------------=");
console.log (" Kraker Mockery (version 1) ... waiting on port " + http_port);
console.log ("=---------------------------------------------------=");

// fix home directory if command line includes "-home"
if (process.argv.includes ("-home")) process.chdir (__dirname);

console.log ("@ Home directory is located at " + process.cwd());

var state, http_server, https_server; start_servers ("", "");

///// End of Setup /////

///////////////////////////////////
///// function: start_servers /////
///////////////////////////////////

function start_servers (crtfile, keyfile)
{
  if (!keyfile) keyfile = "_https_key.pem";
  if (!crtfile) crtfile = "@mock.pem"; var default_crt = "_https_crt.pem";

  var ssl_key = ""; try { ssl_key = fs.readFileSync (keyfile); } catch {};
  var ssl_crt = ""; try { ssl_crt = fs.readFileSync (crtfile); } catch {};

  if (!ssl_crt) try { ssl_crt = fs.readFileSync (default_crt); } catch {};

  var options = {
    key: ssl_key, cert: ssl_crt, handshakeTimeout: 5000, connectionsCheckingInterval: 86400000
  }

  if (!state)
  {
    net.createServer (proxy_handler).listen (bridge_port, proxy_addr);
    http_server = http.createServer (options, http_handler).listen (http_port, proxy_addr);
    https_server = https.createServer (options, http_handler).listen (https_port, proxy_addr);
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
  http_server.maxConnections = https_server.maxConnections = 50;

  if (!state) state = []; return ("HTTPS certificate: okay");
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

  msg = "Kraker Mockery (NODE.JS " + process.version + ")\n";

  if (error == 200) err_msg = "OK"; else
  {
    err_msg = "Not Working"; msg = "--Service Not Available--";
    if (error == 777) msg = "Local Request: Error";
    if (error == 888) msg = "Local Request: Invalid";
    if (error == 999) msg = "--Invalid Request--";
    if (local & 1) console.log (msg); msg = "";
  }

  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";

  header ["content-type"] = "text/plain";
  header ["content-length"] = (msg = Buffer.from (msg)).length;

  response.writeHead (error, err_msg, header); stream_end (response, msg);
}

///////////////////////////////
///// function: proc_done /////
///////////////////////////////

function proc_done (response, data, mime, local)
{
  var header = {};

  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";

  if (mime) header ["content-type"] = mime;
  if (mime) header ["x-content-type-options"] = "nosniff";

  header ["content-length"] = (data = Buffer.from (data)).length;

  response.writeHead (200, "OK", header); stream_end (response, data);
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

function mime_type (str)
{
  if (!str) return ""; str = str.toLowerCase();
  var m, n = str.lastIndexOf (".") + 1; str = str.substr (n);
  for (n = 0; n < mime_list.length; n++) if (mime_list [n++] == str) m = n;
  return (m ? mime_list [m] : "");
}

///////////////////////////////
///// function: file_type /////
///////////////////////////////

function file_type (str)
{
  if (!str) return ""; str = str.toLowerCase();
  var m, n = str.indexOf (";"); if (n > 0) str = str.substr (0, n);
  for (n = 0; n < mime_list.length; n++) if (mime_list [++n] == str) m = n;
  return (m ? mime_list [m - 1] : "");
}

/////////////////////////////////
///// function: save_stream /////
/////////////////////////////////

function save_stream (stream, resp, name, gzip)
{
  var proc = stream, file = fs.createWriteStream (name);

  if (gzip == "gzip") { proc = zlib.createGunzip(); stream.pipe (proc); }

  file.on ("error", function() { console.log ("@ Error writing " + name); });

  if (resp) resp.stream = file; proc.pipe (file, {end:true});
}

//////////////////////////////////
///// function: http_handler /////
//////////////////////////////////

function http_handler (request, response)
{
  var m, n, p, q, portnum, proxy, conn, mock = "";
  var safe = !state.includes (request.socket.remotePort);

  var method = request.method, ssl = request.socket.encrypted ? 1 : 0;
  var localhost = "localhost:" + (ssl ? https_port : http_port);
  var shadow = request.headers ["host"] || localhost;

  var url = request.url; if ((n = url.indexOf ("#")) >= 0) url = url.substr (0, n);
  if ((n = url.indexOf ("?")) < 0) n = url.length; var query = url.substr (n);
  url = (url.substr (0, n)).replace (/\\/g, "/").replace (/%7C/g, "|");

  if (!shadow.indexOf (proxy_addr + ":")) shadow = shadow.replace (proxy_addr, "localhost");

  if (url [0] != "/") safe = false; else if (shadow == localhost)
  {
    url = url.substr (1); if (!url) { proxy_command (request, response, query); return; }
  }
  else url = (ssl ? "https://" : "http://") + shadow + url;

  // if (method == "OPTIONS") { options_proc (request, response); return; }

  if (local & 1)
  {
    if ((m = url.length) > 200) m = 200;
    if ((n = query.length) + m > 220) n = 220 - m;
    p = url.substr (0, m); if (p.length < url.length) p += "...";
    q = query.substr (0, n); if (q.length < query.length) q += "...";
    console.log (">" + method + " " + p + q);
  }

  if ((n = url.indexOf ("://") + 3) > 8 || n < 3) n = 0;
  var origin = url.substr (0, n), host = url.substr (n);

  if ((n = host.indexOf ("/")) < 0) n = host.length;
  url = "/" + host.substr (n + 1); host = host.substr (0, n); 

  if (n = host.indexOf ("@") + 1)
  {
    mock = host.substr (n); host = host.substr (0, n - 1);
  }

  var myheader = request.headers; myheader ["host"] = host; p = origin; origin += host;

  if (host [0] == "[" && (n = host.indexOf ("]") + 1))
  {
    m = host.substr (n); host = host.substr (1, n - 2);
    portnum = safe_numero (m.substr (m.lastIndexOf (":") + 1));
  }
  else if (n = host.lastIndexOf (":") + 1)
  {
    portnum = safe_numero (host.substr (n)); host = host.substr (0, n - 1);
  }

  if (host == "localhost") host = proxy_addr;
  if (host == proxy_addr && portnum == bridge_port) p = "";

  if (p == "http://")  { proxy = http;  portnum = portnum || 80; }
  if (p == "https://") { proxy = https; portnum = portnum || 443; }

  if (!host || !proxy)
  {
    default_handler (response, 999, local); return;
  }

  var name = "", file = "", seq = "", count = 0;

  if (m = settings.name)
  {
    if (m [0] == "#") m = m.substr (1); else file = m; count = reqcount [m] || 0;
    reqcount [m] = ++count; seq = "#" + (count < 1000 ? ("00" + count).substr (-3) : count);
  }

  if (file) if (method != "GET" && method != "POST") file = ""; else
  {
    if (method == "POST")
    {
      name = file_type (myheader ["content-type"]); if (!name) name = "txt";
      name = file + "/" + seq.substr (1) + "-post." + name;
      save_stream (request, null, name, "");
    }
    myheader ["accept-encoding"] = "gzip";
  }

  for (m = {}, n = 0; n < request.rawHeaders.length; n += 2)
  {
    q = request.rawHeaders [n]; p = q.toLowerCase();
    m [q] = myheader [p]; delete myheader [p];
  }
  myheader = Object.assign (m, myheader);
  m = []; for (n in myheader) m.push (n, myheader [n]);

  var report = {
    sequence: seq, method: method, host: origin, path: url,
    query: query, filename: name, headers: m
  }

  send_message (mocksock, JSON.stringify (report));

  if (mock)
  {
    if (m = safe_numero (mock)) { mock = proxy_addr; portnum = m; }
      else if (!net.isIP (mock)) mock = "";
  }
  else if (safe && settings.shadow)
  {
    host = proxy_addr; portnum = http_host;
    proxy = http; url = origin + url;
  }

  var config = {
    method: method, host: origin, file: file, seq: seq, count: count,
  }

  var options = {
    method: method, hostname: mock || host, port: portnum, path: url + query,
    headers: myheader, rejectUnauthorized: false, servername: net.isIP (host) ? "" : host
  }

  proxy = proxy.request (options, function (res)
  {
    res.on ("end", function()
    {
      conn.timer = setTimeout (function() { conn.destroy(); }, 30000);
    });

    proc_handler (response, res, config);
  });

  proxy.on ("upgrade", function (res, xx, buf)  // websocket
  {
    var sock = response.socket; if (buf.length) conn.unshift (buf);
    conn.pipe (sock, {end:true}); sock.pipe (conn, {end:true});
    config.method = ""; proc_handler (response, res, config);
  });

  proxy.on ("error", function() { oopsie(); });
  proxy.on ("socket", function (s) { clearTimeout ((conn = s).timer); });
  proxy.setTimeout (60000, function() { oopsie(); });
  request.pipe (proxy, {end:true});

  function oopsie ()
  {
    if (m = response.stream) stream_end (m, "");
    default_handler (response, 666, local); if (conn) conn.destroy();
  }
}

//////////////////////////////////
///// function: proc_handler /////
//////////////////////////////////

function proc_handler (response, res, config)
{
  var s, v, report, header = res.headers;
  var status = res.statusCode, message = res.statusMessage;

  if (local & 1)
    console.log (" Request " + config.count + " - Status " + status + " (" + message + ")");

  if (config.seq) report = {
    sequence: config.seq, filename: "", type: "",
    status: status, message: message, headers: res.rawHeaders
  }

  if (!config.method)  // websocket
  {
    response.writeHead (status, message, header); stream_end (response, "");
    if (report) send_message (mocksock, JSON.stringify (report)); return;
  }

  if (report)
  {
    v = (header ["content-type"] || "").toLowerCase(); report.type = v.split (";")[0];

    if (!v.indexOf ("video/")) v = ""; else
      if (!v.indexOf ("image/")) v = ""; else
        if (!(v = file_type (v)) || v == "mpd" || v == "m3u8") v = "txt";

    if (v && config.file && (status == 200 || status == 201))
    {
      v = config.file + "/" + config.seq.substr (1) + "-resp." + v;
      s = header ["content-encoding"] || ""; report.filename = v;
      save_stream (res, response, v, s);
    }

    send_message (mocksock, JSON.stringify (report));
  }

  response.writeHead (status, message, header); res.pipe (response, {end:true});
}

///////////////////////////////////
///// function: proxy_command /////
///////////////////////////////////

function proxy_command (request, response, cmd)
{
  var m, n, p, q, msg, str, xtra;

  n = request.method == "GET"; cmd = cmd.replace (/\s|%20/g, "");
  m = (cmd + "==").split ("="); cmd = m[0].substr (1); str = m[1];
  xtra = m[2]; msg = "Command: " + cmd + " " + str + " " + xtra;

  if (n && request.headers ["upgrade"] == "websocket")
  {
    websocket (request, response); return;
  }

  if (!n || !cmd)
  {
    default_handler (response, n ? 200 : 888, 0); return;
  }

  if (cmd == "restart")
  {
    cmd = ""; m = (str + "+").replace (/,/g, "+").split ("+");
    console.log ("@ " + (str = start_servers (m[0], m[1])));
  }

  if (cmd == "delete" && str)
  {
    cmd = "Files deleted."; if (fs.existsSync (str)) p = fs.statSync (str);

    if (!p || !p.isDirectory()) cmd = "No such directory."; else try
    {
      fs.readdirSync (str, { withFileTypes: true }).forEach (x => { if (x.isFile())
        if ((q = x.name).search ("-(post|resp)\.") > 0) fs.unlinkSync (str + "/" + q); });
    }
    catch(e) { console.log (e); cmd = "Unknown error."; }

    reqcount [str] = 0; str = cmd; cmd = ""; console.log ("@ " + str);
  }

  proc_done (response, (cmd ? "What??" : str) + "\n", "text/plain", 0);
}

///////////////////////////////////
///// function: proxy_handler /////
///////////////////////////////////

function proxy_handler (sock)
{
  var n, p, q, conn, port;

  sock.on ("error", function() { });
  sock.on ("close", function() { socks_abort(); });
  sock.on ("end",   function() { });

  sock.once ("readable", function () { socks_connect(); });

  function socks_abort ()
  {
    if (port && (n = state.indexOf (port)) >= 0)
    {
      port = 0; state.splice (n, 1);
    }

    if (conn) conn.destroy(); sock.destroy();
  }

  function socks_connect ()
  {
    p = sock.read(); if (!p || !p.length) return; n = https_port;

    if (p [0] != 0x16 && (q = p.toString().match (/(.*) (.*) /)))
      if (q [1] != "CONNECT") n = http_port; else p = "";

    conn = net.createConnection (n, proxy_addr, function()
    {
      port = this.localPort; state.push (port);
    });

    conn.on ("error", function () { });
    conn.on ("close", function () { socks_abort(); });
    conn.on ("end",   function () { });

    if (p) sock.unshift (p); else sock.write ("HTTP/1.1 200 OK" + "\r\n\n");
    conn.pipe (sock, {end:true}); sock.pipe (conn, {end:true});
  }
}

///////////////////////////////
///// function: websocket /////
///////////////////////////////

function websocket (request, response)
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

  if (mocksock) mocksock.destroy(); mocksock = sock;

  send_message (sock, "Kraker Mockery says hello.");
  console.log ("@ websocket opened");

  sock.on ("close", function()
  {
    sock.destroy(); if (sock == mocksock) mocksock = null;
    console.log ("@ websocket closed"); settings = {};
  });

  sock.on ("data", function (buf)
  {
    start = 2; opcode = buf [0] & 15; size = buf [1] & 127;
    if (size == 127 || (opcode != 0 && opcode != 1)) size = -1;
    if (size == 126) { start = 4; size = buf.readUInt16BE(2); }
    if (size < 0 || size > 10000) { sock.destroy(); return; }

    msg = take_message (buf, start, size, buf [1] & 128);

    try { p = JSON.parse (msg); } catch { p = ""; }

    if (typeof (p.name) != "string" || typeof (p.shadow) != "boolean") p = "";
    if (p && p.name.search (/[:?*.\s\\/]/) >= 0) p = "";

    if (!p || !(q = p.name) || q == "#")
    {
      send_message (sock, "Configuration seems wrong."); settings = {}; return;
    }

    settings = p; q = q [0] == "#" ? "Not saving" : "Save: " + q;
    send_message (sock, q + ", Shadow: " + p.shadow);
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

///// End of file /////

