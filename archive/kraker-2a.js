/*
Local Proxy Server for Alleycat Player
*/

/*
Improvements from version 1c:

- handle double-slash at start of "location" response header
- handle rare case where "?" immediately follows host name without a slash
- do not strip byte-range headers in non-passthrough mode (problem with seeking on mp4 videos)
- handle socket disconnection error (ECONNRESET) in default_handler (crash issue)
- handle ".well-known/http-opportunistic" request coming from Firefox for 123tvnow.com streams
- delete request headers "origin" and "referer" if set to blank
- complete rewrite of local GET and PUT; security model via _aliases.txt
*/

var fs    = require ('fs');
var http  = require ('http');
var https = require ('https');

var proxy_name = "Kraker-2a";
var proxy_host = "http://localhost:8080/";

var aliases = "_aliases.txt", local_files = new Array ();

var reqcount = passthru = last_time = 0, last_pass = "";

var mime_list = {
  txt: "text/plain", htm: "text/html", js: "application/javascript", json: "application/json",
  jpg: "image/jpeg", png: "image/png", mp3: "audio/mpeg", mp4: "video/mp4", webm: "video/webm",
  mpd: "application/dash+xml", m3u8: "application/x-mpegurl", ts: "video/mp2t"
};

var ssl_key = fs.readFileSync ("_https_key.pem");
var ssl_crt = fs.readFileSync ("_https_crt.pem");

var ssl = { key: ssl_key, cert: ssl_crt, requestCert: false, rejectUnauthorized: false };

http.createServer (http_handler).listen (8080);
https.createServer (ssl, https_handler).listen (8081);

console.log ("=--------------------------------------------------------------------------------=");
console.log (" Kraker (version 2a) - Local Proxy Server - waiting on port 8080 - ctrl-C to exit ");
console.log ("=--------------------------------------------------------------------------------=");

///// End of Setup

/////////////////////////////////////
///// function: default_handler /////
/////////////////////////////////////

function default_handler (response, error, local)
{
  var msg, err_msg, header = {};

  if (response._header)  // socket error while streaming
  {
    console.log ("--Unexpected disconnection--"); return;
  }

  msg = "--------------------\n" +
        " Local Proxy Server \n" +
        "--------------------\n\n" +
        "Version Name: " + proxy_name + " [June 29, 2020]\n\n" +
        "HTTP at 8080 (active), HTTPS at 8081 (stub)\n";

  if (!error) error = 200; else
  {
    msg = "--Service Not Available--";
    if (error == "777") msg = " Local Request: Error";
    if (error == "888") msg = " Local Request: Invalid";
    if (error == "999") msg = "--Invalid Request--";
    if (local > 0) console.log (msg); msg = "";
  }

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
  var header = {};

  var headers = request.headers ["access-control-request-headers"];
  var methods = request.headers ["access-control-request-method"];

  if (headers && headers != "accept" && headers != "range") return false;

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
  var u = url.split ("."), n = u.length - 1;
  var mime = mime_list [u[n]]; return (mime ? mime : "");
}

////////////////////////////////
///// function: local_data /////
////////////////////////////////

function local_data (name, data)
{
  if (data)
  {
    for (var n = local_files.length - 1; n >= 0; n--)
      if (local_files [n]['name'] == name) local_files.splice (n,1);

    if (local_files.length > 49) local_files.splice (0,3);
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

function local_link (url, local)
{
  if (url [0] == "+")
  {
    var dat = fs.existsSync (aliases) ? fs.readFileSync (aliases, "utf8") : "";
    var n = dat.indexOf (url + ","); if (n < 0) n = dat.indexOf (url + "?,");
    if (n < 0) url = ""; else
    {
      url = dat.substr (n + 1, 300);
      url = url.substr (url.indexOf ("+") + 1);
      url = url.substr (0, url.indexOf (";"));
      if (url && local > 0) console.log (" FILE: " + url);
    }
  }
  return (url == aliases ? "" : url);
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

  stream.on ("error", function (err) { default_handler (response, 777, local); });

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
    range = range.substr (range.search ("=") + 1);
    range = range.split ("-"); end = range[1] ? range[1] * 1 : 0;
    if (range[0]) start = range[0] * 1; else { start = size - end - 1; end = 0; }
    if (!end || end >= size) end = size - 1;
    if (start > end) start = end;
    if (end < start) end = start;
  }

  var stream = fs.createReadStream (url, { start: start, end: end });

  stream.on ("error", function (err) { default_handler (response, 777, local); });

  stream.on ("open", function()
  {
    proc_done (response, [size, start, end], mime_type (url), local);
    stream.pipe (response, { end:true });
  });
}

//////////////////////////////////
///// function: http_handler /////
//////////////////////////////////

function http_handler (request, response)
{
  var n, local = portnum = 0;
  var proxy, origin = host = cookie = refer = "";
  var referral = head = head1 = head2 = m3ufix1 = m3ufix2 = "";

  var url = request.url; var method = request.method;

  if (url.substr (0,1) != "/") url = ""; else
  {
    local = 1; url = url.substr (1);
  }

  if (url.substr (0,1) == "~")
  {
    local = -1; url = url.substr (1); referral = "~";
  }

  if (!url || url.search ("\\.well-known") == 0)
  {
    default_handler (response, 0, 0); return;
  }
  
  url = url.replace (/%7C/g, "|");  // Opera and Chrome convert vertical bar to %7C
  // note: (^) is replaced with %5E and anything after (#) is stripped (all browsers)

  if (method == "OPTIONS" && options_proc (request, response, local)) return;

  if (local >= 0) console.log ((local ? ">" : "?") + method + " " + url);

  if (url.search (":|/") < 0)
  {
    if (url [0] == "!") url = url.substr (1);
    n = url.search ("\\?"); if (n >= 0) url = url.substr (0, n);
    if (!local || url.length < 3) default_handler (response, 888, local);
    else if (method == "GET") get_file (request, response, url, local);
    else if (method == "PUT") put_file (request, response, url, local);
    else if (method == "POST") handle_special (request, response, url, local);
    else default_handler (response, 888, local);
    return;
  }

  if (url.substr (0,1) == "*")
  {
    url = url.substr (1); n = url.search ("\\*");
    if (n >= 0) { refer = url.substr (0, n); url = url.substr (n + 1); }
    referral = referral + "*" + refer + "*"; if (!refer) refer = "*";
  }

  if ((n = url.search ("\\|\\*")) >= 0)
  {
    head = url.substr (0, n).split ("|"); url = url.substr (n + 2);
  }

  if ((n = refer.search (",")) >= 0)
  {
    m3ufix1 = refer.substr (n + 1); if (!(refer = refer.substr (0, n))) refer = "*";

    if ((n = m3ufix1.search (",")) >= 0)
    {
      if (n >= 0) { m3ufix2 = m3ufix1.substr (n + 1); m3ufix1 = m3ufix1.substr (0, n); }
      
      if ((n = url.search ("\\.m3u")) > 0)
      {
        var m = url.search ("\\?"); if (m < 0) m = url.length;
        if (m > n + 3 && m < n + 7) local += local;
      }
    }
  }

  if (url.substr (0,1) == "!")  // for DASH videos
  {
    n = url.search ("/"); var ext = url.substr (n + 1);
    url = local_data (url.substr (1, n - 1), "") + ext;
  }

  n = url.search (":");
  if (n < 0 || n > 5) { url = refer + url; n = url.search (":"); }
  if (n > 0 && n < 6) { origin = url.substr (0, n + 3); host = url.substr (n + 3); }

  url = "/"; n = host.search ("/");
  if (n > 0) { url = host.substr (n); host = host.substr (0, n); }
  // if "?" follows host name then ensure that it is preceded by a slash
  if ((n = host.search ("\\?")) > 0) { url += host.substr (n); host = host.substr (0, n); }

  if (origin == "http://") { proxy = http; portnum = 80; }
  if (origin == "https://") { proxy = https; portnum = 443; }

  if (!portnum)
  {
    default_handler (response, 999, local); return;
  }

  if ((n = host.search (":")) > 0)
  {
    portnum = host.substr (n + 1) * 1; host = host.substr (0, n);
  }

  var myheader = request.headers;
  var cookie = myheader ["accept"];
  myheader ["host"] = host;
  origin = origin + host;

  if (!cookie || cookie.substr (0,2) != "**") cookie = ""; else
  {
    myheader ["accept"] = "*/*";
    cookie = cookie.substr (2); if (!cookie) cookie = "null";
    if (cookie != "null") myheader ["cookie"] = cookie;
  }

  if (refer != "null")
  {
    if (refer == "*") refer = origin + "/";
    if (refer) myheader ["origin"] = myheader ["referer"] = refer; else
      { delete myheader ["origin"]; delete myheader ["referer"]; }
  }
  if (!refer) refer = "null";

  if (head) for (var i = head.length - 1, j, f, g, h; i >= 0; i--)
  {
    f = head[i]; j = f.search ("=");
    if (!head1) head1 = "*"; head1 = f + "|" + head1;

    if (f && j) if (j < 0) head2 = f + (head2 ? ", " : "") + head2; else
    {
      g = f.substr (0, j); h = f.substr (j + 1);
      myheader [g] = decodeURIComponent (h);
    }
  }

  if (local < -1 || local > 1) myheader ["accept-encoding"] = "identity";   // no compression

  if (!m3ufix1 && m3ufix2) url = url.replace ("\.ts", "." + m3ufix2);  // for misleading mpeg-2 extension

  if (local > 0) n = ++reqcount; else n = 0;

  var options = {
    method: method, hostname: host, port: portnum, path: url,
    headers: myheader, requestCert: false, rejectUnauthorized: false
  }

  var config = {
    method: method, host: origin, refer: refer, referral: referral, count: n, 
    cookie: cookie, fix1: m3ufix1, fix2: m3ufix2, headers: head1, exposes: head2
  }

  proxy = proxy.request (options, function (res) { proc_handler (response, res, config, local); });

  proxy.on ("error", function () { default_handler (response, 666, local); });

  request.pipe (proxy, { end:true });
}

///////////////////////////////////
///// function: https_handler /////
///////////////////////////////////

function https_handler (request, response)
{
  default_handler (response, 0, 0);
}

//////////////////////////////////
///// function: proc_handler /////
//////////////////////////////////

function proc_handler (response, res, config, local)
{
  var n, s, v, buffer = "", custom_header = false, header = {};

  var status = res.statusCode; var message = res.statusMessage;

  if (local > 0)
  {
    last_time = 0; n = config.count;
    console.log (" Request " + n + " - Status " + status + " (" + message + ")");
  }
  else if (local < 0)
  {
    var the_time = Date.now() / 1000; passthru++;
    var delay = last_pass == config.host ? 30 : 20;

    if (last_time <= the_time - delay)
    {
      last_time = the_time; last_pass = config.host;
      console.log ("<Passthrough " + passthru + " - " + last_pass + " - " + config.refer);
    }
  }

  if (local <= 0 || config.method == "OPTIONS") header = res.headers; else
  {
    var header_name = [
      "connection", "content-type", "content-length", "content-encoding",
      "content-range", "accept-ranges"
    ];

    for (n = 0; n < header_name.length; n++)
    {
      s = header_name [n]; v = res.headers [s]; if (v) header [s] = v;
    }

    if (config.cookie && (v = res.headers ["set-cookie"]))
    {
      s = "zz-set-cookie"; header [s] = v; custom_header = true;
    }
  }

  if ((v = res.headers [(s = "location")]))
  {
    var x = config.host, y = v.substr (0,2);
    if (y [0] == "/") { if (y == "//") x = x.substr (0, x.search (y)); v = x + v; }
    if (config.cookie) { delete (header [s]); s = "zz-location"; custom_header = true; }
    header [s] = (custom_header ? v : proxy_host + config.referral + config.headers + v);
  }

  s = "access-control-expose-headers"; v = res.headers [s]; if (!v) v = "";
  if (custom_header) v = v + (v ? ", " : "") + "zz-location, zz-set-cookie";
  if (config.exposes) v = v + (v ? ", " : "") + config.exposes;
  if (v) header [s] = v;

  header ["zz-proxy-server"] = proxy_name;
  header ["access-control-allow-origin"] = "*";

  if (config.method == "OPTIONS")
  {
    s = "access-control-allow-headers"; v = res.headers [s];
    header [s] = (v = v ? v + ", " : "") + "Accept";
    header ["access-control-max-age"] = "86400";
  }

  if (local > -2 && local < 2)
  {
    response.writeHead (status, message, header);
    res.pipe (response, { end:true });
    return;
  }

  res.on ("data", function (data)
  {
    buffer = buffer + data.toString();
  });

  res.on ("end", function ()
  {
    if (local == -2 || local == 2)
    {
      var mydata = tweak_m3u8 (buffer, config);
      header ["content-length"] = mydata.length;
      response.writeHead (status, message, header);
      response.end (mydata);
    }
  });
}

////////////////////////////////
///// function: tweak_m3u8 /////
////////////////////////////////

function tweak_m3u8 (data, config)
{
  var regx, fix1 = config.fix1, fix2 = config.fix2;

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
  
  if (!mode) { default_handler (response, 888, local); return; }

  request.on ("data", function (data)
  {
    buffer = buffer + data.toString();
  });

  request.on ("end", function ()
  {
    var name = mode == 1 ? "_blank_dash_mpd.txt" : "_blank_live_mpd.txt";

    fs.readFile (name, function (err, data)
    {
      if (err) default_handler (response, 777, local); else
      {
        handle_boot_dash (data, buffer, url);
        proc_done (response, "", "", 0);
      }
    });
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

///// End of file
