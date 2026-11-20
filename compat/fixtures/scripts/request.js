// Loon http-request script sample
var headers = Object.assign({}, $request.headers || {});
headers["X-Compat"] = "request";
$done({ url: $request.url, headers: headers, body: $request.body });
