// Loon http-response script sample
$done({
  status: 200,
  headers: Object.assign({}, $response.headers || {}, {"X-Compat": "response"}),
  body: $response.body
});
