// Loon Script API surface sample: unsupported in current app
$httpClient.get("https://example.com/ping", function (err, resp) {
  $persistentStore.write("last", "ok");
  $notification.post("compat", "done", "ok");
  $done({});
});
