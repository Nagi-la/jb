/* MagicRule rule filter for Loon, Shadowrocket, Quantumult X and Stash. */
(function () {
  "use strict";

  var PROFILES = {
    loon: {format: "plain", bits: {"DOMAIN":1,"DOMAIN-SUFFIX":2,"DOMAIN-KEYWORD":4,"USER-AGENT":8,"URL-REGEX":16,"IP-CIDR":32,"IP-CIDR6":64,"GEOIP":128,"IP-ASN":256,"SRC-PORT":512,"DEST-PORT":1024,"PROTOCOL":2048,"AND":4096,"OR":8192,"NOT":16384}},
    shadowrocket: {format: "plain", bits: {"DOMAIN":1,"DOMAIN-SUFFIX":2,"DOMAIN-KEYWORD":4,"USER-AGENT":8,"URL-REGEX":16,"IP-CIDR":32,"IP-CIDR6":64,"GEOIP":128,"IP-ASN":256,"DEST-PORT":512,"PROTOCOL":1024,"PROCESS-NAME":2048,"IN-PORT":4096,"SRC-IP":8192,"AND":32768,"OR":65536,"NOT":131072}},
    quantumultx: {format: "plain", bits: {"HOST":1,"HOST-SUFFIX":2,"HOST-WILDCARD":4,"HOST-KEYWORD":8,"USER-AGENT":16,"URL-REGEX":32,"IP-CIDR":64,"IP6-CIDR":128,"GEOIP":256,"IP-ASN":512}},
    stash: {format: "stash-yaml", bits: {"DOMAIN":1,"DOMAIN-SUFFIX":2,"DOMAIN-KEYWORD":4,"DOMAIN-WILDCARD":8,"DOMAIN-REGEX":16,"IP-CIDR":32,"IP-CIDR6":64,"IP-ASN":128,"NETWORK":256,"USER-AGENT":512,"URL-REGEX":1024,"GEOSITE":2048,"PROTOCOL":4096,"PROCESS-NAME":8192,"PROCESS-PATH":16384,"DST-PORT":32768,"GEOIP":65536,"SCRIPT":131072,"OR":262144,"AND":524288,"NOT":1048576}}
  };
  var CLIENT_PROFILE = "shadowrocket";
  var LOCAL_MAX = 512 * 1024;
  var EXCLUDE_LOCAL_MAX = 1024 * 1024;
  var SHORT_ARTIFACT_ORIGIN = "https://magicrule.pages.dev/data/_shared/artifacts/";

  function query(url, name, shortName) {
    var parsed = new URL(url);
    var value = parsed.searchParams.get(name);
    return value === null && shortName ? parsed.searchParams.get(shortName) : value;
  }
  function profileFromUrl(url) {
    if (!/^\/[^/]+$/.test(new URL(url).pathname)) throw new Error("unsupported client filter path");
    return CLIENT_PROFILE;
  }
  function parseCompose(value, profile) {
    if (!/^[1-9]\d*$/.test(value || "")) throw new Error("compose must be a positive integer");
    var compose = Number(value);
    var mask = Object.keys(PROFILES[profile].bits).reduce(function (result, type) {
      return result | PROFILES[profile].bits[type];
    }, 0);
    if (!Number.isSafeInteger(compose) || (compose & ~mask) !== 0) throw new Error("unsupported compose bits");
    return compose;
  }
  function flag(value, name) {
    if (value === null || value === "" || value === "0") return false;
    if (value === "1") return true;
    throw new Error(name + " must be 0 or 1");
  }
  function parseExclude(value) {
    if (value === null || value === "") return null;
    if (value.length > 256 || /[\u0000-\u001f\u007f]/.test(value)) throw new Error("exclude must be at most 256 printable characters");
    return value.toLowerCase();
  }
  function matchesGlob(value, pattern) {
    value = String(value || "").toLowerCase();
    var valueIndex = 0, patternIndex = 0, starIndex = -1, retryIndex = 0;
    while (valueIndex < value.length) {
      if (patternIndex < pattern.length && (pattern.charAt(patternIndex) === "?" || pattern.charAt(patternIndex) === value.charAt(valueIndex))) { valueIndex += 1; patternIndex += 1; }
      else if (patternIndex < pattern.length && pattern.charAt(patternIndex) === "*") { starIndex = patternIndex; patternIndex += 1; retryIndex = valueIndex; }
      else if (starIndex !== -1) { patternIndex = starIndex + 1; retryIndex += 1; valueIndex = retryIndex; }
      else return false;
    }
    while (pattern.charAt(patternIndex) === "*") patternIndex += 1;
    return patternIndex === pattern.length;
  }
  function sourceUrl(value) {
    if (!/^https?:\/\//i.test(value || "")) throw new Error("source must use http or https");
    return value;
  }
  function sourceFromRequest(requestUrl) {
    var explicit = query(requestUrl, "source", "s");
    if (explicit !== null && explicit !== "") return sourceUrl(explicit);
    var fileName = new URL(requestUrl).pathname.replace(/^\//, "");
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z0-9]{1,8}$/.test(fileName)) throw new Error("source is required or request path must be an artifact file name");
    return SHORT_ARTIFACT_ORIGIN + encodeURIComponent(fileName);
  }
  function removeNoResolve(fields) {
    return fields.filter(function (field, index) {
      return index < 2 || field.trim().toLowerCase() !== "no-resolve";
    });
  }
  function transformRule(rule, profile, compose, output, skipNoResolve, exclude) {
    var fields = rule.split(",");
    var type = (fields[0] || "").trim().toUpperCase();
    var bit = PROFILES[profile].bits[type];
    if (bit === undefined || (compose & bit) === 0) return null;
    var value = (fields[1] || "").trim();
    if (exclude && matchesGlob(value, exclude)) return null;

    if (output === "domain-set" || output === "domain") {
      if (type === "DOMAIN") return value;
      if (type === "DOMAIN-SUFFIX") {
        var suffix = value;
        return suffix.charAt(0) === "." ? suffix : "." + suffix;
      }
      return null;
    }
    if (output === "ipcidr") {
      return ["IP-CIDR", "IP-CIDR6"].indexOf(type) !== -1 ? value : null;
    }
    if (skipNoResolve && ["IP-CIDR", "IP-CIDR6", "IP6-CIDR", "IP-ASN"].indexOf(type) !== -1) {
      fields = removeNoResolve(fields);
    }
    return fields.join(",");
  }
  function decodeStashPayload(line) {
    var match = /^\s*-\s*'((?:[^']|'')*)'\s*$/.exec(line);
    return match ? match[1].replace(/''/g, "'") : null;
  }
  function encodeStashPayload(value) {
    return "- '" + value.replace(/'/g, "''") + "'";
  }
  function filterContent(content, profile, compose, output, options) {
    var stash = PROFILES[profile].format === "stash-yaml";
    return String(content).split(/\r?\n/).map(function (line) {
      var normalized = line.trim();
      if (!normalized || normalized.charAt(0) === "#" || (stash && normalized === "payload:")) return line;
      var rule = stash ? decodeStashPayload(line) : line;
      if (rule === null) return null;
      var transformed = transformRule(rule, profile, compose, output, options.skipNoResolve, options.exclude);
      return transformed === null ? null : (stash ? encodeStashPayload(transformed) : transformed);
    }).filter(function (line) { return line !== null; }).join("\n");
  }

  function request(options, callback) {
    if (typeof $task !== "undefined" && $task.fetch) {
      $task.fetch(options).then(function (response) {
        callback(null, {status: response.statusCode, headers: response.headers || {}}, response.body || "");
      }, function (error) { callback(error); });
      return;
    }
    var method = (options.method || "GET").toLowerCase();
    $httpClient[method](options, callback);
  }
  function header(headers, name) {
    var result = null;
    Object.keys(headers || {}).some(function (key) {
      if (key.toLowerCase() === name.toLowerCase()) { result = headers[key]; return true; }
      return false;
    });
    return result;
  }
  function response(status, body) {
    var headers = {"Content-Type":"text/plain; charset=utf-8","Cache-Control":"no-store"};
    if (typeof $task !== "undefined") {
      return {status: "HTTP/1.1 " + status + (status === 200 ? " OK" : " Error"), headers: headers, body: body};
    }
    return {response: {status: status, headers: headers, body: body}};
  }
  function functionUrl(source, compose, output, profile, options) {
    var parsed = new URL(source);
    var url = parsed.origin + "/api/" + profile + "-rule-filter?source=" + encodeURIComponent(parsed.toString()) +
      "&compose=" + compose + "&output=" + encodeURIComponent(output);
    if (options.skipNoResolve) url += "&skip_no_resolve=1";
    return url;
  }
  function run() {
    var profile, source, compose, output, options;
    try {
      profile = profileFromUrl($request.url);
      source = sourceFromRequest($request.url);
      compose = parseCompose(query($request.url, "compose", "c"), profile);
      output = query($request.url, "output", "o") || (profile === "stash" ? "classical" : "rule-set");
      options = {
        skipNoResolve: flag(query($request.url, "skip_no_resolve", "n"), "skip_no_resolve"),
        exclude: parseExclude(query($request.url, "exclude", "x"))
      };
    } catch (error) {
      $done(response(400, "Bad Request: " + error.message + "\n")); return;
    }
    function useFunction() {
      var target = functionUrl(source, compose, output, profile, options);
      if (typeof $task === "undefined") { $done({url: target}); return; }
      request({url: target, method: "GET", headers: {"Accept-Encoding":"identity"}}, function (error, res, body) {
        if (error) $done(response(502, "Function request failed: " + error + "\n"));
        else $done(response(Number(res.status) || 502, body));
      });
    }
    function useLocal(fallbackToFunction) {
      request({url: source, method: "GET", headers: {"Accept-Encoding":"identity"}}, function (error, res, body) {
        if (error || Number(res && res.status) < 200 || Number(res && res.status) >= 300) { if (fallbackToFunction) useFunction(); else $done(response(502, "Source request failed\n")); return; }
        try { $done(response(200, filterContent(body, profile, compose, output, options))); }
        catch (filterError) { if (fallbackToFunction) useFunction(); else $done(response(500, "Local filter failed: " + filterError.message + "\n")); }
      });
    }
    request({url: source, method: "HEAD", headers: {"Accept-Encoding":"identity"}}, function (error, res) {
      var length = Number(header(res && res.headers, "Content-Length"));
      if (options.exclude) { if (!error && Number.isFinite(length) && length > EXCLUDE_LOCAL_MAX) $done(response(413, "Source exceeds the 1 MiB local exclusion limit\n")); else useLocal(false); return; }
      if (!error && Number.isFinite(length) && length > LOCAL_MAX) useFunction(); else useLocal(true);
    });
  }

  if (typeof module !== "undefined" && module.exports) module.exports = {
    PROFILES: PROFILES, profileFromUrl: profileFromUrl, parseCompose: parseCompose,
    transformRule: transformRule, filterContent: filterContent, functionUrl: functionUrl, parseExclude: parseExclude, matchesGlob: matchesGlob, sourceFromRequest: sourceFromRequest
  };
  if (typeof $request !== "undefined" && typeof $done === "function") run();
}());
