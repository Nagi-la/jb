/*
 * Surge rule filter.
 *
 * Request example:
 * https://magic.rule/list?source=<encodeURIComponent(rule URL)>&compose=1
 */

(function () {
  "use strict";

  // compose is a bit mask. Keep this table stable after publishing it.
  var RULE_TYPE_BITS = {
    "DOMAIN": 1,
    "DOMAIN-SUFFIX": 2,
    "DOMAIN-KEYWORD": 4,
    "USER-AGENT": 8,
    "URL-REGEX": 16,
    "IP-CIDR": 32,
    "IP-CIDR6": 64,
    "GEOIP": 128,
    "IP-ASN": 256,
    "DEST-PORT": 512,
    "PROTOCOL": 1024,
    "PROCESS-NAME": 2048,
    "IN-PORT": 4096,
    "SRC-IP": 8192,
    "AND": 32768,
    "OR": 65536,
    "NOT": 131072
  };

  var SUPPORTED_MASK = Object.keys(RULE_TYPE_BITS).reduce(function (mask, type) {
    return mask | RULE_TYPE_BITS[type];
  }, 0);
  // Keep each $httpClient response below Surge's conservative script body limits.
  var RANGE_CHUNK_SIZE = 64 * 1024;
  var LOCAL_FILTER_MAX_BYTES = 512 * 1024;
  var EXCLUDE_LOCAL_MAX_BYTES = 1024 * 1024;
  var SHORT_ARTIFACT_ORIGIN = "https://magicrule.pages.dev/data/_shared/artifacts/";

  function getQueryParameter(url, name, shortName) {
    var queryStart = url.indexOf("?");
    if (queryStart === -1) return null;

    var hashStart = url.indexOf("#", queryStart);
    var query = url.slice(queryStart + 1, hashStart === -1 ? url.length : hashStart);
    var pairs = query.split("&");

    for (var i = 0; i < pairs.length; i += 1) {
      var separator = pairs[i].indexOf("=");
      var rawKey = separator === -1 ? pairs[i] : pairs[i].slice(0, separator);
      if (decodeURIComponent(rawKey.replace(/\+/g, " ")) !== name) continue;

      var rawValue = separator === -1 ? "" : pairs[i].slice(separator + 1);
      return decodeURIComponent(rawValue.replace(/\+/g, " "));
    }

    return shortName ? getQueryParameter(url, shortName) : null;
  }

  function parseCompose(rawCompose) {
    if (rawCompose === null || !/^[1-9]\d*$/.test(rawCompose)) {
      throw new Error("compose must be a positive integer bit mask");
    }

    var compose = Number(rawCompose);
    if (!Number.isSafeInteger(compose) || compose > 0x7fffffff) {
      throw new Error("compose is outside the supported range");
    }
    if ((compose & ~SUPPORTED_MASK) !== 0) {
      throw new Error("compose contains unsupported rule type bits");
    }

    return compose;
  }

  function validateSource(source) {
    if (!source) throw new Error("source is required");
    if (!/^https?:\/\//i.test(source)) {
      throw new Error("source must use http or https");
    }
    return source;
  }

  function sourceFromRequest(requestUrl) {
    var explicit = getQueryParameter(requestUrl, "source", "s");
    if (explicit !== null && explicit !== "") return validateSource(explicit);
    var fileName = new URL(requestUrl).pathname.replace(/^\//, "");
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z0-9]{1,8}$/.test(fileName)) {
      throw new Error("source is required or request path must be an artifact file name");
    }
    return SHORT_ARTIFACT_ORIGIN + encodeURIComponent(fileName);
  }

  function parseOutput(rawOutput) {
    var output = (rawOutput || "rule-set").toLowerCase();
    if (["domain-set", "rule-set"].indexOf(output) === -1) {
      throw new Error("output must be domain-set or rule-set");
    }
    return output;
  }

  function parseBooleanFlag(rawValue, name) {
    if (rawValue === null || rawValue === "" || rawValue === "0") return false;
    if (rawValue === "1") return true;
    throw new Error(name + " must be 0 or 1");
  }

  function parseExclude(rawValue) {
    if (rawValue === null || rawValue === "") return null;
    if (rawValue.length > 256 || /[\u0000-\u001f\u007f]/.test(rawValue)) {
      throw new Error("exclude must be at most 256 printable characters");
    }
    return rawValue.toLowerCase();
  }

  // A single, linear glob matcher. Only * and ? have special meaning.
  function matchesGlob(value, pattern) {
    value = String(value || "").toLowerCase();
    var valueIndex = 0, patternIndex = 0, starIndex = -1, retryIndex = 0;
    while (valueIndex < value.length) {
      if (patternIndex < pattern.length && (pattern.charAt(patternIndex) === "?" || pattern.charAt(patternIndex) === value.charAt(valueIndex))) {
        valueIndex += 1;
        patternIndex += 1;
      } else if (patternIndex < pattern.length && pattern.charAt(patternIndex) === "*") {
        starIndex = patternIndex;
        patternIndex += 1;
        retryIndex = valueIndex;
      } else if (starIndex !== -1) {
        patternIndex = starIndex + 1;
        retryIndex += 1;
        valueIndex = retryIndex;
      } else return false;
    }
    while (pattern.charAt(patternIndex) === "*") patternIndex += 1;
    return patternIndex === pattern.length;
  }

  function removeNoResolve(line) {
    var fields = line.split(",");
    return fields.filter(function (field, index) {
      return index < 2 || field.trim().toLowerCase() !== "no-resolve";
    }).join(",");
  }

  function transformLine(line, compose, output, skipNoResolve, exclude) {
    var normalized = line.trim();

    // Metadata, comments and visual spacing are not routing rules, so retain them.
    if (!normalized || normalized.charAt(0) === "#") return line;

    var comma = normalized.indexOf(",");
    var type = (comma === -1 ? normalized : normalized.slice(0, comma)).trim().toUpperCase();
    var bit = RULE_TYPE_BITS[type];
    if (bit === undefined || (compose & bit) === 0) return null;
    var nextComma = normalized.indexOf(",", comma + 1);
    var value = normalized.slice(comma + 1, nextComma === -1 ? normalized.length : nextComma).trim();
    if (exclude && matchesGlob(value, exclude)) return null;
    if (output === "rule-set") {
      if (skipNoResolve && ["IP-CIDR", "IP-CIDR6", "IP-ASN"].indexOf(type) !== -1) {
        return removeNoResolve(line);
      }
      return line;
    }

    // Surge DOMAIN-SET uses bare domains and a leading dot for suffix rules.
    if (type === "DOMAIN") return value;
    if (type === "DOMAIN-SUFFIX") return value.charAt(0) === "." ? value : "." + value;
    return null;
  }

  function shouldKeepLine(line, compose) {
    return transformLine(line, compose, "rule-set") !== null;
  }

  function createIncrementalRuleFilter(compose, output, skipNoResolve, exclude) {
    output = parseOutput(output);
    var carry = "";
    var outputParts = [];
    var finished = false;

    function push(text, final) {
      if (finished) throw new Error("filter is already finished");

      var input = carry + String(text || "");
      var accepted = [];
      var lineStart = 0;
      var newline;

      while ((newline = input.indexOf("\n", lineStart)) !== -1) {
        var line = input.slice(lineStart, newline);
        if (line.charAt(line.length - 1) === "\r") line = line.slice(0, -1);
        var transformed = transformLine(line, compose, output, skipNoResolve, exclude);
        if (transformed !== null) accepted.push(transformed + "\n");
        lineStart = newline + 1;
      }

      carry = input.slice(lineStart);
      if (final) {
        if (carry) {
          var transformedCarry = transformLine(carry, compose, output, skipNoResolve, exclude);
          if (transformedCarry !== null) accepted.push(transformedCarry);
        }
        carry = "";
        finished = true;
      }

      if (accepted.length) outputParts.push(accepted.join(""));
    }

    function result() {
      if (!finished) throw new Error("filter has not been finished");
      return outputParts.join("");
    }

    return {push: push, result: result};
  }

  function filterRules(content, compose, output, skipNoResolve, exclude) {
    var filter = createIncrementalRuleFilter(compose, output, skipNoResolve, exclude);
    filter.push(String(content), true);
    return filter.result();
  }

  function getHeader(headers, name) {
    if (!headers) return null;
    var expected = name.toLowerCase();
    var keys = Object.keys(headers);
    for (var i = 0; i < keys.length; i += 1) {
      if (keys[i].toLowerCase() === expected) return headers[keys[i]];
    }
    return null;
  }

  function parseContentRange(value) {
    var match = /^bytes\s+(\d+)-(\d+)\/(\d+|\*)$/i.exec(String(value || "").trim());
    if (!match) return null;
    return {
      start: Number(match[1]),
      end: Number(match[2]),
      total: match[3] === "*" ? null : Number(match[3])
    };
  }

  function buildFunctionTarget(source, compose, output, skipNoResolve) {
    var sourceUrl = new URL(source);
    if (sourceUrl.protocol !== "https:") throw new Error("Pages source must use https");
    sourceUrl.hash = "";
    var url = sourceUrl.origin + "/api/surge-rule-filter?source=" + encodeURIComponent(sourceUrl.toString()) +
        "&compose=" + encodeURIComponent(String(compose)) +
        "&output=" + encodeURIComponent(parseOutput(output));
    if (skipNoResolve) url += "&skip_no_resolve=1";
    return {
      url: url,
      host: sourceUrl.host
    };
  }

  function replaceHostHeader(headers, host) {
    var result = {};
    Object.keys(headers || {}).forEach(function (key) {
      var lower = key.toLowerCase();
      if (lower !== "host" && lower !== ":authority") result[key] = headers[key];
    });
    result.Host = host;
    return result;
  }

  function processingModeFromHead(error, response) {
    var localMaxBytes = arguments.length > 2 ? arguments[2] : LOCAL_FILTER_MAX_BYTES;
    if (error) return "local-fallback";
    var status = Number(response && (response.status || response.statusCode));
    if (status < 200 || status >= 300) return "local-fallback";
    var rawLength = getHeader(response.headers, "Content-Length");
    if (!/^\d+$/.test(String(rawLength || ""))) return "local-fallback";
    return Number(rawLength) <= localMaxBytes ? "local" : "function";
  }

  function parseLocalMaxBytes(rawValue) {
    if (rawValue === null || rawValue === "") return LOCAL_FILTER_MAX_BYTES;
    if (!/^\d+$/.test(rawValue)) throw new Error("local_max must be an integer number of bytes");
    var value = Number(rawValue);
    if (!Number.isSafeInteger(value) || value < LOCAL_FILTER_MAX_BYTES || value > 4 * 1024 * 1024) {
      throw new Error("local_max must be between 524288 and 4194304 bytes");
    }
    return value;
  }

  function plainTextResponse(status, body) {
    return {
      response: {
        status: status,
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-store"
        },
        body: body
      }
    };
  }

  function fetchAndFilter(source, compose, output, skipNoResolve, exclude, done) {
    if (typeof output === "function") {
      done = output;
      output = "rule-set";
      skipNoResolve = false;
    } else if (typeof skipNoResolve === "function") {
      done = skipNoResolve;
      skipNoResolve = false;
      exclude = null;
    } else if (typeof exclude === "function") {
      done = exclude;
      exclude = null;
    }
    var filter = createIncrementalRuleFilter(compose, output, skipNoResolve, exclude);
    var decoder = typeof TextDecoder !== "undefined" ? new TextDecoder("utf-8") : null;
    var offset = 0;

    function decodeChunk(data, final) {
      if (typeof data === "string") return data;
      if (!decoder) throw new Error("This Surge script engine cannot decode binary range responses");
      return decoder.decode(data || new Uint8Array(0), {stream: !final});
    }

    function finish() {
      // Flush an incomplete UTF-8 sequence, if the last range ended with one.
      filter.push(decoder ? decoder.decode() : "", true);
      done(null, filter.result());
    }

    function fetchNext() {
      var rangeEnd = offset + RANGE_CHUNK_SIZE - 1;
      $httpClient.get({
        url: source,
        headers: {
          "Accept": "text/plain,*/*;q=0.8",
          "Accept-Encoding": "identity",
          "Range": "bytes=" + offset + "-" + rangeEnd,
          "User-Agent": "Surge-Rule-Filter/1.1"
        },
        timeout: 25,
        "auto-redirect": true,
        "binary-mode": Boolean(decoder)
      }, function (error, response, data) {
        if (error) {
          var message = String(error);
          if (/exceeds size limit/i.test(message)) {
            done(new Error(
              "Source did not honor the 64 KiB Range request; please use a source URL with HTTP byte-range support"
            ));
          } else {
            done(new Error("Failed to fetch source: " + message));
          }
          return;
        }

        var status = Number(response && (response.status || response.statusCode));
        if (status === 200 && offset === 0) {
          // The origin ignored Range. The scanner still avoids split/filter copies.
          filter.push(decodeChunk(data, true), true);
          done(null, filter.result());
          return;
        }

        if (status === 416 && offset > 0) {
          finish();
          return;
        }

        if (status !== 206) {
          done(new Error("Source returned HTTP " + (status || "unknown")));
          return;
        }

        var contentRange = parseContentRange(getHeader(response.headers, "Content-Range"));
        if (!contentRange || contentRange.start !== offset || contentRange.end < contentRange.start) {
          done(new Error("Source returned an invalid Content-Range"));
          return;
        }

        var isLast = contentRange.total !== null && contentRange.end + 1 >= contentRange.total;
        var decoded = decodeChunk(data, isLast);
        filter.push(decoded, isLast);

        if (isLast) {
          done(null, filter.result());
          return;
        }

        offset = contentRange.end + 1;
        fetchNext();
      });
    }

    fetchNext();
  }

  function run() {
    if (($request.method || "GET").toUpperCase() !== "GET") {
      $done(plainTextResponse(405, "Method Not Allowed\n"));
      return;
    }

    var source;
    var compose;
    var requestedMode;
    var localMaxBytes;
    var output;
    var skipNoResolve;
    var exclude;
    try {
      source = sourceFromRequest($request.url);
      compose = parseCompose(getQueryParameter($request.url, "compose", "c"));
      output = parseOutput(getQueryParameter($request.url, "output", "o"));
      skipNoResolve = parseBooleanFlag(getQueryParameter($request.url, "skip_no_resolve", "n"), "skip_no_resolve");
      exclude = parseExclude(getQueryParameter($request.url, "exclude", "x"));
      requestedMode = (getQueryParameter($request.url, "mode", "m") || "auto").toLowerCase();
      localMaxBytes = parseLocalMaxBytes(getQueryParameter($request.url, "local_max", "l"));
      if (["auto", "local", "function"].indexOf(requestedMode) === -1) {
        throw new Error("mode must be auto, local or function");
      }
    } catch (error) {
      $done(plainTextResponse(400, "Bad Request: " + error.message + "\n"));
      return;
    }

    function useLocalFilter(fallbackToFunction) {
      fetchAndFilter(source, compose, output, skipNoResolve, exclude, function (error, content) {
        if (error) {
          if (fallbackToFunction) {
            usePagesFunction();
            return;
          }
          $done(plainTextResponse(502, error.message + "\n"));
          return;
        }
        $done(plainTextResponse(200, content));
      });
    }

    function usePagesFunction() {
      try {
        var target = buildFunctionTarget(source, compose, output, skipNoResolve);
        $done({url: target.url, headers: replaceHostHeader($request.headers, target.host)});
      } catch (error) {
        $done(plainTextResponse(400, "Bad Request: " + error.message + "\n"));
      }
    }

    if (requestedMode === "local") {
      useLocalFilter(false);
      return;
    }
    if (requestedMode === "function") {
      usePagesFunction();
      return;
    }

    $httpClient.head({
      url: source,
      headers: {"Accept-Encoding": "identity", "User-Agent": "Surge-Rule-Filter/1.2"},
      timeout: 10,
      "auto-redirect": true
    }, function (error, response) {
      if (exclude) {
        var contentLength = Number(getHeader(response && response.headers, "Content-Length"));
        if (!error && Number.isFinite(contentLength) && contentLength > EXCLUDE_LOCAL_MAX_BYTES) {
          $done(plainTextResponse(413, "Source exceeds the 1 MiB local exclusion limit\n"));
        } else {
          useLocalFilter(false);
        }
        return;
      }
      var mode = processingModeFromHead(error, response, localMaxBytes);
      if (mode === "function") usePagesFunction();
      else useLocalFilter(true);
    });
  }

  // CommonJS export is ignored by Surge and makes the pure logic testable with Node.js.
  if (typeof module !== "undefined" && module.exports) {
    module.exports = {
      RULE_TYPE_BITS: RULE_TYPE_BITS,
      SUPPORTED_MASK: SUPPORTED_MASK,
      getQueryParameter: getQueryParameter,
      sourceFromRequest: sourceFromRequest,
      parseCompose: parseCompose,
      parseOutput: parseOutput,
      parseBooleanFlag: parseBooleanFlag,
      parseExclude: parseExclude,
      matchesGlob: matchesGlob,
      validateSource: validateSource,
      transformLine: transformLine,
      removeNoResolve: removeNoResolve,
      filterRules: filterRules,
      createIncrementalRuleFilter: createIncrementalRuleFilter,
      parseContentRange: parseContentRange,
      fetchAndFilter: fetchAndFilter,
      buildFunctionTarget: buildFunctionTarget,
      replaceHostHeader: replaceHostHeader,
      processingModeFromHead: processingModeFromHead,
      parseLocalMaxBytes: parseLocalMaxBytes,
      LOCAL_FILTER_MAX_BYTES: LOCAL_FILTER_MAX_BYTES
    };
  }

  if (typeof $request !== "undefined" && typeof $done === "function") {
    run();
  }
}());
