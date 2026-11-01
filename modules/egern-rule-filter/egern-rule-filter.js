const RULE_TYPE_BITS = {
  domain_set: 1,
  domain_suffix_set: 2,
  domain_keyword_set: 4,
  domain_wildcard_set: 8,
  ip_cidr_set: 16,
  ip_cidr6_set: 32,
  asn_set: 64,
  url_regex_set: 128,
  user_agent_set: 256,
  dest_port_set: 512,
  geoip_set: 1024,
  protocol_set: 2048,
};

const SUPPORTED_MASK = Object.values(RULE_TYPE_BITS).reduce((mask, bit) => mask | bit, 0);
const LOCAL_MAX = 512 * 1024;
const EXCLUDE_LOCAL_MAX = 1024 * 1024;
const SHORT_ARTIFACT_ORIGIN = "https://magicrule.pages.dev/data/_shared/artifacts/";

function parameter(url, name, shortName) {
  return url.searchParams.get(name) ?? (shortName ? url.searchParams.get(shortName) : null);
}

function sourceFromRequest(requestUrl) {
  const explicit = parameter(requestUrl, "source", "s");
  if (explicit !== null && explicit !== "") {
    const source = new URL(explicit);
    if (!/^https?:$/.test(source.protocol)) throw new Error("source must use http or https");
    return source;
  }
  const fileName = requestUrl.pathname.replace(/^\//, "");
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z0-9]{1,8}$/.test(fileName)) {
    throw new Error("source is required or request path must be an artifact file name");
  }
  return new URL(encodeURIComponent(fileName), SHORT_ARTIFACT_ORIGIN);
}

function parseCompose(value) {
  if (!/^[1-9]\d*$/.test(value || "")) throw new Error("compose must be a positive integer");
  const compose = Number(value);
  if (!Number.isSafeInteger(compose) || (compose & ~SUPPORTED_MASK) !== 0) {
    throw new Error("unsupported compose bits");
  }
  return compose;
}

function parseFlag(value, name) {
  if (value === null || value === "" || value === "0") return false;
  if (value === "1") return true;
  throw new Error(`${name} must be 0 or 1`);
}

function parseExclude(value) {
  if (value === null || value === "") return null;
  if (value.length > 256 || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error("exclude must be at most 256 printable characters");
  }
  return value.toLowerCase();
}

function matchesGlob(value, pattern) {
  value = String(value || "").toLowerCase();
  let valueIndex = 0, patternIndex = 0, starIndex = -1, retryIndex = 0;
  while (valueIndex < value.length) {
    if (patternIndex < pattern.length && (pattern[patternIndex] === "?" || pattern[patternIndex] === value[valueIndex])) {
      valueIndex += 1;
      patternIndex += 1;
    } else if (patternIndex < pattern.length && pattern[patternIndex] === "*") {
      starIndex = patternIndex;
      patternIndex += 1;
      retryIndex = valueIndex;
    } else if (starIndex !== -1) {
      patternIndex = starIndex + 1;
      retryIndex += 1;
      valueIndex = retryIndex;
    } else return false;
  }
  while (pattern[patternIndex] === "*") patternIndex += 1;
  return patternIndex === pattern.length;
}

function yamlListValue(line) {
  const match = /^\s*-\s*(?:'((?:[^']|'')*)'|(.+?))\s*$/.exec(line);
  return match ? (match[1] === undefined ? match[2] : match[1].replace(/''/g, "'")) : null;
}

function selectedTypes(compose) {
  return new Set(Object.entries(RULE_TYPE_BITS)
    .filter(([, bit]) => (compose & bit) !== 0)
    .map(([type]) => type));
}

function filterYaml(content, compose, skipNoResolve = false, exclude = null) {
  const selected = selectedTypes(compose);
  const lines = String(content).split(/\r?\n/);
  const output = [];
  let keepSection = true;
  let hadNoResolve = false;

  for (const line of lines) {
    const section = /^([a-z][a-z0-9_]*):\s*$/.exec(line);
    if (section && RULE_TYPE_BITS[section[1]] !== undefined) {
      keepSection = selected.has(section[1]);
      if (keepSection) output.push(line);
      continue;
    }
    if (/^no_resolve:\s*(?:true|false)\s*$/i.test(line)) {
      hadNoResolve = /^no_resolve:\s*true\s*$/i.test(line);
      continue;
    }
    if (/^[^\s#][^:]*:/.test(line)) keepSection = true;
    const value = yamlListValue(line);
    if (keepSection && !(exclude && value !== null && matchesGlob(value, exclude))) output.push(line);
  }

  const needsNoResolve = hadNoResolve && !skipNoResolve;
  if (needsNoResolve) {
    const index = output.findIndex((line) => RULE_TYPE_BITS[(/^([a-z][a-z0-9_]*):\s*$/.exec(line) || [])[1]] !== undefined);
    output.splice(index < 0 ? output.length : index, 0, "no_resolve: true");
  }
  while (output.length && output[output.length - 1] === "") output.pop();
  return output.join("\n") + "\n";
}

function functionUrl(source, compose, skipNoResolve) {
  const parsed = new URL(source);
  const url = new URL("/api/egern-rule-filter", parsed.origin);
  url.searchParams.set("source", parsed.toString());
  url.searchParams.set("compose", String(compose));
  url.searchParams.set("output", "rule-set");
  if (skipNoResolve) url.searchParams.set("skip_no_resolve", "1");
  return url.toString();
}

function contentLength(response) {
  const value = Number(response?.headers?.get?.("content-length"));
  return Number.isFinite(value) && value >= 0 ? value : null;
}

export default async function(ctx) {
  let source;
  let compose;
  let skipNoResolve;
  let exclude;
  try {
    const requestUrl = new URL(ctx.request.url);
    source = sourceFromRequest(requestUrl);
    compose = parseCompose(parameter(requestUrl, "compose", "c"));
    skipNoResolve = parseFlag(parameter(requestUrl, "skip_no_resolve", "n"), "skip_no_resolve");
    exclude = parseExclude(parameter(requestUrl, "exclude", "x"));
  } catch (error) {
    return ctx.respond({status: 400, headers: {"Content-Type": "text/plain; charset=utf-8"}, body: `Bad Request: ${error.message}\n`});
  }

  const fallback = () => ({url: functionUrl(source, compose, skipNoResolve)});
  try {
    const head = await ctx.http.head(source.toString(), {headers: {"Accept-Encoding": "identity"}, timeout: 15000});
    const length = contentLength(head);
    if (exclude && length !== null && length > EXCLUDE_LOCAL_MAX) {
      return ctx.respond({status: 413, headers: {"Content-Type": "text/plain; charset=utf-8"}, body: "Source exceeds the 1 MiB local exclusion limit\n"});
    }
    if (!exclude && length !== null && length > LOCAL_MAX) return fallback();
  } catch (_) {
    // Missing HEAD metadata is not fatal; prefer local filtering first.
  }

  try {
    const response = await ctx.http.get(source.toString(), {headers: {"Accept-Encoding": "identity"}, timeout: 300000});
    if (response.status < 200 || response.status >= 300) {
      if (exclude) return ctx.respond({status: 502, headers: {"Content-Type": "text/plain; charset=utf-8"}, body: "Source request failed\n"});
      return fallback();
    }
    const body = await response.text();
    return ctx.respond({
      status: 200,
      headers: {"Content-Type": "text/yaml; charset=utf-8", "Cache-Control": "no-store"},
      body: filterYaml(body, compose, skipNoResolve, exclude),
    });
  } catch (error) {
    if (exclude) {
      return ctx.respond({status: 500, headers: {"Content-Type": "text/plain; charset=utf-8"}, body: `Local filter failed: ${error.message}\n`});
    }
    return fallback();
  }
}

export {RULE_TYPE_BITS, parseCompose, selectedTypes, filterYaml, functionUrl, contentLength, parseExclude, matchesGlob, sourceFromRequest};
