/*tested with bruno 2.3.0 and 4.3.0 */
const crypto = require('crypto-js');

/* Manual URL parsing function to replace url.parse() */
function parseUrl(urlString) {
  const match = urlString.match(/^(?:(https?:)\/\/)([^:\/\s]+):?(\d*)([^?\s]*)?(\?[^#]*)?(#.*)?$/);
  if (!match) {
    throw new Error('Invalid URL: ' + urlString);
  }

  const [, protocol, hostname, port, pathname = '', search = '', hash = ''] = match;
  return {
    protocol: protocol,
    hostname: hostname,
    port: port,
    pathname: pathname,
    search: search,
    path: pathname + search,
    hash: hash
  };
}

/* Function to substitute Bruno variables */
function substituteVariables(urlString) {
  let substituted = urlString;
  const variablePattern = /\{\{([^}]+)\}\}/g;
  let match;

  while ((match = variablePattern.exec(urlString)) !== null) {
    const variableName = match[1];
    // Try in order of precedence (most specific to least specific)
    let variableValue = bru.getRequestVar && bru.getRequestVar(variableName) ||
        bru.getEnvVar(variableName) ||
        bru.getCollectionVar && bru.getCollectionVar(variableName) ||
        bru.getGlobalEnvVar(variableName) ||
        bru.getVar(variableName);

    if (variableValue) {
      substituted = substituted.replace(match[0], variableValue);
    } else {
      throw new Error(`Variable '${variableName}' not found in environment or collection variables`);
    }
  }

  return substituted;
}

/* Function to substitute path parameters */
function substitutePathParams(urlString) {
  // Get path parameters from Bruno and convert array to object
  const pathParamsArray = req.getPathParams();
  const pathParamsMap = {};
  if (pathParamsArray && Array.isArray(pathParamsArray)) {
    pathParamsArray.forEach(param => {
      if (param.name && param.value) {
        pathParamsMap[param.name] = param.value;
      }
    });
  }

  // Substitute path parameters (:paramName)
  const pathParamRegex = /:([a-zA-Z0-9_]+)/g;
  return urlString.replace(pathParamRegex, (match, paramName) => {
    if (pathParamsMap[paramName]) {
      return pathParamsMap[paramName];
    }
    console.warn(`Warning: No value found for path parameter: ${paramName}`);
    return match;
  });
}

/* Resolve a credential from env var / secret-checkbox var, then process env, then secret manager */
function getCredential(name) {
  if (bru.hasEnvVar(name)) return bru.getEnvVar(name);
  if (bru.hasGlobalEnvVar && bru.hasGlobalEnvVar(name)) return bru.getGlobalEnvVar(name);
  return bru.getProcessEnv(name)
    || (bru.getSecretVar && bru.getSecretVar(`veracode.${name}`))
    || null;
}

/* get Veracode API credentials for HMAC signing */
function getHmacCredentials() {
  const id = getCredential('api_id');
  if (!id) {
    throw new Error("No 'api_id' found in the environment, process env, or in the env secrets. Please ensure you have configured a Veracode environment.");
  }
  const key = getCredential('api_key');
  if (!key) {
    throw new Error("No 'api_key' found in the environment, process env, or in the env secrets. Please ensure you have configured a Veracode environment.");
  }
  return { id, key };
}

const authorizationScheme = 'VERACODE-HMAC-SHA-256';
const requestVersion = "vcode_request_version_1";
const nonceSize = 16;

function computeHashHex(message, key_hex) {
  return crypto.HmacSHA256(message, crypto.enc.Hex.parse(key_hex)).toString(crypto.enc.Hex);
}

function calculateDataSignature(apikey, nonceBytes, dateStamp, data) {
  let kNonce = computeHashHex(nonceBytes, apikey);
  let kDate = computeHashHex(dateStamp, kNonce);
  let kSig = computeHashHex(requestVersion, kDate);
  return computeHashHex(data, kSig);
}

function newNonce() {
  return crypto.lib.WordArray.random(nonceSize).toString().toUpperCase();
}

function toHexBinary(input) {
  return crypto.enc.Hex.stringify(crypto.enc.Utf8.parse(input));
}

function removePrefixFromApiCredential(input) {
  return input.split('-').at(-1);
}

function calculateVeracodeAuthHeader(httpMethod, requestUrl, id, key) {
  const formattedId = removePrefixFromApiCredential(id);
  const formattedKey = removePrefixFromApiCredential(key);
  let parsedUrl = parseUrl(requestUrl);
  let data = `id=${formattedId}&host=${parsedUrl.hostname}&url=${parsedUrl.path}&method=${httpMethod}`;
  let dateStamp = Date.now().toString();
  let nonceBytes = newNonce();
  let dataSignature = calculateDataSignature(formattedKey, nonceBytes, dateStamp, data);
  let authorizationParam = `id=${formattedId},ts=${dateStamp},nonce=${toHexBinary(nonceBytes)},sig=${dataSignature}`;
  return authorizationScheme + " " + authorizationParam;
}

/* ---------- OAuth bearer token ---------- */

const oauthTokenPath = '/api/authn/v2/oauth2/token';
const oauthExpiryMarginMs = 60 * 1000;
const oauthCacheKeys = {
  token: 'veracode_oauth_access_token',
  expiresAt: 'veracode_oauth_expires_at',
  hostname: 'veracode_oauth_cache_hostname',
  clientId: 'veracode_oauth_cache_client_id'
};

function hostKey(parsed) {
  return `${parsed.hostname.toLowerCase()}:${parsed.port || '443'}`;
}

/* Resolve and validate hostname, client id and client secret */
function getOAuthConfig() {
  const rawHostname = getCredential('hostname');
  if (!rawHostname) {
    throw new Error("No 'hostname' found in the environment. Set it to the Veracode API base URL, e.g. https://api.veracode.com");
  }
  const baseUrl = rawHostname.trim().replace(/\/+$/, '');
  let parsed;
  try {
    parsed = parseUrl(baseUrl);
  } catch (e) {
    throw new Error(`'hostname' must be a base URL including the scheme, e.g. https://api.veracode.com`);
  }
  if (parsed.protocol !== 'https:') {
    throw new Error("'hostname' must use https://");
  }
  const clientId = getCredential('oauth_veracode_client_id');
  if (!clientId) {
    throw new Error("No 'oauth_veracode_client_id' found in the environment, process env, or in the env secrets.");
  }
  const clientSecret = getCredential('oauth_veracode_client_secret');
  if (!clientSecret) {
    throw new Error("No 'oauth_veracode_client_secret' found in the environment, process env, or in the env secrets.");
  }
  return { baseUrl, parsed, clientId, clientSecret };
}

/* Never send the bearer token to a host other than the one the token was issued by */
function assertSameHost(requestUrl, config) {
  const requestParsed = parseUrl(requestUrl);
  if (requestParsed.protocol !== 'https:' || hostKey(requestParsed) !== hostKey(config.parsed)) {
    throw new Error(`OAuth bearer token can only be sent to ${config.parsed.protocol}//${hostKey(config.parsed)} (from 'hostname'), but the request is for ${requestParsed.protocol}//${hostKey(requestParsed)}`);
  }
}

function getCachedOAuthToken(config) {
  const token = bru.getVar(oauthCacheKeys.token);
  const expiresAt = Number(bru.getVar(oauthCacheKeys.expiresAt));
  if (!token || !Number.isFinite(expiresAt)) return null;
  if (bru.getVar(oauthCacheKeys.hostname) !== config.baseUrl) return null;
  if (bru.getVar(oauthCacheKeys.clientId) !== config.clientId) return null;
  if (Date.now() >= expiresAt - oauthExpiryMarginMs) return null;
  return token;
}

/* POST a form body. Prefer bru.sendRequest (honors Bruno proxy/TLS settings), fall back to axios. Returns { status, data } */
async function postForm(url, body, headers) {
  if (typeof bru.sendRequest === 'function') {
    try {
      const res = await bru.sendRequest({ method: 'POST', url, headers, data: body });
      return { status: res.status, data: res.data };
    } catch (err) {
      if (err && err.response) return { status: err.response.status, data: err.response.data };
      throw err;
    }
  }
  const axios = require('axios');
  const res = await axios.post(url, body, { headers, validateStatus: () => true });
  return { status: res.status, data: res.data };
}

function describeTokenError(data) {
  if (data && typeof data === 'object') {
    return data.error_description || data.error || data.message || '';
  }
  return typeof data === 'string' ? data.slice(0, 200) : '';
}

async function fetchOAuthToken(config) {
  const basic = crypto.enc.Base64.stringify(crypto.enc.Utf8.parse(`${config.clientId}:${config.clientSecret}`));
  let res;
  try {
    res = await postForm(config.baseUrl + oauthTokenPath, 'grant_type=client_credentials', {
      'Authorization': `Basic ${basic}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json'
    });
  } catch (err) {
    throw new Error(`OAuth token request failed: ${err && err.message ? err.message : 'no response'}`);
  }
  if (res.status < 200 || res.status >= 300) {
    const detail = describeTokenError(res.data);
    throw new Error(`OAuth token request failed (HTTP ${res.status})${detail ? ': ' + detail : ''}`);
  }
  const data = res.data;
  const expiresIn = data && Number(data.expires_in);
  if (!data || !data.access_token || !Number.isFinite(expiresIn) || expiresIn <= 0) {
    throw new Error('OAuth token response did not contain a valid access_token and expires_in');
  }
  /* cache only after the response is validated */
  bru.setVar(oauthCacheKeys.token, data.access_token);
  bru.setVar(oauthCacheKeys.expiresAt, String(Date.now() + expiresIn * 1000));
  bru.setVar(oauthCacheKeys.hostname, config.baseUrl);
  bru.setVar(oauthCacheKeys.clientId, config.clientId);
  return data.access_token;
}

async function applyOAuthAuth() {
  const config = getOAuthConfig();
  assertSameHost(substituteVariables(req.getUrl().toString()), config);

  let token = getCachedOAuthToken(config);
  if (token) {
    console.log('OAuth: using cached token');
  } else {
    token = await fetchOAuthToken(config);
    console.log('OAuth: fetched new token');
  }
  /* do not log the token or the Authorization header */
  req.setHeader("Authorization", `Bearer ${token}`);
}

/* ---------- HMAC ---------- */

function applyHmacAuth() {
  const { id, key } = getHmacCredentials();

  // Get the raw URL
  const rawUrl = req.getUrl().toString();

  // Substitute {{variables}} first
  let substitutedUrl = substituteVariables(rawUrl);

  // Then substitute :pathParameters
  substitutedUrl = substitutePathParams(substitutedUrl);

  // Calculate HMAC with fully substituted URL
  let hmac = calculateVeracodeAuthHeader(req.method, substitutedUrl, id, key);

  // Debug logging
  console.log('Raw URL:', rawUrl);
  console.log('Substituted URL:', substitutedUrl);
  console.log('HMAC:', hmac);

  // Set the Authorization header
  req.setHeader("Authorization", hmac);
}

/* ---------- select auth method ---------- */

const authType = (getCredential('veracode_auth_type') || 'hmac').trim().toLowerCase() || 'hmac';
if (authType === 'oauth') {
  await applyOAuthAuth();
} else if (authType === 'hmac') {
  applyHmacAuth();
} else {
  throw new Error(`Invalid 'veracode_auth_type' value '${authType}'. Allowed values: 'hmac', 'oauth'.`);
}
