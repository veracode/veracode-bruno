/*tested with bruno 2.3.0 */
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

/* get Veracode API credentials */
const id = getCredential('api_id');
if (!id) {
  throw new Error("No 'api_id' found in the environment, process env, or in the env secrets. Please ensure you have configured a Veracode environment.");
}
const key = getCredential('api_key');
if (!key) {
  throw new Error("No 'api_key' found in the environment, process env, or in the env secrets. Please ensure you have configured a Veracode environment.");
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

function calculateVeracodeAuthHeader(httpMethod, requestUrl) {
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

// Get the raw URL
const rawUrl = req.getUrl().toString();

// Substitute {{variables}} first
let substitutedUrl = substituteVariables(rawUrl);

// Then substitute :pathParameters
substitutedUrl = substitutePathParams(substitutedUrl);

// Calculate HMAC with fully substituted URL
let hmac = calculateVeracodeAuthHeader(req.method, substitutedUrl);

// Debug logging
console.log('Raw URL:', rawUrl);
console.log('Substituted URL:', substitutedUrl);
console.log('HMAC:', hmac);

// Set the Authorization header
req.setHeader("Authorization", hmac);
