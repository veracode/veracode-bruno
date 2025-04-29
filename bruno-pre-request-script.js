/*jshint esversion: 6 */

var url = require('url');
var crypto = require('crypto-js');

/* set Veracode API credentials in api_id and api_key in environment*/
const id = bru.getEnvVar('api_id');
if (!id) {
  throw new Error("Environment does not have an 'api_id'. Please ensure you have configured a Veracode environment.");
}
const key = bru.getEnvVar('api_key');
if (!id) {
  throw new Error("Environment does not have an 'api_key'. Please ensure you have configured a Veracode environment.");
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

  let parsedUrl = url.parse(requestUrl);
  let data = `id=${formattedId}&host=${parsedUrl.hostname}&url=${parsedUrl.path}&method=${httpMethod}`;
  let dateStamp = Date.now().toString();
  let nonceBytes = newNonce();
  let dataSignature = calculateDataSignature(formattedKey, nonceBytes, dateStamp, data);
  let authorizationParam = `id=${formattedId},ts=${dateStamp},nonce=${toHexBinary(nonceBytes)},sig=${dataSignature}`;
  return authorizationScheme + " " + authorizationParam;
}

let runtimeUrl = req.getUrl().toString();

let hmac = calculateVeracodeAuthHeader(req.method, runtimeUrl);
// bruno.setEnvVar('hmacAuthHeader', hmac);

req.setHeader(
    "Authorization",
    hmac
);
