/**
 * Utility functions
 */

function addOpenIDNamespace(fields) {
  var NAMESPACE = "openid.";
  var out = {};
  for(var key in fields) {
    out[NAMESPACE+key] = fields[key];
  }
  return out;
}
module.exports.addOpenIDNamespace = addOpenIDNamespace;

function getOpenIDFields(fields) {
  var out = {};
  for(var i in fields) {
    if (i.substr(0,7).toLowerCase() === "openid.") {
      out[i.substr(7).toLowerCase()] = fields[i];
    }
  }
  return out;
}
module.exports.getOpenIDFields = getOpenIDFields;

//@TODO: I have reason to believe this function doesn't work correctly
//@DEPRECIATED: only ever used in associate, migrate into the associate code
function btwoc(i) {
  console.warn("btwoc is deprecated");
  if(i[0] > 127) {
    return Buffer.concat([new Buffer([0]), i]);
  }
  else {
    return i;
  }
}
module.exports.btwoc = btwoc;

//@DEPRECIATED: only ever used in associate, migrate into the associate code
function xor(bb, ab)
{
  //@TODO: convert this function to use native buffers instead of converting between buffers and binary strings
  console.warn("xor is deprecated");
  var a = ab.toString('binary');
  var b = bb.toString('binary');
  if(a.length != b.length)
  {
    throw new Error('Length must match for xor');
  }

  var r = '';
  for(var i = 0; i < a.length; ++i)
  {
    r += String.fromCharCode(a.charCodeAt(i) ^ b.charCodeAt(i));
  }

  return new Buffer(r, 'binary');
}
module.exports.xor = xor;

function options(user_config, defaults)
{
  var config = {};
  
  //set defaults
  for (var key in defaults || {}) {
    config[key] = defaults[key];
  }
  
  //merge in 
  for (var key in user_config || {}) {
    config[key] = user_config[key];
  }
  
  return config;
}
module.exports.options = options;

function isEmptyObject(obj) {
  for(var i in obj) {
    return false;
  }
  return true;
}