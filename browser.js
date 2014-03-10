var crypto = require("crypto");
var cs2a = require("./cs2a.js");

var ecc = require("ecc-jsbn");  
require("./forge.min.js"); // PITA not browserify compat
cs2a.crypt(ecc);

cs2a.genkey = function(ret,cbDone,cbStep)
{
	var state = forge.rsa.createKeyPairGenerationState(2048, 0x10001);
	var step = function() {
	  // run for 100 ms
	  if(!forge.rsa.stepKeyPairGenerationState(state, 100)) {
      if(cbStep) cbStep();
	    setTimeout(step, 10);
	  } else {
      var key = forge.asn1.toDer(forge.pki.publicKeyToAsn1(state.keys.publicKey)).bytes();
      ret["2a"] = forge.util.encode64(key);
      ret["2a_secret"] = forge.util.encode64(forge.asn1.toDer(forge.pki.privateKeyToAsn1(state.keys.privateKey)).bytes());
      var md = forge.md.sha256.create();
      md.update(key);
      ret.parts["2a"] = md.digest().toHex();
      cbDone();
	  }
	}
	setTimeout(step);  
}

cs2a.loadkey = function(id, pub, priv)
{
  // take pki or ber format
  if(pub.length > 300)
  {
    if(pub.substr(0,1) == "-") pub = forge.asn1.toDer(forge.pki.publicKeyToAsn1(forge.pki.publicKeyFromPem(key))).bytes();
    else pub = forge.util.decode64(pub);
  }
  id.key = pub;
  var pk = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(pub));    
  id.encrypt = function(buf){
    return new Buffer(pk.encrypt(buf.toString("binary"), "RSA-OAEP"), "binary");
  };
  id.verify = function(a,b){
    return pk.verify(a.toString("binary"), b.toString("binary"));
  };
  if(priv)
  {
    var sk = (priv.substr(0,1) == "-") ? forge.pki.privateKeyFromPem(priv) :  forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(forge.util.decode64(priv)));
    id.sign = function(buf){
      return new Buffer(sk.sign(buf.toString("binary")),"binary");
    };
    id.decrypt = function(buf){
      return new Buffer(sk.decrypt(buf.toString("binary"), "RSA-OAEP"),"binary");
    };
  }
  return false;
}

Object.keys(cs2a).forEach(function(f){ exports[f] = cs2a[f]; });

