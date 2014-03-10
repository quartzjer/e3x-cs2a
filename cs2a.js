var crypto = require("crypto");
var sjcl = require("sjcl");

var self;
exports.install = function(telehash)
{
  self = telehash;
  telehash.CSets["2a"] = exports;
}

exports.crypt = function(ecc,aes)
{
  crypto.ecc = ecc;
  crypto.aes = aes;
}

exports.openize = function(id, to, inner)
{
	if(!to.ecc) to.ecc = new ecc.ECKey(ecc.ECCurves.nistp256);
  var eccpub = to.ecc.PublicKey.slice(1);

	// encrypt the body
	var ibody = pencode(inner, id.cs["2a"].key);
  var keyhex = crypto.createHash("sha256").update(eccpub).digest("hex");
  var key = new sjcl.cipher.aes(sjcl.codec.hex.toBits(keyhex));
  var iv = sjcl.codec.hex.toBits("00000000000000000000000000000001");
  var cipher = sjcl.mode.gcm.encrypt(key, sjcl.codec.hex.toBits(ibody.toString("hex")), iv, [], 128);
  var cbody = new Buffer(sjcl.codec.hex.fromBits(cipher), "hex");

	// sign & encrypt the sig
  var sig = id.cs["2a"].sign(cbody);
  var keyhex = crypto.createHash("sha256").update(Buffer.concat([eccpub,new Buffer(to.lineOut,"hex")])).digest("hex");
  var key = new sjcl.cipher.aes(sjcl.codec.hex.toBits(keyhex));
  var cipher = sjcl.mode.gcm.encrypt(key, sjcl.codec.hex.toBits(sig.toString("hex")), iv, [], 32);
  var csig = new Buffer(sjcl.codec.hex.fromBits(cipher), "hex");

	// encrypt the ecc key
  var ekey = to.encrypt(eccpub);

  var body = Buffer.concat([ekey,csig,cbody]);    
  //	console.log(open, body.length);
	var packet = pencode(0x2a, body);
	return packet;
}

exports.deopenize = function(id, open)
{
  var ret = {verify:false};
  // grab the chunks
  var ekey = open.body.slice(0,256);
  var csig = open.body.slice(256,256+260);
  var cbody = open.body.slice(256+260);

  // decrypt the ecc public key and verify/load it
  var eccpub = id.cs["2a"].decrypt(ekey);
  if(!eccpub) return ret;
  try {
    ret.linepub = new ecc.ECKey(ecc.ECCurves.nistp256, Buffer.concat([new Buffer("04","hex"),eccpub]), true);
  }catch(E){};
  if(!ret.linepub) return ret;

  // decipher the body as a packet so we can examine it
  var keyhex = crypto.createHash("sha256").update(eccpub).digest("hex");
  var key = new sjcl.cipher.aes(sjcl.codec.hex.toBits(keyhex));
  var iv = sjcl.codec.hex.toBits("00000000000000000000000000000001");
  var cipher = sjcl.mode.gcm.decrypt(key, sjcl.codec.hex.toBits(cbody.toString("hex")), iv, [], 128);
  var ibody = new Buffer(sjcl.codec.hex.fromBits(cipher), "hex");
  var deciphered = pdecode(ibody);
  if(!deciphered || !deciphered.body) return ret;
  ret.js = deciphered.js;
  ret.key = deciphered.body;

  // extract attached public key
	var from = {};
  if(exports.loadkey(from,deciphered.body)) return ret;

  // decrypt signature
  var keyhex = crypto.createHash("sha256").update(Buffer.concat([eccpub,new Buffer(deciphered.js.line,"hex")])).digest("hex");
  var key = new sjcl.cipher.aes(sjcl.codec.hex.toBits(keyhex));
  var cipher = sjcl.mode.gcm.decrypt(key, sjcl.codec.hex.toBits(csig.toString("hex")), iv, [], 32);
  var sig = new Buffer(sjcl.codec.hex.fromBits(cipher), "hex");

  // verify signature
  ret.verify = from.verify(cbody,sig);
  return ret;
}

// set up the line enc/dec keys
exports.openline = function(from, open)
{
  var ecdhe = from.ecc.deriveSharedSecret(open.linepub);
  from.lineInB = new Buffer(from.lineIn, "hex");
  var hex = crypto.createHash("sha256")
    .update(ecdhe)
    .update(new Buffer(from.lineOut, "hex"))
    .update(new Buffer(from.lineIn, "hex"))
    .digest("hex");
  from.encKey = new sjcl.cipher.aes(sjcl.codec.hex.toBits(hex));
  var hex = crypto.createHash("sha256")
    .update(ecdhe)
    .update(new Buffer(from.lineIn, "hex"))
    .update(new Buffer(from.lineOut, "hex"))
    .digest("hex");
  from.decKey = new sjcl.cipher.aes(sjcl.codec.hex.toBits(hex));
  return true;
}

exports.lineize = function(to, packet)
{
  var iv = crypto.randomBytes(16);
  var buf = pencode(packet.js,packet.body);

	// now encrypt the packet
  var cipher = sjcl.mode.gcm.encrypt(to.encKey, sjcl.codec.hex.toBits(buf.toString("hex")), sjcl.codec.hex.toBits(iv.toString("hex")), [], 128);
  var cbody = new Buffer(sjcl.codec.hex.fromBits(cipher),"hex");

  var body = Buffer.concat([to.lineInB,iv,cbody]);
	return pencode(null,body);
},

exports.delineize = function(from, packet)
{
  if(!packet.body) return "missing body";
  // remove lineid
  packet.body = packet.body.slice(16);
  var iv = sjcl.codec.hex.toBits(packet.body.slice(0,16).toString("hex"));

  try{
    var cipher = sjcl.mode.gcm.decrypt(from.decKey, sjcl.codec.hex.toBits(packet.body.slice(16).toString("hex")), iv, [], 128);    
  }catch(E){
    return E;
  }
  if(!cipher) return "no cipher output";
  var deciphered = pdecode(new Buffer(sjcl.codec.hex.fromBits(cipher),"hex"));
	if(!deciphered) return "invalid decrypted packet";

  packet.js = deciphered.js;
  packet.body = deciphered.body;
  return false;
}

