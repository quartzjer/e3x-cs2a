var crypto = require("crypto");
var sjcl = require("sjcl");

exports.id = '2a';

// env-specific crypto methods
var forge;
exports.crypt = function(ecc,f)
{
  crypto.ecc = ecc;
  forge = f;
}

exports.generate = function(cb, cbStep)
{
  var state = forge.rsa.createKeyPairGenerationState(2048, 0x10001);
  var step = function() {
    // run for 100 ms
    if(!forge.rsa.stepKeyPairGenerationState(state, 100)) {
      if(cbStep) cbStep();
      setTimeout(step, 10);
    } else {
      var key = forge.asn1.toDer(forge.pki.publicKeyToAsn1(state.keys.publicKey)).bytes();
      var secret = forge.asn1.toDer(forge.pki.privateKeyToAsn1(state.keys.privateKey)).bytes();
      cb(null, {key:new Buffer(key, 'binary'), secret:new Buffer(secret, 'binary')});
    }
  }
  setTimeout(step);  
}

exports.loadkey = function(id, key, secret)
{
  var pk = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(key.toString("binary")));    
  id.encrypt = function(buf){
    return new Buffer(pk.encrypt(buf.toString("binary"), "RSA-OAEP"), "binary");
  };
  id.verify = function(a,b){
    return pk.verify(a.toString("binary"), b.toString("binary"));
  };
  if(secret)
  {
    var sk = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(secret.toString("binary")));
    id.sign = function(buf){
      var md = forge.md.sha256.create();
      md.update(buf.toString("binary"));
      return new Buffer(sk.sign(md),"binary");
    };
    id.decrypt = function(buf){
      return new Buffer(sk.decrypt(buf.toString("binary"), "RSA-OAEP"),"binary");
    };
  }
  return false;
}

exports.openize = function(id, to, inner)
{
	if(!to.ecc) to.ecc = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp256r1);
  var eccpub = to.ecc.PublicKey.slice(1);

	// encrypt the body
  var ibody = (!Buffer.isBuffer(inner)) ? self.pencode(inner,id.cs["2a"].key) : inner;
  var keyhex = crypto.createHash("sha256").update(eccpub).digest("hex");
  var key = new sjcl.cipher.aes(sjcl.codec.hex.toBits(keyhex));
  var iv = sjcl.codec.hex.toBits("00000000000000000000000000000001");
  var cipher = sjcl.mode.gcm.encrypt(key, sjcl.codec.hex.toBits(ibody.toString("hex")), iv, [], 128);
  var cbody = new Buffer(sjcl.codec.hex.fromBits(cipher), "hex");

	// sign & encrypt the sig
  var sig = id.cs["2a"].sign(cbody);
  if(!to.lineOut) to.lineOut = ""; // no lines for tickets
  var keyhex = crypto.createHash("sha256").update(Buffer.concat([eccpub,new Buffer(to.lineOut,"hex")])).digest("hex");
  var key = new sjcl.cipher.aes(sjcl.codec.hex.toBits(keyhex));
  var cipher = sjcl.mode.gcm.encrypt(key, sjcl.codec.hex.toBits(sig.toString("hex")), iv, [], 32);
  var csig = new Buffer(sjcl.codec.hex.fromBits(cipher), "hex");

	// encrypt the ecc key
  var ekey = to.encrypt(eccpub);

  var body = Buffer.concat([ekey,csig,cbody]);    
  //	console.log(open, body.length);
	var packet = self.pencode(0x2a, body);
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
    ret.linepub = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp256r1, Buffer.concat([new Buffer("04","hex"),eccpub]), true);
  }catch(E){};
  if(!ret.linepub) return ret;

  // decipher the body as a packet so we can examine it
  var keyhex = crypto.createHash("sha256").update(eccpub).digest("hex");
  var key = new sjcl.cipher.aes(sjcl.codec.hex.toBits(keyhex));
  var iv = sjcl.codec.hex.toBits("00000000000000000000000000000001");
  var cipher = sjcl.mode.gcm.decrypt(key, sjcl.codec.hex.toBits(cbody.toString("hex")), iv, [], 128);
  var ibody = new Buffer(sjcl.codec.hex.fromBits(cipher), "hex");
  var deciphered = self.pdecode(ibody);
  if(!deciphered || !deciphered.body) return ret;
  ret.js = deciphered.js;
  ret.inner = deciphered;
  
  var from = {};
  var lineIn;
  if(!open.from)
  {
    // extract attached public key
    ret.key = deciphered.body;
    if(exports.loadkey(from,deciphered.body)) return ret;
    lineIn = deciphered.js.line;
  }else{
    from = open.from;
    lineIn = "";
  }

  // decrypt signature
  var keyhex = crypto.createHash("sha256").update(Buffer.concat([eccpub,new Buffer(lineIn,"hex")])).digest("hex");
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
  var buf = self.pencode(packet.js,packet.body);

	// now encrypt the packet
  var cipher = sjcl.mode.gcm.encrypt(to.encKey, sjcl.codec.hex.toBits(buf.toString("hex")), sjcl.codec.hex.toBits(iv.toString("hex")), [], 128);
  var cbody = new Buffer(sjcl.codec.hex.fromBits(cipher),"hex");

  var body = Buffer.concat([to.lineInB,iv,cbody]);
	return self.pencode(null,body);
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
  var deciphered = self.pdecode(new Buffer(sjcl.codec.hex.fromBits(cipher),"hex"));
	if(!deciphered) return "invalid decrypted packet";

  packet.js = deciphered.js;
  packet.body = deciphered.body;
  return false;
}


exports.Local = function(pair)
{
  var self = this;
  self.key = {}
  try{
    self.err = exports.loadkey(self.key,pair.key,pair.secret);
  }catch(E){
    self.err = E;
  }

  // decrypt message body and return the inner
  self.decrypt = function(body){
    if(!Buffer.isBuffer(body)) return false;
    if(body.length < 256+12+256+16) return false;

    // rsa decrypt the keys
    var keys = self.key.decrypt(body.slice(0,256));
    if(!keys || keys.length != (65+32)) return false;

    // aes decrypt the inner
    var keyhex = keys.slice(65,65+32).toString('hex');
    var ivhex = body.slice(256,256+12).toString('hex');
    var aadhex = body.slice(0,256+12).toString('hex');
    var cbodyhex = body.slice(256+12).toString('hex');

    var key = new sjcl.cipher.aes(sjcl.codec.hex.toBits(keyhex));
    var iv = sjcl.codec.hex.toBits(ivhex);
    var aad = sjcl.codec.hex.toBits(aadhex);
    var cbody = sjcl.codec.hex.toBits(cbodyhex);
    var cipher = sjcl.mode.gcm.decrypt(key, cbody, iv, aad, 128);
    var body = new Buffer(sjcl.codec.hex.fromBits(cipher), 'hex');
    
    // return buf of just the inner, add decrypted sig/keys
    var ret = body.slice(0,body.length-256);
    ret._keys = keys;
    ret._sig = body.slice(ret.length);

    return ret;
  };
}

exports.Remote = function(key)
{
  var self = this;
  self.key = {};
  try{
    self.err = exports.loadkey(self.key,key);
    self.ephemeral = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp256r1);
    self.secret = crypto.randomBytes(32);
    self.iv = crypto.randomBytes(12);
    self.keys = self.key.encrypt(Buffer.concat([self.ephemeral.PublicKey,self.secret]));
    self.token = crypto.createHash('sha256').update(self.keys.slice(0,16)).digest().slice(0,16);
  }catch(E){
    self.err = E;
  }

  // verifies the authenticity of an incoming message body
  self.verify = function(local, body){
    if(!Buffer.isBuffer(body)) return false;

    // decrypt it first
    var inner = local.decrypt(body);
    if(!inner) return false;
    
    // verify the rsa signature
    if(!self.key.verify(Buffer.concat([body.slice(0,256+12),inner]), inner._sig)) return false;
    
    // cache the decrypted keys
    self.cached = inner._keys;
    
    return true;
  };

  self.encrypt = function(local, inner){
    if(!Buffer.isBuffer(inner)) return false;

    // increment the IV
    var seq = self.iv.readUInt32LE(0);
    seq++;
    self.iv.writeUInt32LE(seq,0);

    // generate the signature
    var sig = local.key.sign(Buffer.concat([self.keys,self.iv,inner]));

    // aes gcm encrypt the inner+sig
    var aad = Buffer.concat([self.keys,self.iv]);
    var body = Buffer.concat([inner,sig]);
    var key = new sjcl.cipher.aes(sjcl.codec.hex.toBits(self.secret.toString('hex')));
    var iv = sjcl.codec.hex.toBits(self.iv.toString('hex'));
    var cipher = sjcl.mode.gcm.encrypt(key, sjcl.codec.hex.toBits(body.toString('hex')), iv, sjcl.codec.hex.toBits(aad.toString('hex')), 128);
    var cbody = new Buffer(sjcl.codec.hex.fromBits(cipher), 'hex');

    // all done!
    return Buffer.concat([self.keys,self.iv,cbody]);

  };

}

exports.Ephemeral = function(remote, outer, inner)
{
  var self = this;
  
  try {
    // get the ecc key from cached or decrypted
    var keys = remote.cached || (inner && inner._keys);

    // do the ecdh thing
    var ecc = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp256r1, keys.slice(0,65), true);
    var ecdhe = remote.ephemeral.deriveSharedSecret(ecc);

    // use the other two secrets too
    var secret = keys.slice(65);
    var hex = crypto.createHash("sha256")
      .update(ecdhe)
      .update(remote.secret)
      .update(secret)
      .digest("hex");
    self.encKey = new sjcl.cipher.aes(sjcl.codec.hex.toBits(hex));
    var hex = crypto.createHash("sha256")
      .update(ecdhe)
      .update(secret)
      .update(remote.secret)
      .digest("hex");
    self.decKey = new sjcl.cipher.aes(sjcl.codec.hex.toBits(hex));
    
    self.token = crypto.createHash('sha256').update(outer.slice(0,16)).digest().slice(0,16);
    
  }catch(E){
    self.err = E;
  }
  

  self.decrypt = function(outer){

    try{
      var ivhex = sjcl.codec.hex.toBits(outer.slice(0,16).toString("hex"));
      var cipher = sjcl.mode.gcm.decrypt(self.decKey, sjcl.codec.hex.toBits(outer.slice(16).toString("hex")), ivhex, [], 128);
      var inner = new Buffer(sjcl.codec.hex.fromBits(cipher),"hex");
    }catch(E){
      self.err = E;
    }
    
    return inner;
  };

  self.encrypt = function(inner){
    // now encrypt the packet

    var iv = crypto.randomBytes(16);
    var cipher = sjcl.mode.gcm.encrypt(self.encKey, sjcl.codec.hex.toBits(inner.toString("hex")), sjcl.codec.hex.toBits(iv.toString("hex")), [], 128);
    var cbody = new Buffer(sjcl.codec.hex.fromBits(cipher),"hex");

    return Buffer.concat([iv,cbody]);
  };
}

