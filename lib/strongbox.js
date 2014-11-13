var Bolty = require('bolty');
var sjcl = require('sjcl-all');

var StrongBox = function(schema){
  this._sjclDefaults = {
    v: 1,
    iter: 1000,
    ks: 256,
    ts: 128,
    mode: 'ccm',
    cipher: 'aes'
  };

  for(var key in schema.security)
    this._sjclDefaults[key] = schema.security[key];

  this._schema = schema;
  this._schemaEncoder = new Bolty(schema.fields);
  this._strongBoxEncoder = new Bolty({
    iv: 'buffer',
    salt: 'buffer',
    data: 'buffer'
  });
};

StrongBox.prototype.lock = function(obj){
  var data = this._schemaEncoder.encode(obj);
  var p = this._sjclDefaults;
  var salt = p.salt || sjcl.random.randomWords(2, 2);
  var iv = p.iv || sjcl.random.randomWords(4, 2);
  var pwd = sjcl.misc.pbkdf2(p.password, salt, p.iter);
  var prp = new sjcl.cipher[p.cipher](pwd);

  var ct = sjcl.mode[p.mode]
    .encrypt(prp, sjcl.codec.bytes.toBits(data), iv, p.adata, p.ts);

  var buffer = new Buffer(sjcl.codec.bytes.fromBits(ct));

  return this._strongBoxEncoder.encode({
    iv: p.iv ? new Buffer(0) : Buffer.concat(iv.map(function(word){
      var buff = new Buffer(4);
      buff.writeInt32LE(word, 0);

      return buff;
    })),
    salt: p.salt ? new Buffer(0) : Buffer.concat(salt.map(function(word){
      var buff = new Buffer(4);
      buff.writeInt32LE(word, 0);

      return buff;
    })),
    data: buffer
  });
};

StrongBox.prototype.unlock = function(buffer){
  var data = this._strongBoxEncoder.decode(buffer);
  var p = this._sjclDefaults;

  var salt = !data.salt.length ? p.salt : Array
    .apply(null, {length: (data.salt.length / 4)})
    .map(Number.call, Number)
    .map(function(pos){
      return data.salt.readInt32LE(pos * 4);
    });

  var iv = !data.iv.length ? p.iv : Array
    .apply(null, {length: (data.iv.length / 4)})
    .map(Number.call, Number)
    .map(function(pos){
      return data.iv.readInt32LE(pos * 4);
    });

  var pwd = sjcl.misc.pbkdf2(p.password, salt, p.iter);
  var prp = new sjcl.cipher[p.cipher](pwd);
  var ct = sjcl.mode[p.mode]
    .decrypt(prp, sjcl.codec.bytes.toBits(data.data), iv, p.adata, p.ts);

  var buff = new Buffer(sjcl.codec.bytes.fromBits(ct));

  return this._schemaEncoder.decode(buff);
};

module.exports = StrongBox;
