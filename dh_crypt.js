const 
sjcl   = require("./lib/sjcl"),
crypto = require('crypto'),
DH_PRIME  = "dbc91460ad6c3a2a91729f07ce5e96eb"; // 128 bit prime

// need sjcl bn 
function Uldh(prime) {
    this.bn = sjcl.bn ;
    this.MG = new this.bn("02");
    this.MP = new this.bn(prime);

    this._pad = (skey,klen = 32) => {
        if (skey.startsWith("0x")) skey = skey.slice(2);
        return (skey.length < klen) ? (Array(klen).fill(0).join('')+skey).slice(-klen) : skey;
    },

    this.getKeys = (vkey)=>{
        if (this.VK) {
            // return [this.VK.toString(), this.PK.toString()];
        } else if (vkey) { // generate public key by private key 
            this.VK = new this.bn(vkey);
            this.PK = this.MG.powermod(this.VK,this.MP);

        } else {
            this.VK = this.bn.random(this.MP.sub(new this.bn("2000"))).add(new this.bn("1000"));
            this.PK = this.MG.powermod(this.VK,this.MP);
        }
        return [ this._pad(this.VK.toString()), this._pad(this.PK.toString())];
    }

    this.compute = (spkey)=>{
        let spk = new this.bn(spkey);
        let sk  = spk.powermod(this.VK,this.MP).toString();
        return this._pad(sk);
    }
}

// client key
const uldh = new Uldh(DH_PRIME);
let cks = uldh.getKeys();

console.log("Client Keys:", JSON.stringify(cks));

let cpkey= cks[1];
console.log("Send Public key to Server:", cpkey);

// server key generate on startup as const
const
ilen   =  32; // pad length
spk =  "9618ad003b3999be68749f48d2dce2a3",
svk =  "6a6cb85ebccf4a2771284ed326a5d438",
sdh = crypto.createDiffieHellman(DH_PRIME,"hex","02","hex");

sdh.generateKeys();
sdh.setPrivateKey(svk,"hex");
sdh.setPublicKey(spk,"hex");

let sskey = sdh.computeSecret(cpkey,"hex","hex");
sskey = (Array(ilen).fill("0").join('')+sskey).slice(-ilen);
console.log("Shared Key:", sskey);

console.log("Send Server Public Key to Client:",spk);

let cskey = uldh.compute(spk);

// client get server public key and comput share key

console.log("Client Compute Shared Key:", cskey);

// client encrypt 
const 
KLEN = 256,
TLEN = 8,
CTEMPLE = {
    v : 1,
    ks: KLEN,
    ts: TLEN * 8,
    mode: "ccm",
    adata:"",
    cipher:"aes"
};

let ptext = JSON.stringify({
    id: 100,
    name : "china中国"
});

let 
iv   = sjcl.random.randomWords(2), // random iv 
cp   = { 
    mode: "ccm",
    ks  : KLEN ,
    ts  : TLEN * 8,
    iv  : iv
};
crp = {};

// sha256 share key for encrypt use iv as key of key 
console.log("CIV:", sjcl.codec.hex.fromBits(iv) );
let ckey = new sjcl.misc.hmac(iv).encrypt(cskey);

// ckey = sjcl.codec.hex.fromBits(ckey);
let encrypted = sjcl.encrypt(ckey, ptext, cp, crp);
console.log("Client Hmac Key:", sjcl.codec.hex.fromBits(ckey));

let cobject = JSON.parse(encrypted);
console.log("Client Encrypted:", encrypted);

let cresult = [cobject.ct,cobject.iv].join(",");

console.log("Client Send To Server:", cresult);

// decrypt on server 
const 
ALGO = 'aes-256-ccm', // 算法
COPTION = { // 算法参数 
    authTagLength: 8
};

let [ctext, iv2] = cresult.split(",");
iv2 = Buffer.from(iv2,"base64");

let etext = Buffer.from(ctext,"base64").toString("hex");
let etag = etext.slice(-COPTION.authTagLength*2);
etext = etext.slice(0,-COPTION.authTagLength*2);
console.log("Cryped Sjcl:",etext,etag);

// sha256 server share key
let skey = crypto.createHmac("sha256",iv2).update(sskey).digest();
// let skey = crypto.createHash("sha256").update(sskey).digest("hex");
// skey = Buffer.from(skey,"hex");
const decipher = crypto.createDecipheriv(ALGO, skey, iv2 , COPTION);

// // auth tag
decipher.setAuthTag(Buffer.from(etag,"hex"));
let decrypted = decipher.update(etext, 'hex', 'utf8');
decrypted += decipher.final('utf8');

console.log("Decrypted:",decrypted);

// return to client 
ptext = JSON.stringify({
    R: 200,
    C: "OK正确"
});

// crypto use crypto 
let iv3 = crypto.randomBytes(8);
skey = crypto.createHmac("sha256",iv3).update(sskey).digest();
const cipher = crypto.createCipheriv(ALGO, skey, iv3, COPTION);

let crypted = cipher.update(ptext, 'utf8', 'hex');
crypted += cipher.final('hex');

let tag3 = cipher.getAuthTag().toString("hex");

console.log("Crypted:", crypted, tag3);

crypted = crypted+tag3;
crypted = Buffer.from(crypted,"hex").toString("base64");

let sresult3 = [crypted,iv3.toString("base64")].join(",");
console.log("Server Response:", sresult3);

// sjcl client decrypt
// decrypted use sjcl
let [etext4,iv4] = sresult3.split(",");
ckey = new sjcl.misc.hmac(sjcl.codec.base64.toBits(iv4)).encrypt(cskey);

cobject = JSON.stringify({ ...CTEMPLE, ...{
    iv: iv4,
    ct: etext4
}});

let dresult = sjcl.decrypt(ckey, cobject);
console.log("SJCL Decryped:",dresult);
