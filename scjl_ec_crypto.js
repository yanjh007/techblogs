const 
EC_TYPE = "secp256k1",
crypto = require('crypto'),
sjcl   = require("./lib/sjcl"),
hex    = sjcl.codec.hex;

// Generate Alice's keys use private key ...
const alice_vkey = "451c6de369028a6e6114dcdf4e8f575ae10234818fd91ac1c477bd255af53081";
const alice = crypto.createECDH(EC_TYPE);
alice.setPrivateKey(Buffer.from(alice_vkey,"hex"));

let alice_pkey = alice.getPublicKey("hex");
console.log("Server Pkey:",alice_pkey);

// // SJCL 
// // Unserialized private key:
// const bobVkey2 = new sjcl.ecc.elGamal.secretKey(
//     sjcl.ecc.curves.k256,
//     sjcl.ecc.curves.k256.field.fromBits(sjcl.codec.hex.toBits(alice_vkey))
// )

// bob in client browser
let bobPair = sjcl.ecc.elGamal.generateKeys(sjcl.ecc.curves.k256);

// Serialized private key:
let bobVkey = sjcl.codec.hex.fromBits(bobPair.sec.get())

// Serialized public key conact x and y
let bobPub  = bobPair.pub.get() 
let bobPkey = "04"+sjcl.codec.hex.fromBits(bobPub.x.concat(bobPub.y))

console.log("Client Pkey:",bobPkey);

let shareKey = alice.computeSecret(Buffer.from(bobPkey,"hex")).toString("hex");
console.log("Alice Computed Sharekey:", shareKey);

let apub = new sjcl.ecc.elGamal.publicKey(
    sjcl.ecc.curves.k256, 
    sjcl.codec.hex.toBits(alice_pkey.slice(2))
)
    
let bobV = new sjcl.ecc.elGamal.secretKey( 
    sjcl.ecc.curves.k256, 
    sjcl.ecc.curves.c256.field.fromBits(sjcl.codec.hex.toBits(bobVkey))
)
     
let shareKey2 = sjcl.codec.hex.fromBits(bobV.dhJavaEc(apub));
console.log("Bob Computed Sharekey:", shareKey2);

const clientid = Math.random().toString(36).slice(2,10);
const scontent  = JSON.stringify({ cid: clientid, name: "中国" });

let hmac = new sjcl.misc.hmac(sjcl.codec.utf8String.toBits(shareKey2));
let sign = hmac.encrypt(scontent);
sign = sjcl.codec.hex.fromBits(sign);

console.log("Client ID Signed:",clientid,sign);

let sign2 = crypto.createHmac("sha256",shareKey2).update(scontent).digest("hex");
console.log("Server Signed:",clientid,sign2);

// encrtype 

let ctext1 = sjcl.encrypt(hex.toBits(shareKey),scontent);
ctext1 = JSON.parse(ctext1);
// ctext1 =[ctext1.ct, ctext1.iv, ctext1.salt].join("&");

console.log("SJCL Encrypt:", JSON.stringify(ctext1));

// return ;

const ALGORITHM = 'aes-128-ccm';

// // decrypte
// const password = 'Password used to generate key';
// // Use the async `crypto.scrypt()` instead.
// const key = crypto.scryptSync(password, 'salt', 24);
// // The IV is usually passed along with the ciphertext.
// const iv = Buffer.alloc(16, 0); // Initialization vector.
let iv = "4864aca2";
let aoption = {
    authTagLength: 8
}

let akey = Buffer.from(shareKey,"hex").toString("base64");

const cipher = crypto.createCipheriv(ALGORITHM, akey.substr(0,16), iv, aoption);

let ctext = cipher.update(scontent,"utf8","base64");
ctext += cipher.final("base64");
const tag = cipher.getAuthTag();

console.log("server encrypt:",ctext);

const decipher = crypto.createDecipheriv(ALGORITHM, akey.substr(0,16), iv, aoption);
decipher.setAuthTag(tag);
let dtext = decipher.update(ctext,"base64","utf8");
dtext += decipher.final("utf8");
console.log("server decrypt:",dtext);


// Generate Bob's keys...
// const bob = crypto.createECDH(type);
// const bobKey = bob.generateKeys();

// console.log("Alice private key:\t",alice_vkey);
// console.log("Alice public key:\t",alice_pkey)

// console.log("\nBob private key:\t",bob.getPrivateKey().toString('hex'));
// console.log("Bob public key:\t",bobKey.toString('hex'));


// // Exchange and generate the secret...
// const aliceSecret = alice.computeSecret(bobKey);
// const bobSecret = bob.computeSecret(Buffer.from(alice_pkey,"hex"));

// console.log("\nAlice shared key:\t",aliceSecret.toString('hex'))
// console.log("Bob shared key:\t\t",bobSecret.toString('hex'));

/**
 * Type:	 secp256k1

Alice private key:	 451c6de369028a6e6114dcdf4e8f575ae10234818fd91ac1c477bd255af53081
Alice public key:	 04a7794015e21c019834b37a4854d6e6f320ec704febb1320fe63978ed249c96e139dc520873a980702f62ad6246261f51536453b998515ffe7a787232aa8bc00e

Bob private key:	 e841c650dcc5ebd18f32ab31e7cb707941cfbd158bb7c028f0bcde3facdbc0b8
Bob public key:	 041986216c163f1d38824b07eb51b42de4a01e865137c6e916999767a4c5a0f6e99538165b911f540a1107d4d79ca88a7d21a1ba1c212f28e25116bf6f82d76b4c

Alice shared key:	 893750b7de85bacd97bb70f3205d71052e2fb2a7f336195ac10e44aa0e743cd2
Bob shared key:		 893750b7de85bacd97bb70f3205d71052e2fb2a7f336195ac10e44aa0e743cd2
 * 
 * 
 */
