const 
sjcl   = require("./lib/sjcl"),
crypto = require('crypto');


const 
PASSWD = "passwd",  // 密码
KLEN = 128, // 密钥长度
TLEN = 8, // Tag长度
ALGO = 'aes-128-ccm', // 算法
COPTION = { // 算法参数 
    authTagLength: 8
},
CTEMPLE = {
    v : 1,
    ks: KLEN,
    ts: TLEN*8,
    mode: "ccm",
    adata:"",
    cipher:"aes"
},
ITER = 500 + Math.random()*500 | 0 ; // 轮次 500~999

let ptext = JSON.stringify({
    id: 1000,
    name : "china中国"
});

let salt = sjcl.random.randomWords(1);
let cp = { 
    mode: "ccm",
    iter: ITER,
    ks: KLEN ,
    ts: TLEN * 8,
    salt: salt,
    iv : salt.concat(salt)
};
let crp = {};

let cresult = sjcl.encrypt(PASSWD, ptext, cp, crp);

console.log("Key:", sjcl.codec.hex.fromBits(crp.key));
console.log("Salt:", sjcl.codec.hex.fromBits(crp.salt));
let oresult = JSON.parse(cresult);
console.log("CT",oresult.ct);
let sresult = [oresult.ct,oresult.salt,ITER].join(",");

// decrypt use crypto 
let [ctext, salt2, iter2] = sresult.split(",");
salt2 = Buffer.from(salt2,"base64");
let key2  = crypto.pbkdf2Sync(PASSWD, salt2, parseInt(iter2), KLEN/8 , "sha256");

console.log("Key2:", key2.toString("hex"));

let etext = Buffer.from(ctext,"base64").toString("hex");
let etag = etext.slice(-COPTION.authTagLength*2);
etext = etext.slice(0,-COPTION.authTagLength*2);
console.log("CrypedSjcl:",etext,etag);

let iv2 = Buffer.concat([salt2,salt2]);
const decipher = crypto.createDecipheriv(ALGO, key2, iv2 , COPTION);

// // auth tag
decipher.setAuthTag(Buffer.from(etag,"hex"));
let decrypted = decipher.update(etext, 'hex', 'utf8');
decrypted += decipher.final('utf8');

console.log("Decrypted:",decrypted);


let salt3  = crypto.randomBytes(4);
let key3   = crypto.pbkdf2Sync(PASSWD, salt3, ITER, KLEN/8 , "sha256");
console.log("Key3:",key3.toString("hex"));

// crypto use crypto 
let iv3 = Buffer.concat([salt3,salt3]);
const cipher = crypto.createCipheriv(ALGO, key3, iv3, COPTION);

let crypted = cipher.update(ptext, 'utf8', 'hex');
crypted += cipher.final('hex');

let tag3 = cipher.getAuthTag().toString("hex");

console.log("Crypted:", crypted, tag3);

crypted = crypted+tag3;
crypted = Buffer.from(crypted,"hex").toString("base64");

let sresult4 = [crypted,salt3.toString("base64"),ITER].join(",");

// decrypted use sjcl
let [etext4,salt4,iter4] = sresult4.split(",");

let iv4 = sjcl.codec.base64.toBits(salt4);
iv4 = iv4.concat(iv4);
iv4 = sjcl.codec.base64.fromBits(iv4);

let cobject = {...CTEMPLE,...{
    iter: parseInt(iter4),
    iv: iv4,
    salt: salt4,
    ct: etext4
}}

let dresult = sjcl.decrypt(PASSWD, JSON.stringify(cobject));
console.log("SJCL Decryped:",dresult);


/*
T: 中国China
W: password
P: "{"adata":"","iter":1000,"mode":"ccm","ts":64,"ks":128,"salt":[-501172229,-272242772]}"
RP: "{"iv":[1005516172,-1953078837,-1164633211,-567267489],"v":1,"iter":1000,"ks":128,"ts":64,"mode":"ccm","adata":[],"cipher":"aes","salt":[-501172229,-272242772],"key":[1556955868,632485265,1927209053,-1962681172]}"
K: 5ccd42dc25b2f59172dee05d8b03dcac
S: e220b7fbefc5e7ac
I: 3beef58c8b9661cbba951b85de302f5f
C: {
    "iv":"O+71jIuWYcu6lRuF3jAvXw==",
    "v":1,
    "iter":1000,
    "ks":128,
    "ts":64,
    "mode":"ccm",
    "adata":"",
    "cipher":"aes",
    "salt":"4iC3++/F56w=",
    "ct":"6OVGyQPecTsDAEYtWlfO6681Gg=="
}



*/
