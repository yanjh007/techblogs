const 
crypto     = require('crypto'),
CryptoJS   = require('crypto-js');

const message = JSON.stringify({
    id: 1000,
    name: "中国China"
});
const passwd = "password";

// encrypted with cryptoJS
let CLEN = 32; 
let ITER = 1000 + Math.random()*1000 | 0;
let iv   = CryptoJS.lib.WordArray.random(8);
let salt = iv.toString();

let key1 = CryptoJS.PBKDF2(passwd, salt, { keySize: 256/CLEN, iterations: ITER }); 
console.log("Key1:",key1.toString());

const encrypted = CryptoJS.AES.encrypt(message, key1, {
  iv: iv.concat(iv), // two iv 
  padding: CryptoJS.pad.Pkcs7,
  mode: CryptoJS.mode.CBC
});

// output base64
const encryptedString = [encrypted.toString(), salt, ITER].join(",");

console.log("Encrypted:", encryptedString); 

let [dtext,salt2,it2] = encryptedString.split(",");

let key2  =  crypto.pbkdf2Sync(passwd, salt2, parseInt(it2), CLEN, null);
console.log("Key2:",key2.toString("hex"));

const decipher = crypto.createDecipheriv('aes-256-cbc', key2, Buffer.from(salt2+salt2,"hex"));
let decrypted = decipher.update(dtext, 'base64', 'utf8');
decrypted += decipher.final('utf8');

console.log("Decryptd:",decrypted);


console.log("--------- Server to Client --------------------------");

let salt3 = crypto.randomBytes(8).toString("hex");
let key3  = crypto.pbkdf2Sync(passwd, salt2, ITER, CLEN, null);
console.log("Key3:",key3.toString("hex"));

const cipher = crypto.createCipheriv('aes-256-cbc', key3, Buffer.from(salt3+salt3,"hex"));
let crypted = cipher.update(message, 'utf8', 'base64');
crypted += cipher.final('base64');
crypted = [crypted, salt3, ITER].join(",");
console.log("Server Cryptd:",crypted);

let [dtext3,salt4,it4] = crypted.split(",");
let key4 = CryptoJS.PBKDF2(passwd, salt4, { keySize: 256/CLEN, iterations: parseInt(it4) }); 
console.log("Key4:",key4.toString());

let decrypted4 = CryptoJS.AES.decrypt(dtext3, key4, {
    iv: CryptoJS.enc.Hex.parse(salt4+salt4),
    padding: CryptoJS.pad.Pkcs7,
    mode: CryptoJS.mode.CBC
});

decrypted4 =  decrypted4.toString(CryptoJS.enc.Utf8);
console.log("Decrypted:",decrypted); 


// var key256Bits10000Iterations = CryptoJS.PBKDF2("Secret Passphrase", salt, { keySize: 256/32, iterations: 10000 }); //I don't know this is dividing by 32
// var encrypted = CryptoJS.AES.encrypt("Message", key, { mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7, iv:iv });
