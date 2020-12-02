const
crypto = require("crypto"),
bn     = require("./lib/bn");

// convert hex format string 
const hformat =(fstring)=>{
    return fstring.replace(/\n/g,'').replace(/ /g,'')
}

// SRP optional config
// h = H(G+N)
const SRP_PARAM = {
    1024: {
        L: 1024,
        N: bn(hformat(`
            EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C 9C256576 
            D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4 8E495C1D 6089DAD1 
            5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29 7BCF1885 C529F566 660E57EC 
            68EDBC3C 05726CC0 2FD4CBF4 976EAA9A FD5138FE 8376435B 9FC61D2F C0EB06E3`
            ),16),
        G: bn(2),
        H: 'sha1'
    },
    2048: {
        L: 2048,
        N: bn(hformat(`
            AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294 3DB56050 
            A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D CD7F48A9 DA04FD50 
            E8083969 EDB767B0 CF609517 9A163AB3 661A05FB D5FAAAE8 2918A996 2F0B93B8 
            55F97993 EC975EEA A80D740A DBF4FF74 7359D041 D5C33EA7 1D281E44 6B14773B 
            CA97B43A 23FB8016 76BD207A 436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 
            544523B5 24B0D57D 5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 
            AF874E73 03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6
            94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F 9E4AFF73`
            ),16),
        G: bn(2),
        H: 'sha256'
    },
}


// ustore for client and server single user
const USTORE = {
    id: "yanjh",
    passwd: "password123"
}


// getX from id and passwd with salt
// x = hash(salt+hash(I:P))
const  getX = (param, U, salt)=> {
    let I = Buffer.from(U.id);
    let P = Buffer.from(U.passwd);
    salt  = Buffer.from(salt,"hex");

    // getx
    let hashIP = crypto.createHash(param.H).update(Buffer.concat([I, Buffer.from(':'), P])).digest();
    return  crypto.createHash(param.H).update(salt).update(hashIP).digest("hex");
}

// computer verifier from salt, identy and password 
// salt = random(8)
// v = G ^ x % N
const  getV = (param, U)=> {

    // genarate a salt 
    let salt = crypto.randomBytes(8).toString("hex");

    // compute x 
    let x = getX(param,U,salt);

    // compute v from x
    let v = param.G.modPow(bn(x,16),param.N).toString(16);

    return { salt, v };
};

// client auth request 
// a = random(16)
// A = G ^ a % N
const c1 =(param)=>{
    // generate login session ononce and aA
    let o = crypto.randomBytes(16).toString("hex");

    // generate a and A 
    let a = crypto.randomBytes(16).toString("hex");
    let A = param.G.modPow(bn(a,16),param.N).toString(16);

    USTORE.o = o;
    USTORE.a = a;
    USTORE.A = A;
    return { o, A, uid : USTORE.id }
}

// server auth res 1

// b  = random(16)
// B  = h * v + G ^ B % N
// u  = Hmac(A+B,o)
// KS = (A * (v ^ u % N)) ^ b % N
const s1 =(param, req)=>{
    let { o, A, uid } = req;

    // let u = crypto.randomBytes(16).toString("hex");
    let b = crypto.randomBytes(16).toString("hex");
    let v = bn(USTORE.v,16);
    let B = param.h.multiply(v).add(param.G.modPow(bn(b,16),param.N)).toString(16);

    // generat u 
    let u = crypto.createHmac(param.H, Buffer.from(o,16))
        .update(Buffer.from(A,16))
        .update(Buffer.from(B,16))
        .digest("hex");

    // save as server side 
    USTORE.u = u;
    USTORE.b = b;
    USTORE.B = B;

    // computer Server K
    let A1 = bn(A,16).multiply(v.modPow(bn(u,16),param.N));
    // let A1 = bn(A,16).multiply(v.pow(bn(u,16)));
    
    let K1 = A1.modPow(bn(b,16),param.N).toString(16);
    USTORE.KS = crypto.createHash(param.H).update(Buffer.from(K1,"hex")).digest("hex") ;

    // return to client 
    return {
        B: B, // server pkey
        salt: USTORE.salt // salt for client compute  
    }
}

// client handle response

// u  = Hmac(A+B,o)
// KC = (B - h * (G ^ x % N)) ^ (a + u * x) % N
// M1 = Hmac(A+B,KC)
const c2 = (param, res) => {
    let { B, salt } = res;
    let a = bn(USTORE.a,16);

    // generat u 
    let u = crypto.createHmac(param.H, Buffer.from(USTORE.o,16))
    .update(Buffer.from(USTORE.A,16))
    .update(Buffer.from(B,16))
    .digest("hex");

    // get x from user and salt
    let x = getX(param,USTORE, salt);
    x = bn(x,16);

    // a+u*x 
    let aux = a.add(bn(u,16).multiply(x));

    let K1 = bn(B,16).minus(param.h.multiply(param.G.modPow(x,param.N))).modPow(aux,param.N).toString(16);
    USTORE.KC  = crypto.createHash(param.H).update(Buffer.from(K1,"hex")).digest("hex");

    // sign A+B with K
    let M1 = crypto.createHmac(param.H,Buffer.from(USTORE.KC,"hex"))
        .update(Buffer.from(USTORE.A,"hex"))
        .update(Buffer.from(USTORE.B,"hex"))
        .digest("hex");

    USTORE.M1 = M1;
    return { M1 }
}

// server auth res 2
// r = M1 == Hmac(A+B,KS)
// M2 = Hmac(A+M1),KS)
const s2 =(param, req)=>{
    let mc = req.M1;

    // sign A+B with K
    let ms = crypto.createHmac(param.H,Buffer.from(USTORE.KS,"hex"))
        .update(Buffer.from(USTORE.A,"hex"))
        .update(Buffer.from(USTORE.B,"hex"))
        .digest("hex");

    let r = mc == ms;
    if (r) { // sign A+M with K
        let M2 = crypto.createHmac(param.H,Buffer.from(USTORE.KS,"hex"))
            .update(Buffer.from(USTORE.A,"hex"))
            .update(Buffer.from(mc,"hex"))
            .digest("hex");
        return { r, M2};
    } else {
        return { r };
    }
}

// server auth res 1
// r = M2 == Hmac(A+M1,KC)
const cfinal =(param, req)=>{
    let ms = req.M2;

    // sign A+B with Kc
    let mc = crypto.createHmac(param.H,Buffer.from(USTORE.KC,"hex"))
        .update(Buffer.from(USTORE.A,"hex"))
        .update(Buffer.from(USTORE.M1,"hex"))
        .digest("hex");

    return { result:mc == ms };
}


// simulation srp proectss
const test = ()=> {
    // algo pram prepared fact 
    const cparam = SRP_PARAM[2048];
    cparam.h = bn(crypto.createHash(cparam.H)
        .update(Buffer.from(cparam.G.toString(16)),"hex")
        .update(Buffer.from(cparam.N.toString(16)),"hex")
        .digest("hex"),16)

    // computer Verifirer
    let cv = getV(cparam, USTORE);
    console.log("Identy Save:",cv);

    // save user info in server
    USTORE.salt = cv.salt;
    USTORE.v    = cv.v;

    // client req 1 
    let q1 = c1(cparam);    
    console.log("Client Req1:",q1);
    
    // send to server and get challege
    let r1 = s1(cparam,q1);
    console.log("Server Res1:",r1);
    
    // client response
    let q2 = c2(cparam,r1);
    console.log("Client Req2:",q2);
    
    let r2 = s2(cparam,q2);
    console.log("Server Res2:",r2);

    let cf = cfinal(cparam,r2);
    console.log("Client Final:",cf);

    console.log("------------ finished  -------------",cf);

}

setTimeout(test,1000);
