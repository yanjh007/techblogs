const { ok } = require("assert");
const { setUncaughtExceptionCaptureCallback } = require("process");

// scram method implatment and test 
const 
crypto = require("crypto"),
cstore = {}, // client store instead brwser 
sstore = { sid: "SYSTEMID"}; // server store instead db

// xor computer 
const mxor = (data1,data2)=> {
    if (typeof data1 ==="string") data1 = Buffer.from(data1,"hex");
    if (typeof data2 ==="string") data2 = Buffer.from(data2,"hex");

    let sxor = data1.map((v,i)=>v ^ data2[i]).toString("hex");
    return sxor;
}


// hash and hmac
const hmac = (data,hkey)=>{
    const HTYPE = "sha256";
    const OTYPE = "hex";

    if (hkey) {
        if (typeof hkey == "string") hkey = Buffer.from(hkey);
        return crypto.createHmac(HTYPE,hkey).update(data).digest(OTYPE);
    } else {
        return crypto.createHash(HTYPE).update(data).digest(OTYPE);
    }
}

const reg = (auth)=>{
    let { user, passwd } = auth;
    passwd = hmac(passwd);

    // let salt
    let salt = crypto.randomBytes(4);
    let iter = salt.reduce((v,c)=>c+31*v,1024) % 1024 + 1024;
    let saltpasswd = crypto.pbkdf2Sync(Buffer.from(passwd,"hex"),salt,iter,256,"sha256");

    let clientkey  = hmac(user,saltpasswd);
    console.log("clientkey save:", clientkey);

    let serverkey  = hmac(sstore.sid,saltpasswd);
    
    let storekey = salt.toString("hex") + hmac(Buffer.from(clientkey,"hex"));
    // let storekey = salt.toString("hex")+ clientkey;

    sstore[user] = { storekey, serverkey };

    return user+":"+storekey;
}

// client store info

const c1 = (auth)=>{
    let 
    cnonce = crypto.randomBytes(4).toString("hex"),
    { user, passwd }  = auth;

    cstore.user   = user;
    cstore.passwd = hmac(passwd);
    cstore.cnonce = cnonce;

    return { cnonce, user }
}

// servre phase1
const s1 = (req)=>{
    let {user, cnonce } = req;
    let uinfo = sstore[user];
    // get salt 
    let salt  = uinfo.storekey.slice(0,8);

    // save and get mnonce
    uinfo.snonce = crypto.randomBytes(4).toString("hex");
    uinfo.cnonce = cnonce;

    let mnonce = mxor(uinfo.snonce,cnonce);

    // save uinfo
    sstore[user] = uinfo;

    // return 
    return { salt, mnonce, sid: sstore.sid };
}

// handle server1 response
const c2 = (res)=>{
    // client info
    let {user, passwd, cnonce } = cstore;

    // get server info
    let {salt, mnonce, sid} = res;
    cstore.snonce = mxor(mnonce,cnonce);
    salt   = Buffer.from(salt,"hex");

    let iter = salt.reduce((v,c)=>c+31*v,1024) % 1024 + 1024;
    cstore.sid = sid;

    // saltpasswd clientkey and serverkey
    let saltpasswd = crypto.pbkdf2Sync(Buffer.from(passwd,"hex"),salt,iter,256,"sha256");

    let clientkey  = hmac(user, saltpasswd);
    let serverkey  = hmac(sid, saltpasswd);
    cstore.serverkey = serverkey;

    // sign authmessage 
    let authmsg = cstore.cnonce + cstore.snonce + cstore.user; // sign message 
    let signkey = hmac(Buffer.from(clientkey,"hex"));
    let csign   = hmac(authmsg,Buffer.from(signkey,"hex"));
    let cproof  = mxor(signkey,csign);

    // return to server
    return { cproof, user };
}

const s2 = (req)=>{
    let {cproof, user} = req;
    let uinfo   = sstore[user];
    let signkey = uinfo.storekey.slice(8);

    // check server snonce 
    let authmsg = uinfo.cnonce + uinfo.snonce + user;
    let csign    = hmac(authmsg,Buffer.from(signkey,"hex"));
    let storekey = mxor(mxor(cproof, csign), signkey); // should be clientkey store
    
    if (Buffer.from(storekey,"hex").reduce((v,c)=>v+c) == 0) {
        authmsg = uinfo.snonce + uinfo.cnonce + sstore.sid;
        let ssign  = hmac(authmsg, Buffer.from(uinfo.serverkey,"hex"));
        let sproof = mxor(uinfo.serverkey,ssign);

        return { result: true, sproof };
    } else {
        return { result: false }
    }
}

// client final check 
const cfinal = (res)=>{
    if (res.result) {
        let authmsg = cstore.snonce + cstore.cnonce + cstore.sid;
        let ssign   = hmac(authmsg,Buffer.from(cstore.serverkey,"hex"));
        let sresult = mxor(mxor(res.sproof,ssign),cstore.serverkey);

        if (!Buffer.from(sresult,"hex").some(v=>v>0)) {
            console.log("Auth OK");
        } else {
            console.log("Auth False - Server Verify");
        }
    } else {
        console.log("Auth False");
    }
}

const ttest = ()=>{
    console.log("-----------SCRAM TEST Begin -------------");

    console.log("-----------Auth Register -------------");
    let uinfo = { 
        user   : "yanjh", 
        passwd : "password"
    }

    let rreg = reg(uinfo);

    console.log("register:", rreg);

    console.log("-----------SCRAM Client 1 -------------");
    let c1submit = c1(uinfo);
    
    console.log("request1:", JSON.stringify(c1submit));
    
    console.log("-----------SCRAM Server 1 -------------");
    let s1resp =  s1(c1submit);

    console.log("response:", JSON.stringify(s1resp));

    console.log("-----------SCRAM Client 2 -------------");
    
    let c2submit = c2( s1resp );
    console.log("request2:", JSON.stringify(c2submit));

    console.log("-----------SCRAM Server 2 -------------");

    let s2resp =  s2(c2submit);

    console.log("response2:", JSON.stringify(s2resp));

    cfinal(s2resp);

}

ttest();


