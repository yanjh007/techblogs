const 
_chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
_lookup = _chars.split('').reduce((c,v,i)=>{
    c[v.charCodeAt(0)] = i 
    return c
}, new Int8Array(256))

const base64url = {
    encode: function(arraybuffer) {
        let  
        str = '', 
        bytes = new Uint8Array(arraybuffer),
        len = bytes.length

        for (let i = 0; i < len; i+=3) {
            str += _chars[bytes[i] >> 2];
            str += _chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
            str += _chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
            str += _chars[bytes[i + 2] & 63];
        }

        if ((len % 3) === 2) {
            return str.substring(0, str.length - 1);
        } else if (len % 3 === 1) {
            return str.substring(0, str.length - 2);
        } else {
            return str;
        }
    },

    decode: function(bstring) {
        let encoded1, encoded2, encoded3, encoded4,
        p = 0,
        bufferLength = bstring.length * 0.75,
        bytes = new Uint8Array(bufferLength)

        for (let i = 0,l = bstring.length; i < l; i+=4) {
            encoded1 = _lookup[bstring.charCodeAt(i)];
            encoded2 = _lookup[bstring.charCodeAt(i+1)];
            encoded3 = _lookup[bstring.charCodeAt(i+2)];
            encoded4 = _lookup[bstring.charCodeAt(i+3)];

            bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
            bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
            bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
        }

        return bytes.buffer
    }
}

/**
 * Decodes arrayBuffer required fields.
 */
export function decodeCred(credReq){
    credReq.challenge = base64url.decode(credReq.challenge)
    credReq.user.id   = base64url.decode(credReq.user.id)

    return credReq
}

/**
 * Decodes arrayBuffer required fields.
 */
export function decodeAssert(getAssert) {
    getAssert.challenge = base64url.decode(getAssert.challenge)
    getAssert.allowCredentials.map( v=> { v.id = base64url.decode(v.id)})

    return getAssert
}

/**
 * Converts PublicKeyCredential into serialised JSON
 * @param  {Object} pubKeyCred
 * @return {Object}            - JSON encoded publicKeyCredential
 */
export function packPubkey(pubKeyCred){
    if( pubKeyCred instanceof Array) {
        return pubKeyCred.map(v => { return packPubkey(v) } )
    } else if( pubKeyCred instanceof ArrayBuffer) {
        return base64url.encode(pubKeyCred)
    } else if( pubKeyCred instanceof Object) {
        let obj = {}
        for (let key in pubKeyCred) {
            obj[key] = packPubkey(pubKeyCred[key])
        }
        return obj
    } else {
        return pubKeyCred
    }
}

const WAUTH_KEY = "UL_WAUTH_KEY"
export function getWinfo() {
    let kdata = localStorage.getItem(WAUTH_KEY)
    return kdata ? JSON.parse(kdata) : null
}

export function setWinfo(kdata) {
    localStorage.setItem(WAUTH_KEY, JSON.stringify(kdata));
}

const DHEADER = {
    'Content-Type': 'application/json;charset=UTF-8',
    'Access-Control-Allow-Origin': '*'
}

const doPost = (wurl,pdata)=>{
    return new Promise((rv, rj) => {
        let isTimeOut = false
        const timeout = setTimeout(() => {
          isTimeOut = true       
          rj(new Error("网络请求超时"))
        }, 5000)
    
        let options = {
            method: 'POST',
            headers: DHEADER,
            body: JSON.stringify(pdata)
        }

        fetch(wurl, options)
          .then(res => {
            clearTimeout(timeout)
    
            // not ok 
            if (!res.ok) { throw Error(res.statusText) }

            return res.json()
          })
          .then(res => {
            // data error
            if (!res.R) { // empty or format error
                throw Error('500 - 未知错误')
            } else if ( 2 != (0 | res.R/100 )) { 
                throw Error(res.C || (res.R+' - 未知错误')) 
            } else {
                rv(res.C)
            }
          })
          .catch(err => {
            console.log("FetchError: " + err.message)
    
            // timeout already reject
            if (!isTimeOut) rj(err)
          })
    })
}


// set wauth url by caller 
const 
PATH_REG    = "/register",
PATH_AUTH   = "/login",
PATH_INFO   = "/uinfo",
PATH_UNBIND = "/unbind"

export function wauthRegister(wurl,rdata) {
    let sign,
    login = rdata.login,
    wrurl = wurl+PATH_REG

    return doPost(wrurl,rdata)
    .then(res => {
      let publicKey = decodeCred(res.cred)
      sign  = res.sign
      return navigator.credentials.create({ publicKey })
    })
    .then(kdata =>{
      let credRes = packPubkey(kdata)
      return doPost(wrurl, {...credRes, login, sign, phase: 2})
    })
}

export function wauthAuth(wurl,rdata) {
    let sign,
    login = rdata.login,
    waurl = wurl+PATH_AUTH

    return doPost(waurl,rdata)
    .then(res => {
        let publicKey = decodeAssert(res.assert);
        sign  = res.sign
        return navigator.credentials.get({ publicKey })
    })
    .then(kdata =>{
        let assertRes = packPubkey(kdata)
        return doPost(waurl, {...assertRes, login, sign, phase:2})
    })

}

// wauth unbind
export function wauthUnbind(wurl,rdata) {
    return doPost(wurl+PATH_UNBIND,rdata)
}

// wauth info
export function wauthInfo(wurl,rdata) {
    return doPost(wurl+PATH_INFO,rdata)
}