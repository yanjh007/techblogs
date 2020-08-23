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
    credReq.challenge = base64url.decode(credReq.challenge);
    credReq.user.id   = base64url.decode(credReq.user.id);

    return credReq
}

/**
 * Decodes arrayBuffer required fields.
 */
export function decodeAssert(getAssert) {
    getAssert.challenge = base64url.decode(getAssert.challenge);
    
    for(let allowCred of getAssert.allowCredentials) {
        allowCred.id = base64url.decode(allowCred.id);
    }

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