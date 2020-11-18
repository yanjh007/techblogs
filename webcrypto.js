// John Yan ULCS Ver.20201118
// crypto lib use webcrypto api 

class WebCrypto {
    constructor(name = "WebCrypto") {
        this.name = name
        this.encoder = new TextEncoder()

        const 
        CURVE = "P-384",  //can be "P-256", "P-384", or "P-521"
        PKEY_EXPORT = "spki",
        VKEY_EXPORT = "pkcs8",
        ALGO_LENGTH =  256,
        ALGO_HASH  = "SHA-256",
        ALGO_KDF   = "PBKDF2",
        ALGO_DSA   = { name: "ECDSA", namedCurve: CURVE },
        ALGO_ECDH  = { name: "ECDH",  namedCurve: CURVE },
        ALGO_SIGN  = { name: "ECDSA", hash: { name: ALGO_HASH }},
        ALGO_AES   = { name: "AES-GCM", length: ALGO_LENGTH }

        this.C = {
            CURVE, PKEY_EXPORT, VKEY_EXPORT, ALGO_LENGTH, ALGO_KDF, 
            ALGO_HASH, ALGO_DSA, ALGO_ECDH, ALGO_SIGN, ALGO_AES
        }
    }

    encode(data) {
        if (typeof data === "object") data = JSON.stringify(data)
        return this.encoder.encode(data)
    }

    // convert to base64 or reverse
    b64Str(text) {
        return !text 
            ? null
            : (text.indexOf('+') >-1 || text.indexOf('/') >-1 || text.indexOf('=') >-1 )
            ? text.replace(/\//g,'_').replace(/\+/g,'-').replace(/\=/g,'')
            : (text.indexOf('_') > -1 || text.indexOf('-') > -1)
            ? text.replace(/_/g,'/').replace(/-/g,'+')
            : text 
    }

    // array to b64url default
    toB64(data, toUrl = true) {
        if (typeof data === "string") {
            data = Array.from(new TextEncoder().encode(data))
        } else { // or array 
            data = Array.from(new Uint8Array(data))
        }
        
        const dstr = btoa(data.map(b => String.fromCharCode(b)).join(''))
        return toUrl ? this.b64Str(dstr) : dstr                                    
    }

    // uint8 array to hex string
    toHex(data, dtype = "array") {
        if (dtype == "array") { // from uint8array
            return new Uint8Array(data).reduce((v,x)=> v + x.toString(16).padStart(2,"0"),"")
        } else if (dtype == "base64") { // from base64 string
            return this.toHex(this.b64Array(data))
        } else if (dtype == "utf8") { // from utf9 encode
            return this.toHex(this.encode(data))
        } else {
            return null
        }
    }

    // b64 string to array
    b64Array(data) {
        data = data.replace(/\_/g,"/").replace(/\-/g,"+")
        return Uint8Array.from(atob(data), c => c.charCodeAt(0))
    }

    // hex string to array
    hexArray(data) {
        return Uint8Array.from(data.match(/.{1,2}/g).map(b => parseInt(b, 16)))
    }

    // Method
    async hash(data,key) {
        let 
        _this = this

        data = this.encode(data)

        if (key) { // hmac
            key = this.encode(key)
            return await crypto.subtle.importKey("raw", key,{ name: "HMAC", hash: { name: "SHA-256" }}, false, ["sign", "verify"]) // what this key can do
                .then( k1 => crypto.subtle.sign("HMAC", k1, data))
                .then( sign => this.toHex(sign))
                .catch(err=>{
                    console.log(err.message)
                    return null
                })
        } else {
            return crypto.subtle.digest( _this.C.ALGO_HASH, data)
                .then( sign => this.toHex(sign))
                .catch(err=>{
                    console.log(err.message)
                    return null
                })
        }
    }

    async hmac(data,key) {
        return this.hash(data,key)
    }

    async sign(data, cvkey) {
        let cKeys,
        _this = this,
        adata  = this.encode(data)
    
        return crypto.subtle
        .generateKey(_this.C.ALGO_DSA, true, ["sign"])
        .then( key=> {
            if (cvkey) {
                return crypto.subtle.importKey(_this.C.VKEY_EXPORT, b64Ary(cvkey), _this.C.ALGO_DSA, false, ["sign"] )
            } else {
                cKeys = key
                return cKeys.privateKey
            }
        })
        .then(vkey => crypto.subtle.sign(_this.C.ALGO_SIGN , vkey, adata ))
        .then(sign =>{
            let rsign = {
                sign : _this.toB64(sign)
            }
            if (cvkey) return rsign
    
            return crypto.subtle
                .exportKey( _this.C.PKEY_EXPORT, cKeys.publicKey)
                .then( pk=>{
                    rsign.pkey =  _this.toB64(pk)
                    return crypto.subtle.exportKey(_this.C.VKEY_EXPORT, cKeys.privateKey)
                })
                .then( vk=>{
                    rsign.vkey =  _this.toB64(vk)
                    return rsign
                })
        })
        .catch(err => {
            console.log(err)
            return null
        })
    }

    // ecdsa signature 
    async verify(data, sign, spkey ) {
        let 
        _this = this,
        km    = this.b64Array(spkey)

        sign  = this.b64Array(sign)
        data  = this.encode(data)

        return crypto.subtle
            .importKey( _this.C.PKEY_EXPORT, km , _this.C.ALGO_DSA, false, ["verify"] )
            .then(pkey=>crypto.subtle.verify( _this.C.ALGO_SIGN, pkey, sign, data ))
            .catch(err => {
                console.error(err)
                return false
            });
    }

    // ecdh method if not set client key, will generate key pair
    // use raw key type for nodejs crypto exchange 
    async ecdh(spkey,ckey) {
        let sKey, cKeys,
        _this  = this, 
        aspKey = this.b64Array(spkey)

        return crypto.subtle
            .importKey("raw", aspKey , _this.C.ALGO_ECDH, false, [] )
            .then(k1 => { // get server key object 
                sKey = k1
                if (ckey) { // import private key 
                    return crypto.subtle.importKey(_this.C.VKEY_EXPORT, b64Ary(ckey), _this.C.ALGO_ECDH, false, ["deriveKey", "deriveBits"] )
                } else { // genarate client keypair
                    return crypto.subtle
                        .generateKey(ALGO_ECDH, true, ["deriveKey", "deriveBits"]) //whether the key is extractable (i.e. can be used in exportKey)
                        .then( key=> {
                            cKeys = key
                            return cKeys.privateKey
                        })
                }
            })
            .then( vkey => crypto.subtle.deriveKey({ ..._this.C.ALGO_ECDH, public: sKey, }, vkey, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]))
            .then (eKey => crypto.subtle.exportKey( "raw", eKey))
            .then ( shareKey=>{
                let rkey = {
                    shareKey : _this.toHex(shareKey)
                }

                // only return result
                if (ckey) return rkey

                // export share key and key pair
                return crypto.subtle
                    .exportKey( "raw", cKeys.publicKey)
                    .then( pk=>{
                        rkey.pkey = _this.toB64(pk)
                        return crypto.subtle.exportKey( _this.C.VKEY_EXPORT, cKeys.privateKey)
                    })
                    .then( vk=>{
                        rkey.vkey = _this.toB64(vk) 
                        return rkey
                    })
            })
            .catch(err=>{
                console.log(err)
                return null
            })
    }

    // encrpt use aes Gcm
    async encrypt_gcm(ptext, passwd) {
        // salt iv and iter generate
        let 
        _this = this,
        salt  = crypto.getRandomValues(new Uint8Array(8)),  // get 96-bit random iv
        iv    = Uint8Array.from([...salt,...salt]), // two salt as iv
        iterations  = 800 + 0|Math.random()*400

        passwd = this.encode(passwd)
        ptext  = this.encode(ptext)
        
        let koption = { salt, iterations,
            name: this.C.ALGO_KDF,
            hash: this.C.ALGO_HASH
        }

        // password to key
        return crypto.subtle
            .importKey("raw",passwd, _this.C.ALGO_KDF, false, ["deriveBits", "deriveKey"])
            .then( km  => crypto.subtle.deriveKey(koption,km, _this.C.ALGO_AES, true,[ "encrypt", "decrypt" ]))
            .then( key => crypto.subtle.encrypt({ ..._this.C.ALGO_AES, iv }, key, ptext))
            .then( v=>[ _this.toB64(v), _this.toB64(salt), iterations ].join(".")) // return iv+ciphertext
            .catch( err=>{
                console.log(err)
                return null
            })
    }
}

// for test and use demo
async function wctest() {
    const signData = JSON.stringify({
		id: 301,
		name: "颜建华301"
	})

    setTimeout(async _=> {
		let wcrypto = new WebCrypto()

		const password = "password1234abcd"

		console.log("b64:",wcrypto.toB64(signData))
		
		let hash1 = await wcrypto.hash(signData)
		console.log("hash1:", hash1)

		let hash2 = await wcrypto.hmac(signData, password)
		console.log("hmac:", hash2)

		const cpkey2 = "BP_CZN3_2RXzHLxx16rH0YPKNDigg_ojbJrPJC1ADOBp-66WbnPUy4IOmwb-QVvPhczmk8pdA4P64xRxmh3LcB_CYHQXulezVSbU7Qtd3BU9Ml6yip9tVHFiwNbPWL8pfQ"
		const cvkey2 = "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDD5PS0O5M_dYVxoPmpuBQONVfY8u_tVZTF-huLl26ALVttwDvB5YTH62fRR6H_e3vKhZANiAAT_wmTd_9kV8xy8cdeqx9GDyjQ4oIP6I2yazyQtQAzgafuulm5z1MuCDpsG_kFbz4XM5pPKXQOD-uMUcZody3AfwmB0F7pXs1Um1O0LXdwVPTJesoqfbVRxYsDWz1i_KX0"

		const spkey2 = "BOprhzRyNBgh0Fno83GLC39E6Qj0V2PujPM9CONm0BrPkDf3SaY5aoNpZKDJwYjJzsmhjzUuZwjF82rdDySYdHhEhVGJwX5SE75m02xR2jlCugfvsMKspCQ94fTDO5uoAw=="

		// server public and client private key
		let r1 = await wcrypto.ecdh(spkey2)
        console.log("ecdh1 :", r1 )
        
		let r2 = await wcrypto.ecdh(spkey2,cvkey2)
		console.log("ecdh2 :", r2 )

		// server public and client private key
		let r3 = await wcrypto.encrypt_gcm(signData, password)
		console.log("gcm :", r3 )

		let sign = await wcrypto.sign(signData)
		console.log("signed1 :",{ ...sign, data: signData }, sign.sign.length )

		let vresult = false
		if (sign.pkey) {
			vresult = await wcrypto.verify(signData, sign.sign, sign.pkey)
		} else {
			vresult = await wcrypto.verify(signData, sign.sign, spkey)
		}
        console.log("verify1 :",vresult)
        

        const cvkey1 ="MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAei8DmLgheSCYXwmJrpgC0nIiAm3hyPlj82cIsOdrxKevzNbHgNgkMj0VbQ1nVkiqhZANiAATgIVTxDyWVb-fICDzPzSWm6frS4Kc04X054rf-pV7Ovpdf8o-dVqhc9ZnNgLjl7B4oZfxkVZpL1FuLQGvna1mVsi8fTfc2EqflzhQpFTD8rUpAicn-hN5xZ9bkBjopVOA"
        let sign2 = await wcrypto.sign(signData, cvkey1)
		console.log("signed2 :", sign2.sign, sign2.sign.length)
		
		const sign1 = "UBKTWmgKxd9OxUrBdR9DQNIKwT3K5Pl6684DtQn8EhT+fhPs56JqQnC4UvLJ/ScVz4yr39ef+yXjqYL+chM3v0+YLJuP9KgkxKdMop0mwT1RCrhrA8zyWO3qgDi8N0J3"
		const spkey1 = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEowtIEFmGHVM4v7GGEIxxVJKrmFf2GXx4cPQW_WJjxRjYM3fUROnxKG5vC3FYCioIvckl0V3wF8tcVXH6g4-4_zC04kLtSYGB7HeGuS-fRvQYn6HFz6lRA53HLOQMt-fQ"
		vresult = await wcrypto.verify(signData, sign1, spkey1)
		console.log("verify2 :",vresult)
	},500)
}