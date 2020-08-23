const
_this = this,
crypto    = require('crypto'),
cbor      = require('cbor'),
iso_3166_1 = require('iso-3166-1'),
{ Certificate } = require('@fidm/x509'),
pdb   = require("../lib/db_pos3")(),
b64url = require('../lib/b64url'),
msec   = require('../secret'),
{ r_ok, r_err, handle_req}   = require("./index"),
{ getLoginToken }   = require("./auth"),
cfg = require("../conf"),
TB_AUTH      = "cm_wauth",
TB_USER      = "cm_user";

const ERR_MSG = {
    FORMAT: '客户端响应内容或格式错误!',
    LOGIN : '登录信息错误或缺失',
    UINFO : '未找到有效用户或认证信息',
    RESFORMAT  :'客户端响应内容或格式错误!',
    CHALLENGE  : '挑战或来源信息不匹配!',
    VERIFY     :  '客户端响应验证失败!'
}

// token time out minute
const getOne = async (login,gtype=0)=>{
    let qstr = `select authinfo,status from ${TB_AUTH} where login = $1 limit 1`;
    let qr = await pdb.query(qstr,[login]);
    if (gtype ==0) {
        return (qr && qr.length>0) ? qr[0].authinfo : null;
    } else {
        return (qr && qr.length>0) ? {...qr[0], login } : { status : -1, login };
    }
}

const setOne = async (login,wauth,status)=>{
    let qstr,qr,qparam;
    if (status == -1) {
        qstr = `delete from ${TB_AUTH}  where login = $1 returning *` ;
        qparam = [login];
    } else {
        qstr = `insert into ${TB_AUTH} (login,authinfo,status) values ($1,$2,$3) on conflict (login) 
        do update set (authinfo,status) = (excluded.authinfo, excluded.status)  returning *`;
        qparam = [login,wauth,status];
    }

    qr = await pdb.query(qstr,qparam);
    return (qr && qr.length>0) ? qr[0].authinfo : null;
}

exports.post = async (eparam,f_cb) =>{
    let ainfo, qparam, rlist,
    action  = eparam._action; 
    
    let 
    login = eparam.login,
    rr    = r_ok();

    switch (action) {
        case "uinfo":
            ainfo = await getOne(login,1);

            if (!ainfo) {
                rr.C = { status: -1 }
            } else {
                rr.C = { status: ainfo.status };
            }

        break;
        case "register":
            // check exist 
            ainfo = await getOne(login);
            if (ainfo && ainfo.registered) {
                return f_cb(r_err( `用户 ${login} 已经存在并注册`));
            };

            ainfo  = {
                id   : crypto.randomBytes(16).toString("hex"),
                name : eparam.name,
                registered: false, // set true after response ok
                authenticators: []
            };

            // new or reset 
            await setOne(login,ainfo,0);

            // user format must be 
            let challengeMakeCred = genCredRequest({ 
                id: ainfo.id,
                name: login, 
                displayName: eparam.name, 
            }, cfg.WAUTH.party);

            rr = r_ok({
                cred : challengeMakeCred,
                sign : msec.crcSign(challengeMakeCred.challenge)
            });
        break;
        case "login":
            if(!login) {
                return f_cb(r_err( '缺少登录信息！'));
            }
    
            ainfo = await getOne(login);
            if (!(ainfo && ainfo.registered)) {
                return f_cb(r_err(`用户 ${login} 不存在或未激活!`));
            }
    
            // response assertion by get ator
            let wassert  = genAssertion(ainfo.authenticators);
            rr = r_ok({
                assert: wassert,
                sign: msec.crcSign(wassert.challenge),
                login: login
            });
        break;
        case "response":
            // webauthn Content from base64 url 
            let result,
            waResponse = eparam.response,
            cdata = b64url.decodeObj(waResponse.clientDataJSON) ;

            // check challenge and origin
            if(cdata.origin !== cfg.WAUTH.origin || !msec.crcSign(cdata.challenge,eparam.sign)) {
                return f_cb(r_err(ERR_MSG.CHALLENGE));
            }

            ainfo = await getOne(login);

            rr = r_ok();
            // for register
            if(waResponse.attestationObject !== undefined) { 
                /* This is create cred register OK */
                result = veriAttestRes(waResponse);

                if(result.verified) { // ok and save 
                    // add authinfo to list
                    ainfo.authenticators.push(result.authrInfo);
                    ainfo.registered = true;

                    // save uinfo
                    await setOne(login,ainfo,2);
                    rr.C = {
                        login: login,
                        name : ainfo.name,
                    }
                } else {
                    rr = r_err(ERR_MSG.VERIFY);
                }
                
            // for login
            } else if (waResponse.authenticatorData !== undefined) { 
                result = veriAssertRes(eparam.id, waResponse, ainfo.authenticators);

                if (result && result.verified) {
                    // verify ok get user token
                    let ut = await getLoginToken({ login, ipaddr: eparam._ipaddr });
                    if (ut) {
                        rr.C = ut;
                    } else {
                        rr = r_err(ERR_MSG.UINFO);
                    }
                } else {
                    rr = r_err(ERR_MSG.VERIFY);
                }
            // unknow action 
            } else {
                rr = r_err(ERR_MSG.RESFORMAT);
            }
        break;
        case "unbind":
            ainfo = await getOne(login);
            if (ainfo) {
                await setOne(login,null,-1);
            } else {
                rr = r_err(`用户 ${login} 不存在!`);
            }
        break;
        default: rr = r_err( ERR_MSG.FORMAT);
    }
    f_cb(rr);
}

exports.get = async (eparam,f_cb)=>{
    let rr,qr,qstr,qparam,lparam,cregion,
    action  = eparam._action;

    f_cb(r_ok());
}

exports.setRoute = (app,path)=>{
    app
    .post(`${path}/:action`, (req,rep)=>{
        _this.post(handle_req(req), r=> rep.send(r));
    }) 
    .get(`${path}/:action/:aparam`, (req,rep)=>{
        _this.get(handle_req(req), r => rep.send(r)); 
    });
}

/**
 * U2F with webauthn 
 * U2F Presence constant
 */
let U2F_USER_PRESENTED = 0x01;

/**
 * Takes signature, data and PEM public key and tries to verify signature
 * @param  {Buffer} signature
 * @param  {Buffer} data
 * @param  {String} publicKey - PEM encoded public key
 * @return {Boolean}
 */
const verifySignature = (signature, data, publicKey) => {
    return crypto.createVerify('SHA256').update(data).verify(publicKey, signature);
}

/**
 * Returns SHA-256 digest of the given data.
 * @param  {Buffer} data - data to hash
 * @return {Buffer}      - the hash
 */
const hash = (data) => {
    return crypto.createHash('SHA256').update(data).digest();
}

/**
 * Generates makeCredentials request
 * @param  {String} username       - username
 * @param  {String} displayName    - user's personal display name
 * @param  {String} id             - user's base64url encoded id
 * @return {MakePublicKeyCredentialOptions} - server encoded make credentials request
 */
const genCredRequest = (user, rpname) => {
    return {
        user,
        rp: {
            name: rpname
        },
        challenge: crypto.randomBytes(16).toString("hex"),
        status: 'ok',
        attestation: 'direct',
        pubKeyCredParams: [
            { type: "public-key", alg: -7 } // "ES256" IANA COSE Algorithms registry
        ]
    }
}

/**
 * Generates getAssertion request
 * @param  {Array} authenticators              - list of registered authenticators
 * @return {PublicKeyCredentialRequestOptions} - server encoded get assertion request
 */
const genAssertion = (authenticators) => {
    let allowCredentials = authenticators.map(v=>{
        return {
            id: v.credID,
            type: 'public-key',
            transports: ['usb', 'nfc', 'ble']
        }
    });

    return {
        challenge: crypto.randomBytes(16).toString("hex"),
        allowCredentials: allowCredentials,
        status : 'ok'
    }
}

/**
 * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
 * @param  {Buffer} COSEPublicKey - COSE encoded public key
 * @return {Buffer}               - RAW PKCS encoded public key
 */
let COSEECDHAtoPKCS = (COSEPublicKey) => {
    /* 
       +------+-------+-------+---------+----------------------------------+
       | name | key   | label | type    | description                      |
       |      | type  |       |         |                                  |
       +------+-------+-------+---------+----------------------------------+
       | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
       |      |       |       | tstr    | the COSE Curves registry         |
       |      |       |       |         |                                  |
       | x    | 2     | -2    | bstr    | X Coordinate                     |
       |      |       |       |         |                                  |
       | y    | 2     | -3    | bstr /  | Y Coordinate                     |
       |      |       |       | bool    |                                  |
       |      |       |       |         |                                  |
       | d    | 2     | -4    | bstr    | Private key                      |
       +------+-------+-------+---------+----------------------------------+
    */

    let coseStruct = cbor.decodeAllSync(COSEPublicKey)[0];
    let tag = Buffer.from([0x04]);
    let x   = coseStruct.get(-2);
    let y   = coseStruct.get(-3);

    return Buffer.concat([tag, x, y])
}

/**
 * Convert binary certificate or public key to an OpenSSL-compatible PEM text format.
 * @param  {Buffer} buffer - Cert or PubKey buffer
 * @return {String}             - PEM
 */
let ASN1toPEM = (pkBuffer) => {
    if (!Buffer.isBuffer(pkBuffer))
        throw new Error("ASN1toPEM: pkBuffer must be Buffer.")

    let type;
    if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
        /*
            If needed, we encode rawpublic key to ASN structure, adding metadata:
            SEQUENCE {
              SEQUENCE {
                 OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
                 OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
              }
              BITSTRING <raw public key>
            }
            Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
        */
        
        pkBuffer = Buffer.concat([
            new Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"),
            pkBuffer
        ]);

        type = 'PUBLIC KEY';
    } else {
        type = 'CERTIFICATE';
    }

    let b64cert = pkBuffer.toString('base64');

    let PEMKey = '';
    for(let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
        let start = 64 * i;
        PEMKey += b64cert.substr(start, 64) + '\n';
    }
    PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;
    
    return PEMKey
}

/**
 * Parses authenticatorData buffer.
 * @param  {Buffer} buffer - authenticatorData buffer
 * @return {Object}        - parsed authenticatorData struct
 */
let parseAuthData = (buffer) => {
    let rpIdHash      = buffer.slice(0, 32);          buffer = buffer.slice(32);
    let flagsBuf      = buffer.slice(0, 1);           buffer = buffer.slice(1);
    let flags         = flagsBuf[0];
    let counterBuf    = buffer.slice(0, 4);           buffer = buffer.slice(4);
    let counter       = counterBuf.readUInt32BE(0);
    let aaguid        = buffer.slice(0, 16);          buffer = buffer.slice(16);
    let credIDLenBuf  = buffer.slice(0, 2);           buffer = buffer.slice(2);
    let credIDLen     = credIDLenBuf.readUInt16BE(0);
    let credID        = buffer.slice(0, credIDLen);   buffer = buffer.slice(credIDLen);
    let COSEPublicKey = buffer;

    return {rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey}
}


// verifiy attest infomation
let veriAttestRes = (waResponse) => {
    let attestationBuffer = b64url.toBuffer(waResponse.attestationObject);
    let ctapMakeCredResp  = cbor.decodeAllSync(attestationBuffer)[0];

    let response = { verified : false};

    // format check 
    if(!(ctapMakeCredResp.fmt === 'packed' && ctapMakeCredResp.attStmt.hasOwnProperty('x5c')) && ctapMakeCredResp.fmt !== 'fido-u2f')
        return response;

    let authObj = parseAuthData(ctapMakeCredResp.authData);

    if(!(authObj.flags & U2F_USER_PRESENTED))
        throw new Error('User was NOT presented durring authentication!');

    let clientDataHash  = hash(b64url.toBuffer(waResponse.clientDataJSON))
    let publicKey       = COSEECDHAtoPKCS(authObj.COSEPublicKey)

    let PEMCertificate = ASN1toPEM(ctapMakeCredResp.attStmt.x5c[0]);
    let signature      = ctapMakeCredResp.attStmt.sig;

    if(ctapMakeCredResp.fmt === 'fido-u2f') {
        let reservedByte    = Buffer.from([0x00]);
        let signatureBase   = Buffer.concat([reservedByte, authObj.rpIdHash, clientDataHash, authObj.credID, publicKey]);

        response.verified = verifySignature(signature, signatureBase, PEMCertificate)

    } else  {
        let signatureBase   = Buffer.concat([ctapMakeCredResp.authData, clientDataHash]);

        let pem = Certificate.fromPEM(PEMCertificate);

        // Getting requirements from https://www.w3.org/TR/webauthn/#packed-attestation
        let aaguid_ext = pem.getExtension('1.3.6.1.4.1.45724.1.1.4')

        response.verified = // Verify that sig is a valid signature over the concatenation of authenticatorData
            // and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.
            verifySignature(signature, signatureBase, PEMCertificate) &&
            // version must be 3 (which is indicated by an ASN.1 INTEGER with value 2)
            pem.version == 3 &&
            // ISO 3166 valid country
            typeof iso_3166_1.whereAlpha2(pem.subject.countryName) !== 'undefined' &&
            // Legal name of the Authenticator vendor (UTF8String)
            pem.subject.organizationName &&
            // Literal string “Authenticator Attestation” (UTF8String)
            pem.subject.organizationalUnitName === 'Authenticator Attestation' &&
            // A UTF8String of the vendor’s choosing
            pem.subject.commonName &&
            // The Basic Constraints extension MUST have the CA component set to false
            !pem.extensions.isCA &&
            // If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
            // verify that the value of this extension matches the aaguid in authenticatorData.
            // The extension MUST NOT be marked as critical.
            (aaguid_ext != null ?
                (authObj.hasOwnProperty('aaguid') ?
                !aaguid_ext.critical && aaguid_ext.value.slice(2).equals(authObj.aaguid) : false)
                : true);
    }

    if(response.verified) {
        response.authrInfo = {
            fmt: 'fido-u2f',
            publicKey: b64url.encode(publicKey),
            counter: authObj.counter,
            credID: b64url.encode(authObj.credID)
        }
    }

    return response
}

/**
 * Takes an array of registered authenticators and find one specified by credID
 * @param  {String} credID        - base64url encoded credential
 * @param  {Array} authenticators - list of authenticators
 * @return {Object}               - found authenticator
 */
let findAuthr = (credID, authenticators) => {
    for(let authr of authenticators) {
        if(authr.credID === credID)
            return authr
    }

    throw new Error(`Unknown authenticator with credID ${credID}!`)
}

/**
 * Parses AuthenticatorData from GetAssertion response
 * @param  {Buffer} buffer - Auth data buffer
 * @return {Object}        - parsed authenticatorData struct
 */
let parseGetAssertAuthData = (buffer) => {
    let rpIdHash      = buffer.slice(0, 32);          buffer = buffer.slice(32);
    let flagsBuf      = buffer.slice(0, 1);           buffer = buffer.slice(1);
    let flags         = flagsBuf[0];
    let counterBuf    = buffer.slice(0, 4);           buffer = buffer.slice(4);
    let counter       = counterBuf.readUInt32BE(0);

    return {rpIdHash, flagsBuf, flags, counter, counterBuf}
}

// verify assert response
let veriAssertRes = (rid, waResponse, authenticators) => {
    let authr = findAuthr(rid, authenticators);
    let authenticatorData = b64url.toBuffer(waResponse.authenticatorData);

    let response = {'verified': false};
    if(authr.fmt === 'fido-u2f') {
        let authObj  = parseGetAssertAuthData(authenticatorData);

        if(!(authObj.flags & U2F_USER_PRESENTED))
            throw new Error('User was NOT presented durring authentication!');

        let clientDataHash   = hash(b64url.toBuffer(waResponse.clientDataJSON))
        let signatureBase    = Buffer.concat([authObj.rpIdHash, authObj.flagsBuf, authObj.counterBuf, clientDataHash]);

        let publicKey = ASN1toPEM(b64url.toBuffer(authr.publicKey));
        let signature = b64url.toBuffer(waResponse.signature);

        response.verified = verifySignature(signature, signatureBase, publicKey)

        if(response.verified) {
            if(response.counter <= authr.counter)
                throw new Error('Authr counter did not increase!');

            authr.counter = authObj.counter
        }
    }

    return response
}
