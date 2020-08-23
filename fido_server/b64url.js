// Version 200823 By John Yan ULSC

const padString = (input)=> {
    const 
    segmentLength = 4,
    stringLength = input.length,
    diff = stringLength % segmentLength;

    if (!diff) return input;
    
    let position = stringLength;
    let padLength = segmentLength - diff;
    let paddedStringLength = stringLength + padLength;

    let buffer = Buffer.alloc(paddedStringLength);
    buffer.write(input);
    while (padLength--) buffer.write("=", position++);

    return buffer.toString();
}

const toBase64 =(base64url)=> {
    base64url = base64url.toString();
    return padString(base64url)
        .replace(/\-/g, "+")
        .replace(/_/g, "/");
}

const fromBase64 = (base64)=> {
    return base64
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

const toBuffer = (base64url)=> {
    return Buffer.from(toBase64(base64url), "base64");
}

// encode buffer ,string or object
const encode = (input, encoding)=> {
    if (encoding === void 0) { encoding = "utf8"; }

    if (Buffer.isBuffer(input)) {
        return fromBase64(input.toString("base64"));
    } else if (typeof input === "object") {
        input = JSON.stringify(input);
    } 
    return fromBase64(Buffer.from(input, encoding).toString("base64"));
};

// decode from buffer to encode string
const decode = (base64url, encoding) => {
    if (encoding === void 0) { encoding = "utf8"; }
    return Buffer.from(toBase64(base64url), "base64").toString(encoding);
}

// decode to object
const decodeObj = (base64url) => {
    let sobject = decode(base64url);
    try {
        return JSON.parse(sobject);
    } catch (error) {
        console.log("base64 decode error");
        return {};
    }
}

// exports methods
module.exports = {
    encode, decode, decodeObj, toBuffer
}
// const base64url = {
// }

// exports.default = base64url;