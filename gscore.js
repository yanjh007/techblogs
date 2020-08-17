const
MegaHash = require("megahash"),
mhash = new MegaHash(),
pdb   = require("../lib/db_pos3")(),
// { handle_req, handle_result } = require('./index'),
_this      =  this;

// report interface
exports.mname = __filename.slice(__dirname.length+1).split(".")[0];

const TB_SCORE = "gk_score_2019";
exports.initData = async ()=>{
    let qstr = `select hashid, hscore::json score from ${TB_SCORE} `;
    // qparam = [eparam.q];

    let irow = 0;
    let tstart = Date.now();
    const cursor = await pdb.cursor(qstr);
      
    let rows = await cursor.readAsync(100);
    while (rows.length) { // do something with rows
      irow += rows.length;
      rows.map(v=>{
        mhash.set( v.hashid, v.score );
      });
      rows = await cursor.readAsync(100);
    }

    cursor.close();
    console.log(`${irow} Rows Load Done in ${(Date.now() - tstart)} ms`);
}

// convert get base 64 param to json
exports.b64_object = (gparam) => {
    let rr = {}
    try { // recover base64 string e as {
        if (!gparam || gparam.length == 0 || !gparam.startsWith("e")) return rr;

        gparam = gparam.split("-").join('+').split("_").join('/'); // convert to base64url
        gparam = Buffer.from(gparam,"base64").toString();

        // parse json
        rr = JSON.parse(gparam);
    } catch (err) {
        console.log("param error",err.message);
    } 
    return rr;
}

exports.get = async (eparam,f_cb)=>{
    let rr,qr,qstr,qparam,lparam,
    action  = eparam.action;

    // not default module
    qparam = _this.b64_object(eparam.qparam);

    switch(action) {
        case "query": // zone list with schools
            rr = {}
            // qstr = `select yw,sx,wy,zh,zf,ls_hx,dl_sw,zz_wl 
            // from gk_score where ksh = $1 and kh = $2 and xm = $3 limit 1 `;
            // qparam = eparam.q.split(",");
            qstr = `select hashid, hscore::json from gk_score_2019 where hashid = $1 limit 1 `;
            qparam = [eparam.q];
            
            qr = await pdb.query(qstr,qparam);
            if (qr && qr.length > 0) {
                qr = qr[0];
                rdb.set(eparam.q, qr, (err)=>{
                    if (err) console.log("Redis saved Error",err);
                });
                f_cb({ R:c.V_RESULT_OK, C: qr });
            } else {
                f_cb({ R:204, C: "Not Found" });
            }
            return ;
        break;
        case "query2": // zone list with schools
            rr = mhash.get(qparam.q);
            if (rr) {
                f_cb({ R:200, C: { hashid: qparam.q, scores: rr }});
            } else {
                f_cb({ R:204, C: "Not Found" });
            }
            return ;
        break;
        default: f_cb({ R:500, C:"Param Error" });
    }
}

// set module router
exports.setRoute = (app,path='')=>{
    app
    .get(`${path}/${_this.mname}/:action/:qparam`,(req,rep) => {
        _this.get(req.params, r => rep.send(r));        
    });

    // init data
    _this.initData();
}
