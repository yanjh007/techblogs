const
MegaHash = require("megahash"),
mhash = new MegaHash(),
pdb   = require("../lib/db_pos3")(),
{ b64_object } = require('./index'),
_this      =  this;

// report interface
exports.mname = __filename.slice(__dirname.length+1).slice(0,-3); // trim .js

const TB_SCORE = "gk_score_2019";
exports.initData = async ()=>{
    let 
    irow = 0 ,
    tstart = Date.now(),
    qstr = `select hashid, hscore::json score from ${TB_SCORE} `;

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

exports.get = async (eparam,f_cb)=>{
    let rr,qr,qstr,qparam,lparam,
    action  = eparam.action;

    qparam = b64_object(eparam.qparam);

    switch(action) {
        case "query": // query from database
            rr = {}
            // qstr = `select yw,sx,wy,zh,zf,ls_hx,dl_sw,zz_wl gk_score where ksh = $1 and kh = $2 and xm = $3 limit 1 `;
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
        case "query2": // query from megaHash
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
