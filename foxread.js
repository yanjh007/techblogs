const 
crypto = require('crypto'),
{ DBFFile } = require('dbffile'),
FILE_SCORE  = './spcjk.dbf',
TB_SCORE    = 'gk_score_2020';

require("./lib/db_pos2")({
    secret: 'uldatA~9102',
    connectionString: "F259yJaYT5joevkAqq+8Kg.QVI9cj3WfJV6fBIh8KHfRQ.s5bLRTrCLYHDWbxWtHODkI6ZDn2uz77dcg4+tkfLhJilfVb+Q6qhqeqdBq85JX/nb9v5FYoKQzgglPPgfnEuKA" 
});

async function testRead() {
    let dbf = await DBFFile.open(FILE_SCORE,{ encoding: 'GBK' });
    console.log(`DBF file contains ${dbf.recordCount} records.`);
    console.log(`Field names: ${dbf.fields.map(f => f.name).join(', ')}`);
    let records = await dbf.readRecords(10);
    records.map(v=>{
        console.log(v.XM);
    })
}

async function dataRead () {
    const pdb = require("./lib/db_pos2")();

    let qr = await pdb.query("select count(1) scount from gk_score_2020");
    console.log("DB Record:",qr[0].scount);

    let row,sha1,hid;
    
    let dbf = await DBFFile.open(FILE_SCORE ,{ encoding: 'GBK' });
    console.log(`DBF file contains ${dbf.recordCount} records.`);
    console.log(`Field names: ${dbf.fields.map(f => f.name).join(', ')}`);
    let records = await dbf.readRecords(dbf.recordCount);  //dbf.recordCount
    
    let tstart = Date.now();

    let estr1 = ` insert into ${TB_SCORE} (hashid,hscore) values `;
    let estr2 = ` on conflict (hashid) DO UPDATE set hscore = excluded.hscore returning *  `;

    let k,i,n, ibatch = 1000, sparams = [],lparam = [];

    for (n=1; n<ibatch; n+=2) sparams.push(`($${n},$${n+1})`);
    let estr = estr1 + sparams.join(",") + estr2;

    sparams = [];
    for(n=1, i=0, l=records.length; i<l; i++,n+=2) {
        row = records[i];
        if (n >= ibatch ) { // batch excute
            await pdb.query(estr,lparam);
            console.log("R",i+1,row.XM);
            
            n = 1;
            lparam  = [];
        } else if ( i >= (l-1)) { // last batch n number
            sparams = [];
            for (k=1; k<n; k+=2) sparams.push(`($${k},$${k+1})`);
            estr = estr1 + sparams.join(",") + estr2;
            await pdb.query(estr,lparam);
            console.log("Finish",l,row.XM);
        }
        
        // add data 
        hid = crypto.createHash('sha1').update(row.KSH + row.XM).digest("hex");
        hscore = {
            "13": row.YW,
            "14": row.SX,
            "40": row.WY,
            "93": row.ZH,
            "98": row.ZF
        }

        lparam.push(hid,hscore);
        // sparams.push(`($${k},$${k+1})`);
        // sparams.push(`('${hid}','${JSON.stringify(hscore)}')`);
    }

    console.log("Record:",records.length,",Time:", 0|(Date.now()-tstart)/1000);
}

setTimeout(dataRead,3000);





