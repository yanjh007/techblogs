<template>
<div class="app-container">
  <el-tabs v-model="actTab">
    <el-tab-pane label="修改密码" name="tab1">
      <div style= "width:60%">
        <el-form ref="frmPasswd" label-width="100px" size="small" auto-complete="off" label-position="right"
            :model="curPasswd"
            :rules="pwdRules" 
            :inline-message='true'>
          <el-form-item label="旧密码" prop="old">
            <el-input type="password" v-model="curPasswd.old" autocomplete="off"></el-input>
          </el-form-item>
          <el-form-item label="新密码" prop="new">
            <el-input type="password" v-model="curPasswd.new" autocomplete="off"></el-input>
          </el-form-item>
          <el-form-item label="确认新密码" prop="new2">
            <el-input type="password" v-model="curPasswd.new2" autocomplete="off"></el-input>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" @click.prevent="doPasswd(11)">提交</el-button>
            <el-button @click.prevent="doPasswd(12)">重置</el-button>
          </el-form-item>
        </el-form>
      </div>
    </el-tab-pane>

    <el-tab-pane label="用户设置" name="tab2">
      <el-card class="box-card">
        <div slot="header" class="clearfix">
          <span>用户联系方式</span>
          <el-button style="float: right; padding: 3px 0" type="text" @click="doEdit(2)">设置</el-button>
        </div>
        <el-form ref="frmContact" label-width="100px">
          <el-row :gutter="8">
            <el-col :span="8">
              <el-form-item label="显示名称">
                <div class="col-content"> {{ ucontact.name }}   </div>
              </el-form-item>
            </el-col>

            <el-col :span="8">
              <el-form-item label="联系电话">
                <div class="col-content">  {{ ucontact.phone }} </div>
              </el-form-item>
            </el-col>

            <el-col :span="8">
              <el-form-item label="电邮/QQ">
                <div class="col-content">  {{ ucontact.email }} </div>
              </el-form-item>
            </el-col>
          </el-row >

          <el-row :gutter="8">
            <el-col :span="16">
              <el-form-item label="通信地址">
                <div class="col-content"> {{ ucontact.address }} </div>
              </el-form-item>
            </el-col>
          </el-row >
        </el-form>
      </el-card>
    </el-tab-pane>

    <el-tab-pane label="令牌登录设置" name="tab3">
      <el-card class="box-card">
        <div slot="header" class="clearfix">
          <span>登录令牌状态和设置</span>
        </div>
        <div style="margin: 10px 10px 10px 0; ">
          当前用户: {{ cuser.name }}<br><br>
          令牌状态: {{ ustatus }}
        </div>

        <div>
          <el-button v-if="ustatus < 1" type="primary" @click.prevent="doRegister()">注册</el-button>
          <el-button v-if="ustatus > 1" type="danger" @click.prevent="doUnbind()">解绑</el-button>
        </div>
      </el-card>
    </el-tab-pane>
  </el-tabs>

  <!-- org contact edit  -->
  <el-dialog :title="dlgOcontact.title" :visible.sync="dlgOcontact.show">
    <el-form ref="contactForm" :model="dlgOcontact.data" label-position="left" label-width="80px" style="width: 400px; margin-left:30px;">
      <el-form-item label="联系人">
        <el-input v-model="dlgOcontact.data.name"></el-input>
      </el-form-item>
      <el-form-item label="联系电话">
        <el-input v-model="dlgOcontact.data.phone"></el-input>
      </el-form-item>
      <el-form-item label="电邮/QQ">
        <el-input v-model="dlgOcontact.data.email"></el-input>
      </el-form-item>
      <el-form-item label="机构地址">
        <el-input v-model="dlgOcontact.data.address"></el-input>
      </el-form-item>
    </el-form>

    <div slot="footer" class="dialog-footer">
      <el-button @click="dlgOcontact.show = false ">取消</el-button>
      <el-button type="primary" @click="doEdit(41)">确定</el-button>
    </div>
  </el-dialog>

  <!-- user contact edit  -->
  <el-dialog :title="dlgUcontact.title" :visible.sync="dlgUcontact.show">
    <el-form ref="frmUcontact" :model="dlgUcontact.data" label-position="left" label-width="80px" style="width: 400px; margin-left:30px;">
      <el-form-item label="显示名">
        <el-input v-model="dlgUcontact.data.name"></el-input>
      </el-form-item>
      <el-form-item label="联系电话">
        <el-input v-model="dlgUcontact.data.phone"></el-input>
      </el-form-item>
      <el-form-item label="电邮/QQ">
        <el-input v-model="dlgUcontact.data.email"></el-input>
      </el-form-item>
      <el-form-item label="通信地址">
        <el-input v-model="dlgUcontact.data.address"></el-input>
      </el-form-item>
    </el-form>

    <div slot="footer" class="dialog-footer">
      <el-button @click="dlgUcontact.show = false ">取消</el-button>
      <el-button type="primary" @click="doEdit(21)">确定</el-button>
    </div>
  </el-dialog>
</div>
</template>

<script>
import sjcl from 'msjcl'
import { mapGetters } from 'vuex'
import { validUsername } from '@/utils/validate'
import { fetchData,doAction } from '@/api/index'
import { getKeys, getCaptcha, changePwd } from '@/api/auth'
import { wauthRegister, wauthUnbind, wauthInfo, setWinfo } from '@/utils/webauthn'
import { getLkey, dhEncrypt } from '@/utils/dh'

export default {
  name: 'Setting',
  async created() {
    const eparam = this.$route.params.eparam
    this.actTab = (eparam === '2' || eparam === '3') ? 'tab'+eparam : 'tab1'
  },
  data() { return {
      actTab: 'tab1',
      ustatus: -1,
      wauthUrl: this.$bkend_root + '/wauth',
      pkeys: {},
      ucontact: {},
      dlgUcontact : { show: false, data: {}},
      ocontact: {},
      dlgOcontact : { show: false, data: {}},
      school : {},
      roleList : [],
      lltime  : 0,
      dlgSchool: { show: false, data: {}},
      curPasswd: { old:'', new: '', new2: '' },
      pwdRules: {
        old: [{ required: true, trigger: 'blur', pattern:/^.{6,16}$/, message: '请输入6-16位数字、字母组成的密码' }],
        new: [{ required: true, trigger: 'blur', pattern:/^.{6,16}$/, message: '请输入6-16位数字、字母组成的密码' }],
        new2:[{ required: true, trigger: 'blur', validator: (rule, value, cb) => {
          if (value === '') { cb(new Error('请再次输入新密码')) } 
          else if (value !== this.curPasswd.new) { cb(new Error('两次输入密码不一致!')) } 
          else if (value === this.curPasswd.old) { cb(new Error('旧密码和新密码一致!')) } 
          else {  cb() }
        }}]
      }
  }},

  computed: { ...mapGetters(['cuser']) },

  mounted: function() {
    this.getData()
  },

  methods: {
    setData(stype, sdata) {
      if (stype == 2 && sdata && sdata.length>0) {
        sdata = sdata[0]
        this.ucontact = sdata.contact || {}
        this.ucontact.name  = sdata.name
      }

      if (stype == 4) {
        this.ocontact = sdata[0].contact || {}
      }
    },

    getData(gtype = 7) {
      if (gtype & 1) {

      }

      if (gtype & 2 ) {
        fetchData('home:contact', { gmode : 2 })
        .then(res => {
          this.setData(2,res)
        })
        .catch( err => { })
      }

      if (gtype & 4) {
        let login = this.cuser.login

        wauthInfo(this.wauthUrl, {login}) 
          .then(res => {
            this.ustatus = res.status
            if (this.ustatus>0) {
              setWinfo({ login })
            }
          })
          .catch( err => { })
      }
    },

    doPasswd(dtype = 11){
      if (dtype == 12) { // clean field
        return this.curPasswd = { old:'', new: '', new2: '' }
      }

      this.$refs.frmPasswd.validate((valid, errs) => {
        if (!valid) {
          this.$message('输入信息有误, 无法修改密码!')
          return false
        }

        let pinfo = {
          _t: Date.now(),
          u  : this.cuser.uid,
          p1 : sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(this.curPasswd.old)),
          p2 : sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(this.curPasswd.new))
        }

        // encrypt message 
        let ckeys = getLkey()
        let authdata = dhEncrypt(pinfo,ckeys.csk)
        pinfo = {
          cid     : ckeys.cid,
          auth    : authdata,
        }

        // submit change passwdp
        changePwd({ pinfo })
          .then(res => {
            this.$message("密码修改操作成功")
            this.doPasswd(12)
          })
          .catch(err => {
            this.$message("密码修改操作失败:"+err)
          })
      })
    },

    doEdit(etype = 1,row ) {
      let udata
      if (etype == 2) {
        this.dlgUcontact.data = { ...this.ucontact }
        this.dlgUcontact.title = "设置用户信息"
        this.dlgUcontact.show= true
      } else if (etype == 21) {
        udata = { 
          contact: { ...this.dlgUcontact.data },
          name: this.dlgUcontact.data.name,
          emode : 2
        }
        delete udata.contact.name

        doAction("home:contact", udata ).then(res => {
          this.$message("用户信息更新成功")
          this.dlgUcontact.show = false
          this.getData(2)
        }).catch( err => { })
      } else  if (etype == 22) { // sso
      } else  if (etype == 4) {
        this.dlgOcontact.data = { ...this.ocontact }
        this.dlgOcontact.title = "设置机构联系信息"
        this.dlgOcontact.show= true
      } else if (etype == 41) {
        udata = { 
          contact: { ...this.dlgOcontact.data },
          emode : 4
        }

        doAction("home:contact", udata ).then(res => {
          this.$message("机构信息更新成功")
          this.dlgOcontact.show = false
          this.getData(4)
        }).catch( err => { })
      } else if (etype == 5) {
        this.dlgSchool.data = { ...this.school }
        this.dlgSchool.title = "设置学校信息信息"
        this.dlgSchool.show= true
      } else if (etype == 51) {
        udata = { ...this.dlgSchool.data }

        doAction("school:info", udata ).then(res => {
          this.$message("学校信息更新成功")
          this.dlgSchool.show = false
          this.getData(8)
        }).catch( err => { })
      } else if (etype == 61) {
        udata = { ...row, lltime: this.lltime+1 }

        doAction("home:rswitch", udata ).then(res => {
          this.$router.push({ name: "rlogin", params: { ltype : 2, user: res } })
        }).catch( err => { 
          this.$message('切换操作失败: ' + err.message)
        })
      }
    },

    doRegister() {
        let sign,
        login = this.cuser.login,
        name  = this.cuser.name

        wauthRegister(this.wauthUrl, { login, name })
        .then(rresult => {
          this.$message( "令牌设置成功")
          this.ustatus =  2
        })
        .catch( err => {
          console.log(err)
          this.$message( "Wauth错误:"+ err.message )
        })
      },

      doUnbind() {
        let login = this.cuser.login

        wauthUnbind(this.wauthUrl, {login}) 
          .then(res => {
            this.$message( "Wauth解绑操作成功" )
            this.ustatus =  -1
          })
          .catch( err => {
            console.log(err)
            this.$message( "Wauth错误:"+ err.message )
          })
      }
  }
}
</script>

<style lang="scss" scoped>

</style>
