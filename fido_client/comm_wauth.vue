<template>
  <div class="app-container">
    <div class="topbar">
      FIDO2/WebAuthn令牌设置
    </div>

  <el-card class="box-card">
    <div slot="header" class="clearfix">
      <span>令牌状态和设置</span>
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

  </div>
</template>

<script>
  import waves from '@/directive/waves' // waves directive
  import { mapGetters } from 'vuex'
  import { fetchData, doAction } from '@/api/index'
  import { setValue, getValue } from '@/utils/eventBus'
  import { wregister, wlogin, wresponse, wunbind , wuinfo } from '@/api/auth'
  import { decodeCred, decodeAssert, packPubkey, setWinfo } from '@/utils/webauthn'

  export default {
    name: 'CommonQuery',
    directives: { waves },
    data() { return {
      ustatus: -1,
      ereport: {},
      mainList: [],
      bLoading: false
    }},
    computed: { ...mapGetters([ 'cuser' ]) },
    created() { this.getData() },
    methods: {
      getData(page = 1){
        let login = this.cuser.login

        wuinfo({login}) 
          .then(res => {
            this.ustatus = res.status
            if (this.ustatus>0) {
              setWinfo({ login })
            }
          })
          .catch( err => { })
          .finally(_=>{ })
      },

      doRegister() {
        let sign,
        login = this.cuser.login,
        name  = this.cuser.name

        wregister({ login, name })
          .then(res => {
            let publicKey = decodeCred(res.cred)
            sign = res.sign
            return navigator.credentials.create({ publicKey })
          })
          .then(rdata =>{
            let credRes = packPubkey(rdata)
            return wresponse({...credRes,sign,login})
          })
          .then(res2 => {
            this.$message( "令牌设置成功")
            this.ustatus =  2
          })
          .catch( err => {
            console.log(err)
            this.$message( "Wauth错误:"+ err.message )
          })
          .finally(_=>{
            
          })
      },

      doUnbind() {
        let login = this.cuser.login

        wunbind( {login}) 
          .then(res => {
            this.$message( "Wauth解绑操作成功" )
            this.ustatus =  -1
          })
          .catch( err => {
            console.log(err)
            this.$message( "Wauth错误:"+ err.message )
          })
          .finally(_=>{
            
          })
      }
    }
  }
</script>
<style lang="scss" scoped>

</style>

