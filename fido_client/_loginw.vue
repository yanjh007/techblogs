<template>
<div class="login-container">
  <el-card class="login-card">
    <h3>令牌登录</h3>

    <div class="tips" >
      <i class="el-icon-loading" />
      <span v-html="tlogin" /><br><br>
      <el-input v-model="login" placeholder="请输入用户登录名"></el-input><br><br>
      <el-button type="primary" @click.prevent="doLogin()">登录</el-button>
      <el-button type="primary" @click.prevent="doCancel()">取消并返回</el-button>

    </div>

    <div class="card-footer">
      <hr><span>{{ x_app.copyRight }}</span>
    </div>
  </el-card>
</div>
</template>

<script>
import { setRouter } from '@/routers/index'
import { setTimeout } from 'timers'
import { getUserStore } from '@/utils/auth' 
import { wlogin, wresponse, wuinfo } from '@/api/auth'
import { decodeCred, decodeAssert, packPubkey, getWinfo} from '@/utils/webauthn'

const INFO_LOGIN = [
  "系统正在使用当前客户端信息重新登录...",
  "系统正在进行用户切换...",
  "系统正在使用统一认证信息进行再登录...",
]

export default {
  name: 'LoginW',
  data() { return {
      lmode: 0,
      login : null,
      tlogin: "",
      token : null,
      redirect: undefined
    }
  },
  watch: {
    $route: {
      handler: function(route) {
        this.redirect = route.query && route.query.redirect
      },
      immediate: true
    }
  },
  mounted: function() {
    this.onMount(this.$route.params)
  },
  methods: { 
    onMount(rparam) {
      this.login = getWinfo()
      if (this.login) {
        this.login = this.login.login
        this.tlogin = "正在准备硬件令牌和预留用户信息进行登录,..."

        setTimeout(this.doLogin,1000)
      } else {
        this.tlogin = "无预留登录信息，需要在登录时设置"
      }
    },

    doLogin() {
      let sign,login = this.login || ""

      if (login.trim().length ==0) {
        return this.$message("请设置登录名称")
      }

      wlogin({ login })
      .then(res => {
        let publicKey = decodeAssert(res.assert);
        sign  = res.sign
        login = res.login
        return navigator.credentials.get({ publicKey })
      })
      .then(rdata =>{
        let assertRes = packPubkey(rdata)
        return wresponse({...assertRes,sign,login})
      })
      .then(oUser => {
        this.$message( "令牌登录成功")
        let lparam = {_ltype : 1 , user : oUser}
        return this.$store.dispatch('user/login', lparam)
      })
      .then(cuser => {              
        setRouter(this.$router, this.redirect || '/')
      })
      .catch( err => {
        console.log(err)
        this.$message( "Wauth错误:"+ err.message )
      })
      .finally(_=>{
        
      })
    },

    doCancel() {
      this.$router.back()
    }
  }
}
</script>

<style lang="scss" scoped>
  $bg:#2d3a4b;
  $dark_gray:#889aa4;
  $light_gray:#eee;

  .login-container {
    align-content: center;
    text-align: center;
    min-height: 100%;
    width: 100%;
    
    background: #1FA2FF;  /* fallback for old browsers */
    background: linear-gradient(to top left, #9999ff 7%, #00ffff 100%);

    overflow: hidden;

    .login-card{
      position: relative;
      background-color: $bg;
      border: 10x solid rgba(255, 255, 255, 0.1);
      width  : 600px;
      height : 300px;
      padding : 20px;
      margin-top : 80px;
      margin-left: auto; 
      margin-right: auto;

      h3 {
        font-size: 26px;
        color: $light_gray;
        margin: 0px auto 40px auto;
        text-align: center;
        font-weight: bold;
      }

      .card-footer {
        position: absolute;
        width: 90%;
        text-align : center;
        height: 60px;
        color: $light_gray;
        color: #fff;
        margin: 10px;
        bottom: 0;
        hr {
          margin-top: 30px;
          border: 0.5px dotted rgb(0, 140, 255);
        }
      }

      .tips {
        font-size: 14px;
        color: #fff;
        margin-bottom: 10px;
      }
    }
  }
</style>
