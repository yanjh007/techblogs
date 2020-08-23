import Vue from 'vue'
import fetcher from '@/utils/fetcher'

// system config or null
const getAurl = (apath)=>{
  return (Vue.prototype.$auth_root || '/auth') + apath
}

export function dhKey(data) {
  return fetcher.get(getAurl("/dhkey"),data)
}

export function getKeys() {
  return fetcher.get(getAurl("/keys/") + Math.random().toString().slice(-8))
}

export function getCaptcha() {
  return fetcher.get(getAurl("/captcha/") +  Math.random().toString().slice(-8))
}

export function login(data) {
  return fetcher.post(getAurl("/login"), data)
}

export function logout(data) {
  return fetcher.post(getAurl("/logout"), data)
}

export function changePwd(data) {
  return fetcher.post(getAurl("/passwd"), data)
}

// ul login with token using auth module
export function ulogin(data) {
  return fetcher.post(getAurl("/ulogin"), data)
}


// register
const getWurl = (apath)=>{
  return Vue.prototype.$bkend_root + '/wauth' + apath
}

export function wregister(data) {
  return fetcher.post(getWurl("/register"), data)
}

export function wlogin(data) {
  return fetcher.post(getWurl("/login"), data)
}

// reponse
export function wresponse(data) {
  return fetcher.post(getWurl("/response"), data)
}

// user info 
export function wuinfo(data) {
  return fetcher.post(getWurl("/uinfo"), data)
}

// user info 
export function wunbind(data) {
  return fetcher.post(getWurl("/unbind"), data)
}


