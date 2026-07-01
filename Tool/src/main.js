import babelpolyfill from 'babel-polyfill'
import Vue from 'vue'
import App from './App'
import ElementUI from 'element-ui'
import locale from 'element-ui/lib/locale/lang/en'
import { Message } from 'element-ui'
import './assets/theme/theme-#006a63/index.css'
import VueRouter from 'vue-router'
import store from './vuex/store'
import Vuex from 'vuex'
import routes from './routes'
import 'font-awesome/css/font-awesome.min.css'
import axios from 'axios';

Vue.use(ElementUI, { locale })
Vue.use(VueRouter)
Vue.use(Vuex)

const router = new VueRouter({
  routes
})

axios.interceptors.request.use(
  config => {
    var token = sessionStorage.getItem('token');
    if (token) {
      token = sessionStorage.getItem('token')+':';
      config.headers.Authorization = `Basic ${new Buffer(token).toString('base64')}`;
    }
    return config;
  },
  error => {
    Message({
      message: "Login status expired, please login again",
      type: "error"
    });
    router.push({
      path: "/login"
    });
  }
);

axios.interceptors.response.use(
  response => {
    return response;
  },
  error => {
    if (error.response) {
      switch (error.response.status) {
        case 401:
          localStorage.removeItem('token');
          router.push({
            path: "/login"
          });
          Message({
            message: 'Please check your login status',
            type: 'error'
          });
      }
    }
  }
);

router.beforeEach((to, from, next) => {
  if (to.path == '/login') {
    sessionStorage.removeItem('token');
  }
  let token = sessionStorage.getItem('token');
  if (!token && to.path != '/login') {
    next({ path: '/login' })
  } else {
    next()
  }
})

new Vue({
  router,
  store,
  render: h => h(App)
}).$mount('#app')
