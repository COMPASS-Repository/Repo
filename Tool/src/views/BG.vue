<template>
  <el-row class="container">
    <el-col :span="24" class="header">
      <el-col :span="10" class="logo logo-width">
        <i class="el-icon-picture"></i>
        <span>LPL</span>
      </el-col>

      <div class="button-container">
        <el-button
          type="text"
          @click="goHome"
          class="home-button"
          :class="{ active: currentRoute === '/home' }"
        >
          <i class="fa fa-home"></i>
          <span>Home</span>
        </el-button>

        <el-button
          type="text"
          @click="goToCVEChart"
          class="extra-button"
          :class="{ active: currentRoute === '/CVEchart' }"
        >
          <i class="fa fa-bar-chart"></i>
          <span>Statistic</span>
        </el-button>

        <el-button
          type="text"
          @click="goToCVEList"
          class="extra-button"
          :class="{ active: currentRoute === '/CVEtable' }"
        >
          <i class="fa fa-table"></i>
          <span>Dataset</span>
        </el-button>

        <el-button
          type="text"
          @click="goToCommitList"
          class="extra-button"
          :class="{ active: currentRoute === '/committable' }"
        >
          <i class="fa fa-table"></i>
          <span>Predict</span>
        </el-button>

        <el-button
          type="text"
          @click="goHelp"
          class="help-button"
          :class="{ active: currentRoute === '/help' }"
        >
          <i class="fa fa-question-circle"></i>
          <span>Help</span>
        </el-button>
      </div>
    </el-col>

    <el-col :span="24" class="main">
      <section class="content-container">
        <el-col :span="24" class="content-wrapper">
          <transition name="fade" mode="out-in">
            <router-view></router-view>
          </transition>
        </el-col>
      </section>
    </el-col>
  </el-row>
</template>

<script>
import { setpwd } from "../api/api";
export default {
  data() {
    var validatePass = (rule, value, callback) => {
      if (value === "") {
        callback(new Error("Please enter new password"));
      } else if (value.length < 8) {
        callback(new Error("Password length must be greater than 8"));
      } else {
        if (this.setpwdForm.confirpass !== "") {
          this.$refs.setpwdForm.validateField("confirpass");
        }
        callback();
      }
    };
    var validatePass2 = (rule, value, callback) => {
      if (value === "") {
        callback(new Error("Please re-enter new password"));
      } else if (value !== this.setpwdForm.newpass) {
        callback(new Error("The two passwords entered are inconsistent!"));
      } else {
        callback();
      }
    };
    return {
      sysName: "SHIP",
      sysUserName: "",
      form: {
        name: "",
        region: "",
        date1: "",
        date2: "",
        delivery: false,
        type: [],
        resource: "",
        desc: ""
      },
      setpwdFormVisible: false,
      editLoading: false,
      setpwdFormRules: {
        oldpass: [{ required: true, message: "Please enter old password", trigger: "blur" }],
        newpass: [{ validator: validatePass, trigger: "blur" }],
        confirpass: [{ validator: validatePass2, trigger: "blur" }]
      },
      setpwdForm: {
        oldpass: "",
        newpass: "",
        confirpass: ""
      },
      currentRoute: this.$route.path
    };
  },
  methods: {
    onSubmit() {
      console.log("submit!");
    },
    handleopen() {},
    handleclose() {},
    handleselect: function(a, b) {},
    logout: function() {
      var _this = this;
      this.$confirm("Are you sure to logout?", "Prompt", {})
        .then(() => {
          sessionStorage.removeItem("token");
          _this.$router.push("/login");
        })
        .catch(() => {});
    },
    settings: function() {
      this.setpwdFormVisible = true;
    },
    editSubmit: function() {
      this.$refs.setpwdForm.validate(valid => {
        if (valid) {
          this.$confirm("Are you sure to modify?", "Prompt", {}).then(() => {
            this.editLoading = true;
            let para = Object.assign({}, this.setpwdForm);
            setpwd(para).then(res => {
              this.editLoading = false;
              let { code, msg } = res.data;
              if (code !== 200) {
                this.$message({
                  message: msg,
                  type: 'error'
                });
              } else {
                this.$message({
                  message: msg,
                  type: 'success'
                });
              }
              this.$refs["setpwdForm"].resetFields();
              this.setpwdFormVisible = false;
            });
          });
        }
      });
    },
    goHome() {
      this.$router.push('/home');
    },
    goHelp() {
      this.$router.push('/help');
    },
    goToCVEList() {
      this.$router.push('/CVEtable');
    },
    goToCVEChart() {
      this.$router.push('/CVEchart');
    },
    goToCommitList() {
      this.$router.push('/committable');
    }
  },
  mounted() {
    this.currentRoute = this.$route.path;
    this.$router.afterEach((to) => {
      this.currentRoute = to.path;
    });
  }
};
</script>

<style scoped lang="scss">
@import "~scss_vars";

.container {
  position: absolute;
  top: 0px;
  bottom: 0px;
  width: 100%;
  .header {
    height: 60px;
    line-height: 60px;
    background: #006a63;
    color: #fff;
    display: flex;
    justify-content: space-between;
    align-items: center;

    .logo {
      width: 230px;
      height: 60px;
      font-size: 22px;
      padding-left: 20px;
      padding-right: 20px;
      border-color: rgba(238, 241, 146, 0.3);
      font-family: "Microsoft YaHei";

      img {
        width: 40px;
        float: left;
        margin: 10px 10px 10px 18px;
      }

      i {
        margin-right: 10px;
      }

      .txt {
        color: #fff;
      }
    }

    .button-container {
      margin-left: auto;
      display: flex;
    }

    .home-button, .help-button, .extra-button {
      margin-right: 20px;
      font-size: 16px;
      color: white;
      &:hover {
        transform: scale(1.1);
        transition: all 0.3s ease;
      }
    }

    .active {
      transform: scale(1.3);
      transition: transform 0.5s ease, text-shadow 0.5s ease;
    }
  }

  .main {
    display: flex;
    position: absolute;
    top: 60px;
    bottom: 0px;
    overflow: hidden;
    .content-container {
      flex: 1;
      overflow-y: scroll;
      padding: 20px;
      .breadcrumb-container {
        .title {
          width: 100px;
          float: right;
          color: #475669;
        }
        .breadcrumb-inner {
          float: right;
        }
      }
      .content-wrapper {
        background-color: #fff;
        box-sizing: border-box;
      }
    }
  }
}
</style>
