<template>
  <div class="help-container">
    <el-row class="header">
      <el-col :span="10" class="logo">
        Vulnerability Sorting System
      </el-col>
      <el-col :span="14">
        <el-menu mode="horizontal" :default-active="$route.path">
          <el-menu-item index="/">
            <i class="fa fa-home"></i> Home
          </el-menu-item>
          <el-menu-item index="/CVEtable">
            <i class="fa fa-table"></i> CVE List
          </el-menu-item>
          <el-menu-item index="/CVEchart">
            <i class="fa fa-bar-chart"></i> CVE Chart
          </el-menu-item>
          <el-menu-item index="/committable">
            <i class="fa fa-table"></i> Commit List
          </el-menu-item>
          <el-menu-item index="/Commitchart">
            <i class="fa fa-bar-chart"></i> Commit Chart
          </el-menu-item>
          <el-menu-item index="/help" class="is-active">
            <i class="fa fa-question-circle"></i> Help
          </el-menu-item>
        </el-menu>
      </el-col>
    </el-row>

    <el-row class="help-content">
      <el-col :span="24">
        <h2>Help Information</h2>
        <p>
          This is a help page for the Vulnerability Sorting System. Here you can find some common questions and answers to help you use the system better.
        </p>
        <h3>1. How to search for CVE information?</h3>
        <p>
          On the CVE List page, you can enter the CVE ID in the search box and click the "Search" button to find specific CVE information.
        </p>
        <h3>2. How to add a new CVE?</h3>
        <p>
          On the CVE List page, click the "Add CVE" button, enter the CVE ID and select the repository name, then click the "OK" button to add a new CVE.
        </p>
        <h3>3. How to view the details of a CVE?</h3>
        <p>
          On the CVE List page, click the "Details" button next to the CVE you want to view, and the details page will pop up.
        </p>
        <h3>4. How to predict the commit for a CVE?</h3>
        <p>
          On the CVE details page, if the CVE has not been patched, click the "Predict Commit" button to predict the possible commit for the CVE.
        </p>
      </el-col>
    </el-row>

<script>
export default {
  data() {
    return {};
  },
  methods: {}
};
</script>

<style scoped lang="scss">
.help-container {
  width: 100%;
  min-height: 100vh;
}

.header {
  height: 60px;
  line-height: 60px;
  background: #006a63;
  color: #fff;
  .logo {
    font-size: 22px;
    padding-left: 20px;
  }
  .el-menu {
    border-bottom: none;
  }
  .el-menu-item {
    color: #fff;
  }
}

.help-content {
  padding: 50px;
  h2 {
    margin-bottom: 20px;
  }
  h3 {
    margin-top: 30px;
    margin-bottom: 10px;
  }
}

.footer {
  height: 60px;
  line-height: 60px;
  background: #006a63;
  color: #fff;
  text-align: center;
}
</style>
