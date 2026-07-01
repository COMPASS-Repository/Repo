<template>
  <div class="help-container">
    <el-row>
      <el-col :span="4">
        <el-menu
          mode="vertical"
          :default-active="activeIndex"
          @select="handleSelect"
        >
          <el-menu-item index="searchCVE">How to search for CVE information?</el-menu-item>
          <el-menu-item index="addCVE">How to add a new CVE?</el-menu-item>
          <el-menu-item index="viewDetails">How to view the details of a CVE?</el-menu-item>
          <el-menu-item index="predictCommit">How to predict the commit for a CVE?</el-menu-item>
        </el-menu>
      </el-col>
      <el-col :span="20">
        <el-row class="help-content">
          <el-col :span="24">
            <h2>Help Information</h2>
            <p>
              This is a help page for the Vulnerability Sorting System. Here you can find some common questions and answers to help you use the system better.
            </p>
            <h3 id="searchCVE">1. How to search for CVE information?</h3>
            <p>
              On the CVE List page, you can enter the CVE ID in the search box and click the "Inquire" button to search for specific CVE information.
            </p>
            <h3 id="addCVE">2. How to add a new CVE?</h3>
            <p>
              On the CVE List page, click the "Add CVE" button, enter the CVE ID and select the repository name, then click the "OK" button to add a new CVE.
            </p>
            <h3 id="viewDetails">3. How to view the details of a CVE?</h3>
            <p>
              On the CVE List page, click the "Details" button next to the CVE you want to view, and the details page will pop up.
            </p>
            <h3 id="predictCommit">4. How to predict the commit for a CVE?</h3>
            <p>
              On the CVE details page, if the CVE has not been patched, click the "Predict Commit" button to predict the possible commit for the CVE.
            </p>
          </el-col>
        </el-row>
      </el-col>
    </el-row>
  </div>
</template>

<script>
export default {
  data() {
    return {
      activeIndex: 'searchCVE'
    };
  },
  methods: {
    handleSelect(key) {
      const element = document.getElementById(key);
      if (element) {
        element.scrollIntoView({ behavior: 'smooth' });
        this.activeIndex = key;
      }
    }
  }
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
