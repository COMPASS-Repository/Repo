<template>
  <div class="home-container">
    <img
      src="~@/assets/ship.png"
      alt="Single Image"
      class="single-image"
    >

    <el-row class="features">
      <el-col :span="12" v-for="(feature, index) in features" :key="index">
        <div class="feature-item">
          <i :class="feature.icon"></i>
          <h3>{{ feature.title }}</h3>
          <p>{{ feature.description }}</p>
          <el-button type="primary" @click="goToPage(feature.path)">
            Go to {{ feature.title }}
          </el-button>
        </div>
      </el-col>
    </el-row>


<script>
export default {
  data() {
    return {
      features: [
        {
          icon: 'fa fa-bar-chart',
          title: 'Statistic',
          description: 'View CVE chart',
          path: '/CVEchart'
        },
        {
          icon: 'fa fa-table',
          title: 'Dataset',
          description: 'Manage CVE list and View patch relations',
          path: '/CVEtable'
        },
      ]
    };
  },
  methods: {
    goToPage(path) {
      this.$router.push(path);
    }
  }
};
</script>

<style scoped>
.home-container {
  padding: 20px;
}

.features {
  margin-top: 20px;
  justify-content: space-around;
}

.feature-item {
  text-align: center;
  padding: 20px;
}

.footer {
  margin-top: 20px;
  text-align: center;
}

.single-image {
  width: 100%;
  max-height: 380px;
  object-fit: contain;
  object-position: center;
  margin-bottom: 20px;
  border-radius: 8px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}
</style>
