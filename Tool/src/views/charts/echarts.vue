<template>
  <div class="home-container">
    <el-row class="header">
      <el-col :span="10" class="logo">
        Vulnerability Sorting System
      </el-col>
      <el-col :span="14">
        <el-menu mode="horizontal" :default-active="$route.path">
          <el-menu-item index="/" class="is-active">
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
          <el-menu-item index="/help">
            <i class="fa fa-question-circle"></i> Help
          </el-menu-item>
        </el-menu>
      </el-col>
    </el-row>

    <el-carousel :interval="5000" arrow="always">
      <el-carousel-item v-for="(item, index) in carouselItems" :key="index">
        <img :src="item.image" alt="Carousel Image">
      </el-carousel-item>
    </el-carousel>

    <el-row class="features">
      <el-col :span="8" v-for="(feature, index) in features" :key="index">
        <div class="feature-item">
          <i :class="feature.icon"></i>
          <h3>{{ feature.title }}</h3>
          <p>{{ feature.description }}</p>
        </div>
      </el-col>
    </el-row>

    <el-row class="news">
      <el-col :span="24">
        <h2>News and Information</h2>
        <el-table :data="newsList" stripe>
          <el-table-column prop="title" label="Title"></el-table-column>
          <el-table-column prop="date" label="Date"></el-table-column>
          <el-table-column label="Action">
            <template slot-scope="scope">
              <el-button type="primary" size="small" @click="readNews(scope.row)">Read</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-col>
    </el-row>
  </div>
</template>

<script>
export default {
  data() {
    return {
      carouselItems: [
        { image: 'https://via.placeholder.com/1920x600?text=Slide+1' },
        { image: 'https://via.placeholder.com/1920x600?text=Slide+2' },
        { image: 'https://via.placeholder.com/1920x600?text=Slide+3' }
      ],
      features: [
        {
          icon: 'fa fa-table',
          title: 'CVE List Management',
          description: 'Manage CVE information, including querying, adding, and deleting.'
        },
        {
          icon: 'fa fa-bar-chart',
          title: 'Chart Display',
          description: 'View various charts related to CVE and commit information.'
        },
        {
          icon: 'fa fa-search',
          title: 'Search Function',
          description: 'Quickly search for the information you need.'
        }
      ],
      newsList: [
        {
          title: 'News 1',
          date: '2024-01-01'
        },
        {
          title: 'News 2',
          date: '2024-01-02'
        },
        {
          title: 'News 3',
          date: '2024-01-03'
        }
      ]
    };
  },
  methods: {
    readNews(news) {
      console.log('Read news:', news);
    }
  }
};
</script>

<style scoped lang="scss">
.home-container {
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

.carousel {
  height: 600px;
  img {
    width: 100%;
    height: 100%;
    object-fit: cover;
  }
}

.features {
  padding: 50px 0;
  .feature-item {
    text-align: center;
    i {
      font-size: 48px;
      color: #006a63;
    }
    h3 {
      margin: 20px 0;
    }
  }
}

.news {
  padding: 50px 0;
  h2 {
    margin-bottom: 20px;
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
