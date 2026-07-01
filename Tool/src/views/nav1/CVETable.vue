<template>
  <section>
    <el-col :span="24" class="toolbar" style="padding-bottom: 0px;">
      <el-form :inline="true" :model="filters">
        <el-form-item label="CVE:">
          <el-input v-model="filters.CVE" placeholder="CVE ID"></el-input>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" v-on:click="getCVEs()">Search</el-button>
        </el-form-item>
      </el-form>
    </el-col>

    <div v-loading="listLoading" element-loading-text="LOADING...">
      <table style="width: 100%; border-collapse: collapse;">
        <thead>
          <tr>
            <th style="width: 55px;"></th>
            <th style="width: 150px;">CVE ID</th>
            <th style="width: 125px;">CVE Time</th>
            <th style="width: 185px;">Warehouse Name</th>
            <th style="width: 140px;">Patch Num</th>
            <th style="width: 160px;">CWE ID</th>
            <th style="width: 240px;">CWE Type</th>
            <th style="width: 335px;">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(row, index) in CVEs" :key="index">
            <td>{{ (page - 1) * page_size + index + 1 }}</td>
            <td>{{ row.cve }}</td>
            <td>{{ row.cve_time }}</td>
            <td>{{ row.repo }}</td>
            <td>{{ row['patch num'] }}</td>
            <td>{{ row.cwe_id }}</td>
            <td>{{ row.cwe_type }}</td>
            <td>
              <el-button type="success" size="small" @click="Details(index, row)">Details</el-button>
              <el-button type="success" size="small" @click="Relationship(index, row)">Relationship</el-button>
              <el-button type="warning" size="small" @click="Edit(index, row)">Edit</el-button>
              <el-button type="danger" size="small" @click="Delete(index, row)">Delete</el-button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <el-col :span="24" class="toolbar">
      <el-pagination
        layout="prev, pager, next"
        @current-change="handleCurrentChange"
        :page-size="page_size"
        :total="total"
        style="float:right;"
      ></el-pagination>
    </el-col>

    <el-dialog title="Details" :visible.sync="detailFormVisible" :close-on-click-modal="false">
      <div class="custom-detail-container">
        <div class="custom-detail-row">
          <div class="custom-detail-label">CVE ID</div>
          <div class="custom-detail-value">{{ detailForm.cve }}</div>
        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Repo</div>
          <div class="custom-detail-value">{{ detailForm.repo }}</div>
        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Patch Num</div>
          <div class="custom-detail-value">{{ detailForm['patch num'] }}</div>
        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Patch IDs</div>
          <div class="custom-detail-value">{{ detailForm['commit list'] }}</div>
        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Description</div>
          <div class="custom-detail-value">{{ detailForm['desc'] }}</div>
        </div>
      </div>
    </el-dialog>

    <el-dialog title="Relationship" :visible.sync="relationshipFormVisible" :close-on-click-modal="false">
      <div class="custom-detail-container">
        <div class="custom-detail-row">
          <div class="custom-detail-label">CVE ID</div>
          <div class="custom-detail-value">{{ detailForm.cve }}</div>
        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Patch Num</div>
          <div class="custom-detail-value">{{ detailForm['patch num'] }}</div>
        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Patch IDs</div>
          <div class="custom-detail-value">{{ detailForm['commit list'] }}</div>
        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Merge</div>
          <div class="custom-detail-value">{{ detailForm['merge'] }}</div>
        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Mirror</div>
          <div class="custom-detail-value">{{ detailForm['mirror'] }}</div>
        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Better</div>
          <div class="custom-detail-value">{{ detailForm['better'] }}</div>
        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Fix-of</div>
          <div class="custom-detail-value">{{ detailForm['fix-of'] }}</div>
        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Collab</div>
          <div class="custom-detail-value">{{ detailForm['collab'] }}</div>
        </div>

      </div>

      <div slot="footer" class="dialog-footer">
        <el-button type="primary" @click="showGraph(detailForm)">Graph</el-button>
      </div>
    </el-dialog>

    <el-dialog title="Graph" :visible.sync="graphDialogVisible" :close-on-click-modal="false">
      <div class="custom-detail-container" style="width: 94%; height: 460px;">
        <div id="Graph" style="width: 1000%; height: 500px;"></div>
      </div>
    </el-dialog>

    <el-dialog title="Edit" :visible.sync="editFormVisible" :close-on-click-modal="false">
      <div class="custom-detail-container">
        <div class="custom-detail-row">
          <div class="custom-detail-label">CVE ID</div>
          <div class="custom-detail-value">{{ detailForm['cve'] }}</div>

        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Repo</div>
          <div class="custom-detail-value">{{ detailForm['repo'] }}</div>
        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Patch Num</div>
          <el-input v-model="detailForm['patch num']"></el-input>
        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Patch IDs</div>
          <el-input v-model="detailForm['commit list']"></el-input>
        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Merge</div>
          <el-input v-model="detailForm['merge']"></el-input>
        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Mirror</div>
          <el-input v-model="detailForm['mirror']"></el-input>
        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Better</div>
          <el-input v-model="detailForm['better']"></el-input>
        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Fix-of</div>
          <el-input v-model="detailForm['fix-of']"></el-input>
        </div>

        <div class="custom-detail-row">
          <div class="custom-detail-label">Collab</div>
          <el-input v-model="detailForm['collab']"></el-input>
        </div>

      </div>

      <div slot="footer" class="dialog-footer">
        <el-button type="primary" @click="Submit">Submit</el-button>
        <el-button @click="editFormVisible = false">Cancel</el-button>
      </div>
    </el-dialog>

    <el-dialog title="Submit" :visible.sync="submitVisible" width="30%">
      <span>Success!</span>

    </el-dialog>

    <el-dialog title="Delete" :visible.sync="deleteVisible" width="30%">
      <span>You sure you want to send a 'delete' message?</span>
      <div slot="footer" class="dialog-footer">
        <el-button @click="deleteVisible = false">NO</el-button>
        <el-button type="primary" @click="Submit">YES</el-button>
      </div>
    </el-dialog>
  </section>
</template>

<script>
import echarts from 'echarts';
import { getCVEListPage, removeUser, batchRemoveUser, addNewCVE, updateCVE } from '../../api/api';

export default {
  data() {
    return {
      filters: {
        CVE: '',
        repoid: '',
        repo: ''
      },
      CVEs: [],
      page_size: 20,
      total: 0,
      page: 1,
      listLoading: false,
      sels: [],
      detailFormVisible: false,
      relationshipFormVisible: false,
      editFormVisible: false,
      graphDialogVisible: false,
      relationshipData: {},
      detailForm: {},
      backmsg: '',
      selectLoading: false,
      submitVisible: false,
      deleteVisible: false
    };
  },
  methods: {
    buttonType(str) {
      if (str === '' || str === null) {
        return 'warning';
      }
      return 'success';
    },
    jump(msg) {
      console.log(msg);
      this.$router.push({
        path: '/predict',
        name: 'PredictCommitForCVE',
        params: {
          datacve: msg
        }
      });
    },
    handleCurrentChange(val) {
      this.page = val;
      this.getCVEs();
    },
    getCVEs() {
      let para = {
        page: this.page,
        CVE: this.filters.CVE,
        repoid: this.filters.repoid,
        repo: this.filters.repo
      };
      this.listLoading = true;
      getCVEListPage(para).then((res) => {
        this.total = res.data.total;
        this.page_size = res.data.page_size;
        this.CVEs = res.data.infos;
        this.listLoading = false;
      });
    },
    Delete() {
      this.deleteVisible = true;
    },
    Details(index, row) {
      this.detailFormVisible = true;
      this.detailForm = Object.assign({}, row);
    },
    Relationship(index, row) {
      this.relationshipFormVisible = true;
      this.detailForm = Object.assign({}, row);
    },
    showGraph(data) {
      this.relationshipData = data;
      this.graphDialogVisible = true;
      this.$nextTick(() => {
        this.drawRelationshipGraph();
      });
    },
    drawRelationshipGraph() {
      const chart = echarts.init(document.getElementById('Graph'));

      const {
        'merge': mergeData,
        'mirror': mirrorData,
        'better': betterData,
        'fix-of': fixOfData,
        'collab': collabData,
        commit: commitStr
      } = this.detailForm;

      let commit = [];
      try {
        const validJsonStr = commitStr.replace(/'/g, '"');
        commit = JSON.parse(validJsonStr);
      } catch (error) {
        console.error('Failed to parse commit string:', error);
        commit = commitStr.split(', ').map(str => str.replace(/['"]/g, ''));
      }

      const nodes = [];
      const edges = [];
      const nodeColors = {
        'CVE': '#666666',
        'commit': '#DDDDDD'
      };
      const edgeColors = {
        'merge': '#FFC0CB',
        'mirror': '#66BB6A',
        'better': '#42A5F5',
        'fix-of': '#FFA500',
        'collab': '#BA68C8',
      };

      nodes.push({
        name: 'CVE',
        symbolSize: 30,
        itemStyle: {
          color: nodeColors['CVE'],
          shadowBlur: 10,
          shadowColor: 'rgba(0, 0, 0, 0.3)',
          shadowOffsetX: 0,
          shadowOffsetY: 5
        }
      });

      const allValues = new Set();
      const allKeys = new Set();

      const handleRelationship = (relationData, relationType) => {
        if (relationData) {
          const relationObj = JSON.parse(relationData);
          for (const source in relationObj) {
            const shortSource = source.slice(0, 7);
            allKeys.add(shortSource);
            const sourceNode = {
              name: shortSource,
              symbolSize: 20,
              itemStyle: {
                color: edgeColors[relationType],
                shadowBlur: 10,
                shadowColor: 'rgba(0, 0, 0, 0.3)',
                shadowOffsetX: 0,
                shadowOffsetY: 5
              }
            };
            if (!nodes.some(node => node.name === shortSource)) {
              nodes.push(sourceNode);
            }
            relationObj[source].forEach(commit => {
              const shortCommit = commit.slice(0, 7);
              allValues.add(shortCommit);
              const commitNode = {
                name: shortCommit,
                symbolSize: 20,
                itemStyle: {
                  color: edgeColors[relationType],
                  shadowBlur: 10,
                  shadowColor: 'rgba(0, 0, 0, 0.3)',
                  shadowOffsetX: 0,
                  shadowOffsetY: 5
                }
              };
              if (!nodes.some(node => node.name === shortCommit)) {
                nodes.push(commitNode);
              }

              const existingEdge = edges.find(
                edge =>
                  edge.source === shortCommit &&
                  edge.target === shortSource
              );
              if (existingEdge) {
                existingEdge.relationTypes.push(relationType);
                existingEdge.label.formatter = () => existingEdge.relationTypes.join(', ');
                if (existingEdge.relationTypes.length > 1) {

                  existingEdge.lineStyle = {
                    color: '#FF5555',
                    opacity: 0.7,
                    curveness: 0.5,
                    width: 1
                  };

                  const sourceNodeInNodes = nodes.find(node => node.name === shortSource);
                  const commitNodeInNodes = nodes.find(node => node.name === shortCommit);
                  if (sourceNodeInNodes) {
                    sourceNodeInNodes.itemStyle.color = '#FF5555';
                  }
                  if (commitNodeInNodes) {
                    commitNodeInNodes.itemStyle.color = '#FF5555';
                  }
                }
              } else {
                edges.push({
                  source: shortCommit,
                  target: shortSource,
                  label: {
                    show: true,
                    formatter: () => relationType
                  },
                  lineStyle: {
                    color: edgeColors[relationType],
                    opacity: 0.7,
                    curveness: 0.5,
                    width: 1
                  },
                  symbol: ['none', 'arrow'],
                  symbolSize: [6, 10],
                  relationTypes: [relationType]
                });
              }
            });
          }
        }
      };

      handleRelationship(mergeData, 'merge');
      handleRelationship(mirrorData, 'mirror');
      handleRelationship(betterData, 'better');
      handleRelationship(fixOfData, 'fix-of');
      handleRelationship(collabData, 'collab');

      const keysToConnectToCVE = [];
      allKeys.forEach(key => {
        const shortKey = key.slice(0, 7);
        if (!allValues.has(shortKey)) {
          keysToConnectToCVE.push(shortKey);
        }
      });

      keysToConnectToCVE.forEach(key => {
        edges.push({
          source: key,
          target: 'CVE',
          label: {
            show: true,
            formatter: () => ''
          },
          lineStyle: {
            color: '#666666',
            opacity: 0.7,
            curveness: 0.5,
            width: 1,
          },
          symbol: ['none', 'arrow'],
          symbolSize: [6, 10],
        });
      });

      commit.forEach(commit => {
        const shortCommit = commit.slice(0, 7);
        if (!allValues.has(shortCommit)) {
          const commitNode = {
            name: shortCommit,
            symbolSize: 20,
            itemStyle: {
              color: nodeColors['commit'],
              shadowBlur: 10,
              shadowColor: 'rgba(0, 0, 0, 0.3)',
              shadowOffsetX: 0,
              shadowOffsetY: 5
            }
          };
          if (!nodes.some(node => node.name === shortCommit)) {
            nodes.push(commitNode);
          }
          edges.push({
            source: shortCommit,
            target: 'CVE',
            label: {
              show: false,
              formatter: () => ''
            },
            lineStyle: {
              color: '#666666',
              opacity: 0.7,
              curveness: 0.5,
              width: 1,
            },
            symbol: ['none', 'arrow'],
            symbolSize: [6, 10],
          });
        }
      });

      edges.forEach(edge => {
        if (edge.label.formatter() === 'mirror') {
          edge.lineStyle.type = 'dashed';
          edge.lineStyle.dashArray = [5, 5];
          edge.symbol = ['none', 'none'];
        }
      });

      const option = {
        title: {
          text: 'Relationship Graph',
          left: 'center'
        },
        tooltip: {},
        animationDurationUpdate: 1500,
        animationEasingUpdate: 'quinticInOut',
        series: [{
          type: 'graph',
          layout: 'circular',
          data: nodes.map(node => {
            return {
              name: node.name,
              symbolSize: node.symbolSize,
              itemStyle: node.itemStyle,
              label: {
                show: true,
                formatter: function (params) {
                  return params.name.replace(':-', '');
                },
                position: 'bottom'
              }
            };
          }),
          links: edges,
          lineStyle: function (params) {
            return params.lineStyle || {
              width: 1
            };
          },
          roam: true,
          focusNodeAdjacency: true
        }]
      };

      chart.setOption(option);
    },
    Edit(index, row) {
      this.editFormVisible = true;
      this.detailForm = Object.assign({}, row);
    },
    Submit() {
      this.submitVisible = true;
      this.editFormVisible = false;
      this.deleteVisible = false;
    },
    remoteMethod() {
      this.selectLoading = false;
    },

  },
  mounted() {
    this.getCVEs();
  }
};
</script>

<style scoped>
.toolbar {
  background: #ffffff;
  padding: 10px;
  margin: 10px 0px;
  border: 1px solid #e4e7ed;
  border-radius: 4px;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
}

.toolbar .el-form-item {
  margin-right: 10px;
  margin-bottom: 10px;
}

.toolbar .el-input {
  width: 200px;
}

.toolbar .el-select {
  width: 200px;
}

table {
  margin-top: 20px;
  border: 1px solid #e4e7ed;
}

th,
td {
  border: 1px solid #e4e7ed;
  padding: 8px;
  text-align: center;
}

.custom-detail-container {
  padding: 20px;
  background-color: #f9f9f9;
  border-radius: 8px;
  box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
}

.custom-detail-row {
  display: flex;
  margin-bottom: 15px;
}

.custom-detail-label {
  width: 120px;
  font-weight: bold;
  color: #333;
}

.custom-detail-value {
  flex: 1;
  color: #666;
}
</style>
