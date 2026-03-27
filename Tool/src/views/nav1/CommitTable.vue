<template>
  <section>
    <el-row :gutter="20">
      <el-col :span="4" class="sidebar">
        <el-menu :default-active="activeIndex" class="el-menu-vertical-demo" @select="handleSelect">
          <div class="nav-title-container">
            <div class="nav-title">COMPASS</div>
          </div>
          <el-menu-item index="1">
            <i class="el-icon-plus"></i>
            <span slot="title">Input CVE</span>
          </el-menu-item>
          <el-menu-item index="2">
            <i class="el-icon-search"></i>
            <span slot="title">Predict Patch</span>
          </el-menu-item>
          <el-menu-item index="3">
            <i class="el-icon-search"></i>
            <span slot="title">Predict Relation</span>
          </el-menu-item>
        </el-menu>
        <div style="position: absolute; bottom: 30px; left: 0; width: 100%; text-align: center;">
          <el-button icon="el-icon-setting" @click="openSetting" size="small">Setting</el-button>
        </div>
      </el-col>

      <el-dialog title="Setting" :visible.sync="settingFormVisible" :close-on-click-modal="false">
        <el-form :model="settingForm" :rules="settingFormRules" ref="settingForm" label-width="200px">
          <el-form-item label="Begin Date" prop="startDate">
            <el-date-picker v-model="settingForm.startDate" type="date" placeholder="half a year before"></el-date-picker>
          </el-form-item>
          <el-form-item label="End Date" prop="endDate">
            <el-date-picker v-model="settingForm.endDate" type="date" placeholder="half a year after"></el-date-picker>
          </el-form-item>
          <el-form-item label="Commit Count" prop="commitCount">
            <el-input-number v-model="settingForm.commitCount" :min="1" :max="100000" :placeholder="1500"></el-input-number>
          </el-form-item>
        </el-form>
        <div slot="footer">
          <el-button @click="settingFormVisible = false">close</el-button>
          <el-button type="primary" @click="saveSetting">save</el-button>
        </div>
      </el-dialog>

      <el-col :span="20" style="padding-top: 20px;">
        <div v-loading="listLoading" element-loading-text="LOADING..." style="margin-bottom: 20px;">
          <div class="table-container">
            <div class="table-title">CVE List</div>
            <table style="width: 100%; border-collapse: collapse;">
              <thead>
                <tr class="table-header">
                  <th style="width: 150px;">CVE ID</th>
                  <th style="width: 125px;">CVE Time</th>
                  <th style="width: 185px;">Warehouse Name</th>
                  <th style="width: 140px;">Patch Num</th>
                  <th style="width: 160px;">CWE ID</th>
                  <th style="width: 240px;">CWE Type</th>
                  <th style="width: 140px;">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(row, index) in CVEs" :key="index" class="table-row">
                  <td>{{ row.cve }}</td>
                  <td>{{ row.cve_time }}</td>
                  <td>{{ row.repo }}</td>
                  <td>{{ row['patch num'] }}</td>
                  <td>{{ row.cwe_id }}</td>
                  <td>{{ row.cwe }}</td>
                  <td>
                    <el-button
                      :type="buttonType(row.patch_gitcommit)"
                      size="small"
                      class="action-btn"
                      @click="Details(index, row)">
                      Details
                    </el-button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div v-loading="listLoading" element-loading-text="LOADING..." style="margin-bottom: 60px; padding-top: 20px;">
          <div class="table-container">
            <div class="table-title">Patch List</div>

            <table v-if="predictionCompleted && showPatchTable && Patches.length > 0" style="width: 100%; border-collapse: collapse;">
              <thead>
                <tr class="table-header">
                  <th style="width: 150px;">Patch</th>
                  <th style="width: 125px;">Time</th>
                  <th style="width: 185px;">Author</th>
                  <th style="width: 140px;">Branch</th>
                  <th style="width: 160px;">Version</th>
                  <th style="width: 240px;">Message</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(row, index) in Patches" :key="index" class="table-row">
                  <td>{{ row.commit.substring(0,7) }}</td>
                  <td>{{ row.commit_time || row.patch_time || 'N/A' }}</td>
                  <td>{{ row.author || 'N/A' }}</td>
                  <td>{{ row.branch || row.branches || 'N/A' }}</td>
                  <td>{{ row.tags || 'N/A' }}</td>
                  <td>{{ row.msg_text || row.message || row.patch_desc || 'N/A' }}</td>
                </tr>
              </tbody>
            </table>

            <div v-else-if="predictionCompleted && ((showPatchTable && Patches.length === 0) || (!showPatchTable && Commits.length === 0))" class="empty-commit-list">
              <el-empty description="No information available"></el-empty>
            </div>
          </div>
        </div>

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
              <div class="custom-detail-value">{{ detailForm.patchid }}</div>
            </div>
            <div class="custom-detail-row">
              <div class="custom-detail-label">Description</div>
              <div class="custom-detail-value">{{ detailForm.desc}}</div>
            </div>
          </div>
        </el-dialog>

        <el-dialog
            title="ADD"
            :visible.sync="newCVEFormVisible"
            :close-on-click-modal="false"
            custom-class="gray-dialog">
          <el-row :gutter="15">
            <el-form ref="elForm" :model="newCVEForm" :rules="newCVEFormRules" size="medium" label-width="100px">
              <el-col :span="12">
                <el-form-item label="CVE" prop="CVE">
                  <el-input
                      v-model="newCVEForm.CVE"
                      placeholder="please enter CVE-ID"
                      :maxlength="50"
                      clearable
                      prefix-icon="el-icon-user-solid"
                      class="gray-input">
                  </el-input>
                </el-form-item>
              </el-col>
              <el-col :span="15">
                <el-form-item label="Repo" prop="Repo">
                  <el-input
                      v-model="newCVEForm.Repo"
                      placeholder="please enter Warehouse Name"
                      :maxlength="50"
                      clearable
                      prefix-icon="el-icon-user-solid"
                      class="gray-input">
                  </el-input>
                </el-form-item>
              </el-col>
            </el-form>
          </el-row>
          <div slot="footer">
            <el-button @click.native="newCVEFormVisible = false" class="gray-button">BACK</el-button>
            <el-button type="primary" @click="addCVE" class="primary-gray-button">OK</el-button>
          </div>
        </el-dialog>

        <el-dialog title="Reminder" :visible.sync="addCVEOKVisible" width="30%">
          <span>Add successed</span>
          <span slot="footer" class="dialog-footer">
            <el-button type="primary" @click="addNewCVEOK">OK</el-button>
          </span>
        </el-dialog>

        <div v-loading="addCVELoading" element-loading-text="Selecting CVE......"></div>
        <div v-loading="predictLoading" element-loading-text="Predicting......"></div>
      </el-col>
    </el-row>

    <el-dialog title="Graph" :visible.sync="graphDialogVisible" :close-on-click-modal="false">
      <div class="custom-detail-container" style="width: 94%; height: 460px;">
        <div id="Graph" style="width: 1000%; height: 500px;"></div>
      </div>
    </el-dialog>
  </section>
</template>

<script>
import util from "../../common/js/util";
import echarts from 'echarts';
import { getCVEListPage, removeUser, batchRemoveUser, addNewCVE, getPredictRank } from "../../api/api";
import { addCVE } from "../../api/api";
import { addCommit } from "../../api/api";

export default {
  data() {
    return {
      activeIndex: '1',
      filters: {
        CVE: "",
        repoid: "",
      },
      CVEs: [],
      Patches: [],
      Commits: [],
      page_size: 20,
      total: 0,
      page: 1,
      listLoading: false,
      sels: [],
      detailFormVisible: false,
      newCVEFormVisible: false,
      addCVEOKVisible: false,
      editLoading: false,
      graphDialogVisible: false,
      detailFormRules: {
        name: [{ required: true, message: "Please enter name", trigger: "blur" }]
      },
      detailForm: {},
      PatchRelation: {},
      newCVEForm: {
        CVE: '',
        Repo: ''
      },
      newCVEFormRules: {
        CVE: [{ required: true, message: 'please enter CVE-ID', trigger: 'blur' }],
        Repo: [{ required: true, message: 'please enter Warehouse Name', trigger: 'blur' }]
      },
      backmsg: "",
      selectLoading: false,
      addCVELoading: false,
      predictLoading: false,
      relationLoading: false,
      settingFormVisible: false,
      settingForm: {
        startDate: '',
        endDate: '',
        commitCount: 1500
      },
      settingFormRules: {
        startDate: [{ type: 'date', required: false, message: 'Please select start date', trigger: 'change' }],
        endDate: [{ type: 'date', required: false, message: 'Please select end date', trigger: 'change' }],
        commitCount: [{ type: 'number', required: false, message: 'Please enter commit count', trigger: 'blur' }]
      },
      settingsInitialized: false,
      defaultSettings: {
        commitCount: 1500,
        startDate: '',
        endDate: ''
      },
      predictionCompleted: false,
      showPatchTable: true,
    };
  },
  methods: {
    handleSelect(key, keyPath) {
      if (key === '1') {
        this.newCVE();
      } else if (key === '2') {
        if (this.CVEs.length > 0) {
          this.predict();
        }
      } else if (key === '3') {
        if (this.CVEs.length > 0) {
          if (this.Patches.length > 0){
            const firstCVE = this.CVEs[0].cve;
            this.showGraph();
          }
        }
      }
    },
    buttonType(str) {
      if (str === "" || str === null) {
        return "warning";
      } else {
        return "success";
      }
    },
    jump(msg) {
      console.log(msg);
      this.$router.push({
        path: '/predict',
        name: 'PredictCommitForCVE',
        params: {
          datacve: msg,
        }
      });
    },
    handleCurrentChange(val) {
      this.page = val;
    },
    Details: function (index, row) {
      this.detailFormVisible = true;
      this.detailForm = Object.assign({}, row);
      this.detailForm.patchid = row.patchid;
      if (row.desc) this.detailForm.desc = row.desc;
    },
    openSetting() {
      this.settingFormVisible = true;
      if (!this.settingsInitialized && this.CVEs.length > 0) {
        this.setDefaultDatesBasedOnCVE();
      }
    },
    saveSetting() {
      this.settingFormVisible = false;
      this.settingsInitialized = true;
      this.defaultSettings = {
        commitCount: this.settingForm.commitCount,
        startDate: this.settingForm.startDate,
        endDate: this.settingForm.endDate
      };
    },
    parseCveDate(cveTimeStr) {
      if (!cveTimeStr || typeof cveTimeStr !== 'string' || cveTimeStr.length !== 8) {
        console.error('Invalid CVE time format:', cveTimeStr);
        return null;
      }

      const year = parseInt(cveTimeStr.substr(0, 4), 10);
      const month = parseInt(cveTimeStr.substr(4, 2), 10) - 1;
      const day = parseInt(cveTimeStr.substr(6, 2), 10);

      const date = new Date(year, month, day);
      if (isNaN(date.getTime())) {
        console.error('Invalid date:', year, month + 1, day);
        return null;
      }

      return date;
    },
    setDefaultDatesBasedOnCVE() {
      if (this.CVEs && this.CVEs.length > 0) {
        const cveTime = this.CVEs[0].cve_time;
        if (cveTime) {
          const cveDate = this.parseCveDate(cveTime);

          if (cveDate) {
            this.settingForm.startDate = this.getDateBefore(cveDate, 6);
            this.settingForm.endDate = this.getDateAfter(cveDate, 6);
            this.settingForm.commitCount = 1500;
            this.settingsInitialized = true;
            this.defaultSettings = {
              commitCount: 1500,
              startDate: this.settingForm.startDate,
              endDate: this.settingForm.endDate
            };

            return;
          }
        }
      }

      this.settingForm.startDate = this.getDefaultStartDate();
      this.settingForm.endDate = this.getDefaultEndDate();
      this.settingForm.commitCount = 1500;
      this.settingsInitialized = true;
      this.defaultSettings = {
        commitCount: 1500,
        startDate: this.settingForm.startDate,
        endDate: this.settingForm.endDate
      };
    },

    getDateBefore(date, months) {
      const result = new Date(date);
      result.setMonth(result.getMonth() - months);
      return this.formatDate(result);
    },

    getDateAfter(date, months) {
      const result = new Date(date);
      result.setMonth(result.getMonth() + months);
      return this.formatDate(result);
    },

    formatDate(date) {
      if (!date) return '';

      if (typeof date === 'string') {
        return date;
      }

      if (date instanceof Date && !isNaN(date.getTime())) {
        const year = date.getFullYear();
        const month = (date.getMonth() + 1).toString().padStart(2, '0');
        const day = date.getDate().toString().padStart(2, '0');
        return `${year}-${month}-${day}`;
      }

      console.error('Invalid date format:', date);
      return '';
    },

    getDefaultStartDate() {
      let now = new Date();
      now.setMonth(now.getMonth() - 6);
      return this.formatDate(now);
    },

    getDefaultEndDate() {
      let now = new Date();
      now.setMonth(now.getMonth() + 6);
      return this.formatDate(now);
    },

    toggleTableView() {
      this.showPatchTable = !this.showPatchTable;
    },

    predict() {
      this.predictLoading = true;
      this.showPatchTable = true;
      this.predictionCompleted = false;
      this.Commits = [];
      this.Patches = [];

      if (!this.settingsInitialized) {
        this.setDefaultDatesBasedOnCVE();
      }

      let commitCount = this.settingForm.commitCount || this.defaultSettings.commitCount || 1500;

      let startDate;
      if (this.settingForm.startDate) {
        startDate = this.formatDate(this.settingForm.startDate);
      } else if (this.defaultSettings.startDate) {
        startDate = this.formatDate(this.defaultSettings.startDate);
      } else {
        startDate = this.getDefaultStartDate();
      }

      let endDate;
      if (this.settingForm.endDate) {
        endDate = this.formatDate(this.settingForm.endDate);
      } else if (this.defaultSettings.endDate) {
        endDate = this.formatDate(this.defaultSettings.endDate);
      } else {
        endDate = this.getDefaultEndDate();
      }

      if (!startDate || !endDate || !commitCount) {
        console.error('Invalid prediction parameters:', { startDate, endDate, commitCount });
        this.$message.error('Invalid prediction parameters');
        this.predictLoading = false;
        return;
      }

      let para = {
        cve: this.CVEs[0].cve,
        repo: this.CVEs[0].repo,
        commitCount,
        startDate,
        endDate
      };

      addCommit(para)
        .then(res => {
          this.Commits = res.data.infos.map(item => ({
            commit: item.commit,
            commit_time: item.commit_time,
            author: item.author,
            branch: item.branches,
            tags: item.tags,
            msg_text: item.msg_text
          }));
          this.Patches = this.Commits;
          this.predictionCompleted = true;
        })
        .catch(error => {
          console.error('Error during prediction:', error);
          this.$message.error('Prediction failed');
        })
        .finally(() => {
          this.predictLoading = false;
        });
    },

    randomDate: function(start, end) {
      const startDate = new Date(start);
      const endDate = new Date(end);
      const randomTime = startDate.getTime() + Math.random() * (endDate.getTime() - startDate.getTime());
      return this.formatDate(new Date(randomTime));
    },
    newCVE: function (index, row) {
      this.newCVEFormVisible = true;
    },
    addCVE: function () {
      this.addCVELoading = true;
      let para = {
        CVE: this.newCVEForm.CVE,
        Repo: this.newCVEForm.Repo,
      };
      addCVE(para)
        .then(res => {
          const { cvetime, cwe_id, cwe_type, patch_links, patch_num, desc } = res.data.infos;
          const newCVE = {
            cve: this.newCVEForm.CVE,
            repo: this.newCVEForm.Repo,
            cve_time: cvetime,
            'patch num': patch_num,
            cwe_id: cwe_id,
            cwe: cwe_type,
            desc: desc,
            patchid: patch_links
          };
          this.CVEs.push(newCVE);
          this.setDefaultDatesBasedOnCVE();
        })
        .catch(error => {
          console.error('Error adding CVE:', error);
          this.$message.error('Failed to add CVE');
        })
        .finally(() => {
          this.addCVELoading = false;
          this.newCVEFormVisible = false;
          this.addCVEOKVisible = true;
        });
    },
    addNewCVEOK: function () {
      this.addCVEOKVisible = false;
    },
    selsChange: function (row) {
      if (this.sels.includes(row)) {
        this.sels = this.sels.filter(item => item !== row);
      } else {
        this.sels.push(row);
      }
    },
    showGraph() {
      this.relationLoading = true;
      let para = {
        CVE: this.CVEs[0].cve,
        repo: this.CVEs[0].repo,
      };
      getCVEListPage(para).then(res => {
        this.backmsg = res.data.infos;
        this.PatchRelation = res.data.infos;
        this.graphDialogVisible = true;
        this.$nextTick(() => {
          this.drawRelationshipGraph();
        });
      }).finally(() => {
        this.relationLoading = false;
      });
    },
    batchRemove: function () {
      var ids = this.sels.map(item => item.id).toString();
      this.$confirm("Confirm delete all selected users?", "Tips", {
        type: "warning"
      })
          .then(() => {
            this.listLoading = true;
            let para = { ids: ids };
            batchRemoveUser(para).then(res => {
              this.listLoading = false;
              let { msg, code } = res.data;
              if (code !== 200) {
                this.$message({
                  message: msg,
                  type: "warning"
                });
              } else {
                this.$message({
                  message: msg,
                  type: "success"
                });
              }
              this.CVEs = [];
              this.Patches = [];
              this.Commits = [];
              this.settingsInitialized = false;
              this.defaultSettings = {
                commitCount: 1500,
                startDate: '',
                endDate: ''
              };
              this.predictionCompleted = false;
              this.showPatchTable = true;
            });
          })
          .catch(() => {});
    },

    remoteMethod() {
      this.selectLoading = false;
    },
    drawRelationshipGraph() {
      const chartDom = document.getElementById('Graph');
      if (!chartDom) return;
      
      const myChart = echarts.init(chartDom);
      myChart.clear();

      let nodes = [];
      let links = [];
      let existNodes = new Set();

      if (this.CVEs && this.CVEs.length > 0) {
        const cveId = this.CVEs[0].cve;
        nodes.push({
          name: cveId,
          symbolSize: 50,
          itemStyle: { color: '#F56C6C' },
          label: { show: true }
        });
        existNodes.add(cveId);
      }

      this.Patches.forEach((patch, index) => {
        let name = patch.commit ? patch.commit.substring(0, 7) : patch.patch_id;
        if (!name) return;
        
        if (!existNodes.has(name)) {
          nodes.push({
            name: name,
            symbolSize: 30,
            itemStyle: { color: '#409EFF' },
          });
          existNodes.add(name);
        }

        if (this.CVEs[0].cve) {
           links.push({
             source: this.CVEs[0].cve,
             target: name,
             lineStyle: { width: 1, color: '#e0e0e0' }
           });
        }
      });

      const parsePyString = (str) => {
        if (!str || str === '{}' || str === '[]') return {};
        try {
          return JSON.parse(str.replace(/'/g, '"'));
        } catch (e) {
          console.error("Failed to parse relation data:", str, e);
          return {};
        }
      };

      let relationObj = this.PatchRelation;
      if (Array.isArray(this.PatchRelation) && this.PatchRelation.length > 0) {
        relationObj = this.PatchRelation[0];
      }

      if (relationObj) {
        const relationConfig = [
          { key: 'better', color: '#67C23A', label: 'better' },
          { key: 'merge',  color: '#E6A23C', label: 'merge' },
          { key: 'separate', color: '#909399', label: 'separate' }
        ];

        relationConfig.forEach(config => {
          if (relationObj[config.key]) {
            const relationData = parsePyString(relationObj[config.key]);
            
            Object.keys(relationData).forEach(sourceHash => {
              const targetList = relationData[sourceHash];
              const sourceName = sourceHash.substring(0, 7);

              if (!existNodes.has(sourceName)) {
                nodes.push({ name: sourceName, symbolSize: 20, itemStyle: { color: '#C0C4CC' } });
                existNodes.add(sourceName);
              }

              if (Array.isArray(targetList)) {
                targetList.forEach(targetHash => {
                  const targetName = targetHash.substring(0, 7);
                  
                  if (!existNodes.has(targetName)) {
                    nodes.push({ name: targetName, symbolSize: 20, itemStyle: { color: '#C0C4CC' } });
                    existNodes.add(targetName);
                  }

                  links.push({
                    source: sourceName,
                    target: targetName,
                    label: {
                      show: true,
                      formatter: config.label,
                      fontSize: 10,
                      color: config.color
                    },
                    lineStyle: {
                      color: config.color,
                      type: 'dashed',
                      width: 2,
                      curveness: 0.2
                    },
                    symbol: ['none', 'arrow'],
                    symbolSize: [0, 8]
                  });
                });
              }
            });
          }
        });
      }


      const option = {
        title: {
          text: 'CVE-Patch Relationship',
          left: 'center'
        },
        tooltip: {},
        series: [
          {
            type: 'graph',
            layout: 'force',
            data: nodes,
            links: links,
            roam: true,
            label: {
              position: 'right',
              show: true,
              formatter: '{b}'
            },
            force: {
              repulsion: 1000,
              edgeLength: 120
            }
          }
        ]
      };

      myChart.setOption(option);
    }
  },

  mounted() {
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

.table-container {
  background-color: white;
  border-radius: 12px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.06);
  overflow: hidden;
  margin-bottom: 20px;
}

.table-title {
  padding: 16px 20px;
  background-color: #e6e8eb;
  border-bottom: 1px solid #ebedf0;
  font-size: 18px;
  font-weight: 600;
  color: #333;
}

.table-header {
  background-color: #f8f9fa;
}

.table-header th {
  padding: 16px 8px;
  font-weight: 600;
  color: #333;
  border-bottom: 2px solid #e9ecef;
  text-align: center;
}

.table-row {
  background-color: #ffffff;
  transition: all 0.2s ease;
}

.table-row:hover {
  background-color: #f0f2f5;
}

.table-row:last-child td {
  border-bottom: none;
}

td, th {
  padding: 14px 8px;
  text-align: center;
  border-bottom: 1px solid #ebedf0;
  color: #666;
}

.action-btn {
  border-radius: 4px;
  padding: 4px 12px;
  font-size: 12px;
}

.sidebar {
  height: 100vh;
  background-color: #F2F2F2 !important;
  padding: 10px;
}

.el-menu-item {
  background-color: #F2F2F2 !important;
  color: #333 !important;
  padding: 00px;
  margin-left: 15px;
}

.el-menu-item:hover {
  background-color: #E0E0E0 !important;

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

:deep(.gray-dialog) {
  background-color: #F2F2F2;
}

:deep(.gray-dialog .el-dialog__header) {
  background-color: #E0E0E0;
  padding: 15px 20px;
}

:deep(.gray-dialog .el-dialog__title) {
  color: #333333;
  font-weight: bold;
}

:deep(.gray-dialog .el-dialog__body) {
  background-color: #F2F2F2;
  padding: 20px;
}

:deep(.gray-dialog .el-dialog__footer) {
  background-color: #E0E0E0;
  padding: 10px 20px;
}

.gray-input :deep(.el-input__inner) {
  background-color: #FFFFFF;
  border-color: #CCCCCC;
  color: #333333;
}

.gray-input :deep(.el-input__inner:focus) {
  border-color: #666666;
}

.gray-input :deep(.el-input__prefix) {
  color: #666666;
}

.nav-title-container {
  padding: 20px 16px;
  text-align: center;
  margin-bottom: 24px;
  background-color: #F2F2F2 !important;
  border-bottom: 1px solid #e4e7ed;
}

.nav-title {
  font-family: 'Comic Sans MS', cursive;
  font-size: 50px;
  font-weight: bold;
  color: #333;
  text-align: center;
  letter-spacing: 1px;
}

.gray-button {
  background-color: #E0E0E0;
  border-color: #CCCCCC;
  color: #333333;
}

.gray-button:hover {
  background-color: #D0D0D0;
  border-color: #BBBBBB;
  color: #333333;
}

.primary-gray-button {
  background-color: #666666;
  border-color: #555555;
  color: #FFFFFF;
}

.primary-gray-button:hover {
  background-color: #555555;
  border-color: #444444;
}

.patch-actions {
  display: flex;
  justify-content: flex-end;
  margin-bottom: 10px;
}

.empty-commit-list {
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100px;
  color: #909399;
}

@media (max-width: 1200px) {
  .table-container {
    border-radius: 8px;
    box-shadow: none;
  }

  .table-title {
    padding: 12px 16px;
    font-size: 16px;
  }

  th, td {
    padding: 10px 6px;
    font-size: 14px;
  }

  .patch-actions {
    justify-content: center;
  }
}
</style>
