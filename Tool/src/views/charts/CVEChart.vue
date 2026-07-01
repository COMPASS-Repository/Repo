<template>
  <section class="chart-container">
    <div class="chart-line-container">
      <div id="chartLine" style="width:100%; height:600px;"></div>
    </div>
    <div class="chart-circle-container">
      <div id="chartCircle" style="width:100%; height:600px;"></div>
    </div>
  </section>
</template>

<script>
import echarts from "echarts";
import { getCVELineChart, getCVECircleChart } from "../../api/api";

export default {
  data() {
    return {
      chartLine: null,
      chartCircle: null
    }
  },
  methods: {
    drawLineChart() {
      this.chartLine = echarts.init(document.getElementById("chartLine"));
      getCVELineChart().then(res => {
        let { value, total, time, code } = res.data;
        if (code !== 200) {
          this.$message({
            message: "Server error",
            type: "warning"
          });
        } else {
          this.chartLine.setOption({
            title: {
              text: 'Distribution of CVE Time',
              left: 'center',
              top: '0%',
              textStyle: {
                color: '#333',
                fontSize: 18,
                fontWeight: 'bold'
              },
              subtextStyle: {
                color: '#666',
                fontSize: 12,
              }
            },
            tooltip: {
              trigger: 'axis',
              axisPointer: {
                type: 'shadow',
                shadowStyle: {
                  color: 'rgba(0, 0, 0, 0.1)',
                  width: '100%',
                  type: 'dashed'
                }
              },
              formatter: function (params) {
                let tip = `<div style="font-size: 14px; color: #333;">${params[0].name}</div>`;
                params.forEach((param) => {
                  tip += `<div style="display: flex; align-items: center; margin-top: 5px;"><span style="display: inline-block; width: 10px; height: 10px; border-radius: 5px; background-color: ${param.color}; margin-right: 5px;"></span>${param.seriesName}: ${param.value}</div>`;
                });
                return tip;
              }
            },
            toolbox: {
              show: true,
              feature: {
                saveAsImage: { show: true },
                dataZoom: { show: true },
                restore: { show: true }
              },
              right: '5%',
              top: '0%'
            },
            legend: {
              data: ['number'],
              textStyle: {
                color: '#333',
                fontSize: 14
              },
              right: '10%',
              top: '10%'
            },
            xAxis: {
              type: "category",
              boundaryGap: false,
              data: time,
              axisLine: {
                lineStyle: {
                  color: '#ccc',
                  width: 1
                }
              },
              axisTick: {
                show: false
              },
              axisLabel: {
                color: '#666',
                fontSize: 14
              }
            },
            yAxis: {
              type: 'value',
              axisLine: {
                lineStyle: {
                  color: '#ccc',
                  width: 1
                }
              },
              axisTick: {
                show: false
              },
              axisLabel: {
                color: '#666',
                fontSize: 14,
                formatter: '{value}'
              },
              splitLine: {
                lineStyle: {
                  color: '#f0f0f0',
                  type: 'dashed'
                }
              }
            },
            series: [
              {
                name: 'number',
                type: 'line',
                smooth: true,
                symbol: 'circle',
                symbolSize: 8,
                itemStyle: {
                  normal: {
                    color: '#FF6B6B',
                    borderColor: '#fff',
                    borderWidth: 2
                  }
                },
                lineStyle: {
                  color: '#FF6B6B',
                  width: 2,
                  type: 'solid'
                },
                areaStyle: {
                  normal: {
                    color: new echarts.graphic.LinearGradient(
                      0, 0, 0, 1,
                      [
                        { offset: 0, color: 'rgba(255, 107, 107, 0.3)' },
                        { offset: 1, color: 'rgba(255, 107, 107, 0)' }
                      ]
                    )
                  }
                },
                data: value
              }
            ],
          });
        }
      });
    },
    drawCircleChart() {
      this.chartCircle = echarts.init(document.getElementById("chartCircle"));
      getCVECircleChart().then(res => {
        let { total, value, code, name } = res.data;
        let sum = 0;
        for (let i = 0; i < value.length; i++) {
          sum += value[i].value * (i + 2);
        }
        let average = (sum / total).toFixed(2);

        if (code !== 200) {
          this.$message({
            message: "Server error",
            type: "warning"
          });
        } else {
          this.chartCircle.setOption({
            color: ['#37A2DA', '#67E0E3', '#9FE6B8', '#FFDB5C', '#FF9F8B', '#E062AE'],
            title: [
              {
                text: 'Distribution of Patch Num',
                left: 'center',
                top: '0%',
                textStyle: {
                  color: '#333',
                  fontSize: 18,
                  fontWeight: 'bold'
                },
                subtextStyle: {
                  color: '#666',
                  fontSize: 12,
                }
              },
              {
                text: `Total: ${total}`,
                left: 'right',
                top: '10%',
                textStyle: {
                  color: '#333',
                  fontSize: 14
                }
              },
              {
                text: `Average: ${average}`,
                left: 'right',
                top: '15%',
                textStyle: {
                  color: '#333',
                  fontSize: 14
                }
              }
            ],
            tooltip: {
              trigger: 'item',
              formatter: function (params) {
                return `<div style="font-size: 14px; color: #333;">Patch Num: ${params.name}</div>
                <div style="margin-top: 5px; color: #333;">Count: ${params.value}</div>
                <div style="margin-top: 5px; color: #333;">Percentage: ${params.percent}%</div>`;
              },
              backgroundColor: 'rgba(255, 255, 255, 0.9)',
              borderColor: '#ccc',
              borderWidth: 1,
              padding: 10
            },
            toolbox: {
              show: true,
              feature: {
                saveAsImage: { show: true },
                dataZoom: { show: true },
                restore: { show: true }
              },
              right: '5%',
              top: '0%'
            },
            legend: {
              orient: "horizontal",
              left: 'center',
              bottom: '5%',
              itemWidth: 12,
              itemHeight: 12,
              textStyle: {
                color: '#333',
                fontSize: 14
              }
            },
            series: [
              {
                name: 'risk score',
                type: 'pie',
                radius: ['0%', '60%'],
                center: ['50%', '50%'],
                avoidLabelOverlap: true,
                itemStyle: {
                  borderRadius: 8,
                  borderColor: '#fff',
                  borderWidth: 1,
                  shadowBlur: 5,
                  shadowColor: 'rgba(0, 0, 0, 0.1)'
                },
                label: {
                  show: true,
                  position: 'outside',
                  formatter: '{b}',
                  fontSize: 14,
                  lineHeight: 20
                },
                labelLine: {
                  show: true,
                  length: 10,
                  length2: 20,
                },
                data: value
              }
            ]
          });
        }
      });
    },
    drawCharts() {
      this.drawLineChart();
      this.drawCircleChart();
    }
  },
  mounted: function () {
    this.drawCharts();
  }
};
</script>

<style scoped>
.chart-container {
  width: 100%;
  display: flex;
  flex-wrap: wrap;
  justify-content: space-around;
}

.chart-line-container,
.chart-circle-container {
  width: 48%;
  margin-bottom: 20px;
  box-sizing: border-box;
  padding: 20px;
  border: 1px solid #e0e0e0;
  border-radius: 5px;
  box-shadow: 0 0 5px rgba(0, 0, 0, 0.1);
}
</style>
