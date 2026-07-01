import Home from './views/Home.vue'
import CommitTable from './views/nav1/CommitTable.vue'
import CVETable from './views/nav1/CVETable.vue'
import CVEChart from './views/charts/CVEChart.vue'
import BG from './views/BG.vue'
import Predict from './views/Predict.vue'
import Help from './views/Help.vue'

let routes = [
    {
        path: '/',
        redirect: '/committable'
    },
    {
        path: '/predict',
        component: Predict,
        name: 'PredictCommitForCVE',
        hidden: true
    },
    {
        path: '/',
        component: BG,
        name: 'Home',
        leaf: true,
        iconCls: 'fa fa-home',
        children: [
            { path: '/Home', component: Home, name: 'Home' }
        ]
    },
    {
        path: '/',
        component: BG,
        name: 'ChartCVE',
        leaf: true,
        iconCls: 'fa fa-id-card-o',
        children: [
            { path: '/CVEchart', component: CVEChart, name: 'CVE Information' }
        ]
    },
    {
        path: '/',
        component: BG,
        name: 'TableCommit',
        leaf: true,
        iconCls: 'fa fa-bar-chart',
        children: [
            { path: '/committable', component: CommitTable, name: 'Commit List' }
        ]
    },
    {
        path: '/',
        component: BG,
        name: 'TableCVE',
        leaf: true,
        iconCls: 'fa fa-bar-chart',
        children: [
            { path: '/CVEtable', component: CVETable, name: 'CVE List' }
        ]
    },
    {
        path: '/',
        component: BG,
        name: 'Help',
        leaf: true,
        iconCls: 'fa fa-info-circle',
        children: [
            { path: '/Help', component: Help, name: 'Help' }
        ]
    },
];

export default routes;