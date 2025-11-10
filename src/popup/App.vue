<template>
  <div class="security-popup">
    <!-- 头部 -->
    <div class="header">
      <div class="logo">
        <el-icon size="24" color="#667eea"><Lock /></el-icon>
        <h1>安全守护者</h1>
      </div>
      <div class="status">
        <el-badge :value="blockedThreatsToday" class="badge">
          <el-button :type="isActive ? 'success' : 'danger'" size="small" circle>
            <el-icon><Check v-if="isActive" /><Close v-else /></el-icon>
          </el-button>
        </el-badge>
      </div>
    </div>

    <!-- 安全评分 -->
    <div class="security-score">
      <el-progress 
        type="circle" 
        :percentage="securityScore" 
        :color="getScoreColor(securityScore)"
        :width="80"
      >
        <template #default="{ percentage }">
          <span class="score-text">{{ percentage }}</span>
        </template>
      </el-progress>
      <div class="score-info">
        <h3>安全评分</h3>
        <p>{{ getScoreDescription(securityScore) }}</p>
      </div>
    </div>

    <!-- 当前页面信息 -->
    <div class="current-page">
      <h3>当前页面</h3>
      <div class="page-info">
        <div class="url">{{ currentUrl }}</div>
        <div class="badges">
          <el-tag :type="isHttps ? 'success' : 'warning'" size="small">
            {{ isHttps ? 'HTTPS' : 'HTTP' }}
          </el-tag>
          <el-tag :type="threatLevel" size="small">
            {{ threatStatus }}
          </el-tag>
        </div>
      </div>
    </div>

    <!-- 统计信息 -->
    <div class="stats">
      <div class="stat-item">
        <div class="stat-number">{{ stats.blockedThreats }}</div>
        <div class="stat-label">已阻止威胁</div>
      </div>
      <div class="stat-item">
        <div class="stat-number">{{ stats.totalThreats }}</div>
        <div class="stat-label">检测到威胁</div>
      </div>
      <div class="stat-item">
        <div class="stat-number">{{ blockedThreatsToday }}</div>
        <div class="stat-label">今日阻止</div>
      </div>
    </div>

    <!-- 最近威胁 -->
    <div class="recent-threats" v-if="recentThreats.length > 0">
      <h3>最近威胁</h3>
      <div class="threat-list">
        <div 
          v-for="threat in recentThreats.slice(0, 3)" 
          :key="threat.id" 
          class="threat-item"
        >
          <el-icon :color="getThreatColor(threat.level)">
            <Warning />
          </el-icon>
          <div class="threat-info">
            <div class="threat-title">{{ getThreatTitle(threat.type) }}</div>
            <div class="threat-time">{{ formatTime(threat.timestamp) }}</div>
          </div>
          <el-tag :type="threat.blocked ? 'success' : 'warning'" size="small">
            {{ threat.blocked ? '已阻止' : '已检测' }}
          </el-tag>
        </div>
      </div>
    </div>

    <!-- 操作按钮 -->
    <div class="actions">
      <el-button 
        type="primary" 
        @click="scanCurrentPage"
        :loading="isScanning"
        style="flex: 1"
      >
        <el-icon><Search /></el-icon>
        扫描当前页面
      </el-button>
      <el-button @click="openOptions">
        <el-icon><Setting /></el-icon>
        设置
      </el-button>
    </div>

    <!-- 快速开关 -->
    <div class="quick-toggles">
      <div class="toggle-item">
        <span>恶意URL防护</span>
        <el-switch v-model="settings.maliciousUrlProtection" @change="updateSetting" />
      </div>
      <div class="toggle-item">
        <span>XSS防护</span>
        <el-switch v-model="settings.xssProtection" @change="updateSetting" />
      </div>
      <div class="toggle-item">
        <span>追踪器阻止</span>
        <el-switch v-model="settings.trackerBlocking" @change="updateSetting" />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useSecurityStore } from '../stores/security'
import { 
  Lock, Check, Close, Warning, Search, Setting 
} from '@element-plus/icons-vue'

const securityStore = useSecurityStore()

// 响应式数据
const isScanning = ref(false)
const currentUrl = ref('加载中...')
const isHttps = ref(false)
const currentFullUrl = ref('')

// 计算属性
const isActive = computed(() => securityStore.isActive)
const securityScore = computed(() => securityStore.securityScore)
const settings = computed(() => securityStore.settings)

// 获取当前页面的hostname
const currentHostname = computed(() => {
  try {
    return new URL(currentFullUrl.value).hostname
  } catch {
    return currentUrl.value
  }
})

// 过滤当前页面的威胁
const currentPageThreats = computed(() => {
  const hostname = currentHostname.value
  return securityStore.threats.filter(threat => {
    try {
      const threatHostname = new URL(threat.url).hostname
      return threatHostname === hostname
    } catch {
      return threat.url.includes(hostname)
    }
  })
})

// 当前页面最近的威胁（最多显示3条）
const recentThreats = computed(() => {
  return currentPageThreats.value.slice(0, 10)
})

// 当前页面的统计数据
const stats = computed(() => {
  const pageThreats = currentPageThreats.value
  const statsData = {
    totalThreats: pageThreats.length,
    blockedThreats: pageThreats.filter(t => t.blocked).length,
    allowedThreats: pageThreats.filter(t => !t.blocked).length,
    threatsByType: {} as any,
    threatsByLevel: {} as any,
    lastScanTime: Date.now()
  }
  
  // 统计类型
  pageThreats.forEach(threat => {
    if (!statsData.threatsByType[threat.type]) {
      statsData.threatsByType[threat.type] = 0
    }
    statsData.threatsByType[threat.type]++
  })
  
  // 统计等级
  pageThreats.forEach(threat => {
    if (!statsData.threatsByLevel[threat.level]) {
      statsData.threatsByLevel[threat.level] = 0
    }
    statsData.threatsByLevel[threat.level]++
  })
  
  return statsData
})

// 今日阻止的威胁（当前页面）
const blockedThreatsToday = computed(() => {
  const today = new Date()
  today.setHours(0, 0, 0, 0)
  const todayTimestamp = today.getTime()
  
  return currentPageThreats.value.filter(threat => 
    threat.blocked && threat.timestamp >= todayTimestamp
  ).length
})

const threatLevel = computed(() => {
  if (securityScore.value >= 90) return 'success'
  if (securityScore.value >= 70) return 'warning'
  return 'danger'
})

const threatStatus = computed(() => {
  if (securityScore.value >= 90) return '安全'
  if (securityScore.value >= 70) return '注意'
  return '危险'
})

// 方法
function getScoreColor(score: number) {
  if (score >= 90) return '#67c23a'
  if (score >= 70) return '#e6a23c'
  return '#f56c6c'
}

function getScoreDescription(score: number) {
  if (score >= 90) return '网站安全性良好'
  if (score >= 70) return '存在一些安全风险'
  return '发现严重安全问题'
}

function getThreatColor(level: string) {
  const colors = {
    low: '#909399',
    medium: '#e6a23c',
    high: '#f56c6c',
    critical: '#f56c6c'
  }
  return colors[level as keyof typeof colors] || '#909399'
}

function getThreatTitle(type: string) {
  const titles = {
    malicious_url: '恶意URL',
    xss_attack: 'XSS攻击',
    tracker: '隐私追踪',
    insecure_form: '不安全表单',
    suspicious_script: '可疑脚本',
    phishing: '钓鱼网站'
  }
  return titles[type as keyof typeof titles] || '未知威胁'
}

function formatTime(timestamp: number) {
  const now = Date.now()
  const diff = now - timestamp
  const minutes = Math.floor(diff / 60000)
  
  if (minutes < 1) return '刚刚'
  if (minutes < 60) return `${minutes}分钟前`
  
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}小时前`
  
  const days = Math.floor(hours / 24)
  return `${days}天前`
}

async function scanCurrentPage() {
  isScanning.value = true
  try {
    await securityStore.scanCurrentPage()
  } catch (error) {
    console.error('扫描失败:', error)
  } finally {
    isScanning.value = false
  }
}

function openOptions() {
  if (typeof chrome !== 'undefined' && chrome.runtime) {
    chrome.runtime.openOptionsPage()
  }
}

async function updateSetting() {
  try {
    await securityStore.updateSettings(settings.value)
  } catch (error) {
    console.error('更新设置失败:', error)
  }
}

async function getCurrentPageInfo() {
  try {
    if (typeof chrome !== 'undefined' && chrome.tabs) {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
      if (tab.url) {
        currentFullUrl.value = tab.url
        currentUrl.value = new URL(tab.url).hostname
        isHttps.value = tab.url.startsWith('https://')
        
        // 根据页面安全状况计算评分
        await calculatePageScore(tab.url)
      }
    }
  } catch (error) {
    console.error('获取页面信息失败:', error)
    currentUrl.value = '无法获取'
  }
}

async function calculatePageScore(url: string) {
  let score = 100
  
  // 获取当前页面的hostname
  let currentHostname = ''
  try {
    currentHostname = new URL(url).hostname
  } catch {
    currentHostname = url
  }
  
  // 从统计数据中获取威胁信息
  const stats = securityStore.stats
  const allThreats = securityStore.recentThreats
  
  // 只计算当前页面的威胁（根据URL匹配）
  const currentPageThreats = allThreats.filter(threat => {
    try {
      const threatHostname = new URL(threat.url).hostname
      return threatHostname === currentHostname
    } catch {
      return threat.url.includes(currentHostname)
    }
  })
  
  // 根据威胁等级扣分（只计算当前页面的威胁）
  currentPageThreats.forEach(threat => {
    switch (threat.level) {
      case 'critical':
        score -= 30
        break
      case 'high':
        score -= 20
        break
      case 'medium':
        score -= 10
        break
      case 'low':
        score -= 5
        break
    }
  })
  
  // 检查HTTPS（非本地环境）
  const isLocalDev = url.includes('localhost') || url.includes('127.0.0.1')
  if (!url.startsWith('https://') && !isLocalDev) {
    score -= 15
    console.log('❌ 未使用HTTPS，扣15分')
  }
  
  // 确保分数在0-100之间
  score = Math.max(0, Math.min(100, score))
  
  // 更新store中的评分
  securityStore.currentPageAnalysis = {
    url: url,
    score: score,
    threats: currentPageThreats,
    recommendations: score < 90 ? 
      ['发现安全威胁，建议谨慎操作'] : 
      ['网站安全性良好'],
    scanTime: Date.now(),
    isSecure: score >= 90
  }
  
  console.log(`🔍 页面安全评分: ${score}`)
  console.log(`📊 当前页面威胁: ${currentPageThreats.length} / 总威胁: ${allThreats.length}`)
}

// 监听storage变化
function setupStorageListener() {
  if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName === 'local') {
        console.log('📦 Storage changed:', changes)
        
        // 重新加载数据
        if (changes.security_stats || changes.threat_history) {
          securityStore.loadStats()
          securityStore.loadThreats()
          
          // 重新计算评分
          if (currentFullUrl.value) {
            calculatePageScore(currentFullUrl.value)
          }
        }
      }
    })
  }
}

// 监听标签页切换
function setupTabListener() {
  if (typeof chrome !== 'undefined' && chrome.tabs) {
    chrome.tabs.onActivated.addListener(async () => {
      console.log('🔄 Tab switched, refreshing page info')
      await getCurrentPageInfo()
    })
  }
}

// 生命周期
onMounted(async () => {
  await securityStore.initialize()
  await getCurrentPageInfo()
  setupStorageListener()
  setupTabListener()
})
</script>

<style scoped>
.security-popup {
  padding: 16px;
  background: #f8f9fa;
  min-height: 500px;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding: 12px 16px;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  border-radius: 8px;
  color: white;
}

.logo {
  display: flex;
  align-items: center;
  gap: 8px;
}

.logo h1 {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
}

.security-score {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 20px;
  padding: 16px;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.score-info h3 {
  margin: 0 0 4px 0;
  font-size: 14px;
  color: #333;
}

.score-info p {
  margin: 0;
  font-size: 12px;
  color: #666;
}

.score-text {
  font-size: 16px;
  font-weight: bold;
}

.current-page {
  margin-bottom: 20px;
  padding: 16px;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.current-page h3 {
  margin: 0 0 12px 0;
  font-size: 14px;
  color: #333;
}

.page-info .url {
  font-size: 12px;
  color: #666;
  margin-bottom: 8px;
  word-break: break-all;
}

.badges {
  display: flex;
  gap: 8px;
}

.stats {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
  margin-bottom: 20px;
}

.stat-item {
  text-align: center;
  padding: 12px;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.stat-number {
  font-size: 20px;
  font-weight: bold;
  color: #667eea;
  margin-bottom: 4px;
}

.stat-label {
  font-size: 11px;
  color: #666;
}

.recent-threats {
  margin-bottom: 20px;
  padding: 16px;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.recent-threats h3 {
  margin: 0 0 12px 0;
  font-size: 14px;
  color: #333;
}

.threat-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.threat-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px;
  background: #f8f9fa;
  border-radius: 4px;
}

.threat-info {
  flex: 1;
}

.threat-title {
  font-size: 12px;
  color: #333;
  margin-bottom: 2px;
}

.threat-time {
  font-size: 10px;
  color: #999;
}

.actions {
  display: flex;
  gap: 8px;
  margin-bottom: 20px;
}

.quick-toggles {
  padding: 16px;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.toggle-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 0;
  font-size: 13px;
}

.toggle-item:not(:last-child) {
  border-bottom: 1px solid #f0f0f0;
}
</style>

