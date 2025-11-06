<template>
  <div class="options-page">
    <div class="header">
      <h1>🛡️ Web Security Guardian 设置</h1>
      <p>配置您的浏览器安全防护选项</p>
    </div>

    <el-tabs v-model="activeTab" class="settings-tabs">
      <!-- 基本设置 -->
      <el-tab-pane label="基本设置" name="general">
        <div class="settings-section">
          <h3>防护功能</h3>
          <div class="setting-group">
            <div class="setting-item">
              <div class="setting-info">
                <h4>恶意URL防护</h4>
                <p>自动检测并阻止访问已知的恶意网站</p>
              </div>
              <el-switch v-model="settings.maliciousUrlProtection" />
            </div>
            
            <div class="setting-item">
              <div class="setting-info">
                <h4>XSS攻击防护</h4>
                <p>检测并阻止跨站脚本攻击</p>
              </div>
              <el-switch v-model="settings.xssProtection" />
            </div>
            
            <div class="setting-item">
              <div class="setting-info">
                <h4>隐私追踪阻止</h4>
                <p>阻止第三方追踪器收集您的数据</p>
              </div>
              <el-switch v-model="settings.trackerBlocking" />
            </div>
            
            <div class="setting-item">
              <div class="setting-info">
                <h4>表单安全检查</h4>
                <p>检查表单提交的安全性</p>
              </div>
              <el-switch v-model="settings.formProtection" />
            </div>
            
            <div class="setting-item">
              <div class="setting-info">
                <h4>钓鱼网站防护</h4>
                <p>识别并警告钓鱼网站</p>
              </div>
              <el-switch v-model="settings.phishingProtection" />
            </div>
          </div>

          <h3>通知设置</h3>
          <div class="setting-group">
            <div class="setting-item">
              <div class="setting-info">
                <h4>安全通知</h4>
                <p>当检测到威胁时显示通知</p>
              </div>
              <el-switch v-model="settings.notifications" />
            </div>
            
            <div class="setting-item">
              <div class="setting-info">
                <h4>严格模式</h4>
                <p>启用更严格的安全检查</p>
              </div>
              <el-switch v-model="settings.strictMode" />
            </div>
          </div>
        </div>
      </el-tab-pane>

      <!-- 统计信息 -->
      <el-tab-pane label="统计信息" name="stats">
        <div class="stats-section">
          <div class="stats-cards">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-number">{{ stats.totalThreats }}</div>
                <div class="stat-label">总威胁数</div>
              </div>
            </el-card>
            
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-number">{{ stats.blockedThreats }}</div>
                <div class="stat-label">已阻止</div>
              </div>
            </el-card>
            
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-number">{{ stats.allowedThreats }}</div>
                <div class="stat-label">已允许</div>
              </div>
            </el-card>
          </div>

          <el-card class="chart-card">
            <h3>威胁类型分布</h3>
            <div class="threat-types">
              <div v-for="(count, type) in stats.threatsByType" :key="type" class="threat-type-item">
                <span class="threat-type-name">{{ getThreatTypeName(type) }}</span>
                <el-progress :percentage="getThreatPercentage(count)" :color="getThreatColor(type)" />
                <span class="threat-count">{{ count }}</span>
              </div>
            </div>
          </el-card>
        </div>
      </el-tab-pane>

      <!-- 威胁历史 -->
      <el-tab-pane label="威胁历史" name="threats">
        <div class="threats-section">
          <div class="threats-header">
            <h3>最近威胁记录</h3>
            <el-button @click="clearThreats" type="danger" size="small">
              清除历史
            </el-button>
          </div>
          
          <el-table :data="recentThreats" style="width: 100%">
            <el-table-column prop="type" label="类型" width="120">
              <template #default="scope">
                <el-tag :type="getThreatTagType(scope.row.level)" size="small">
                  {{ getThreatTypeName(scope.row.type) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="url" label="URL" min-width="200" show-overflow-tooltip />
            <el-table-column prop="description" label="描述" min-width="150" />
            <el-table-column prop="timestamp" label="时间" width="150">
              <template #default="scope">
                {{ formatDateTime(scope.row.timestamp) }}
              </template>
            </el-table-column>
            <el-table-column prop="blocked" label="状态" width="80">
              <template #default="scope">
                <el-tag :type="scope.row.blocked ? 'success' : 'warning'" size="small">
                  {{ scope.row.blocked ? '已阻止' : '已检测' }}
                </el-tag>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-tab-pane>

      <!-- 关于 -->
      <el-tab-pane label="关于" name="about">
        <div class="about-section">
          <el-card>
            <div class="about-content">
              <div class="app-info">
                <h2>🛡️ Web Security Guardian</h2>
                <p class="version">版本 1.0.0</p>
                <p class="description">
                  基于Vue3 + Vite开发的现代化浏览器安全防护插件，
                  为您提供全面的Web应用层安全防护。
                </p>
              </div>
              
              <div class="features">
                <h3>主要功能</h3>
                <ul>
                  <li>🚫 恶意URL检测与阻止</li>
                  <li>⚠️ XSS攻击实时防护</li>
                  <li>👁️ 隐私追踪器阻止</li>
                  <li>🔒 表单安全检查</li>
                  <li>🎣 钓鱼网站识别</li>
                  <li>📊 详细的安全统计</li>
                </ul>
              </div>
              
              <div class="tech-stack">
                <h3>技术栈</h3>
                <div class="tech-tags">
                  <el-tag>Vue 3</el-tag>
                  <el-tag>TypeScript</el-tag>
                  <el-tag>Vite</el-tag>
                  <el-tag>Pinia</el-tag>
                  <el-tag>Element Plus</el-tag>
                  <el-tag>Chrome Extensions API</el-tag>
                </div>
              </div>
            </div>
          </el-card>
        </div>
      </el-tab-pane>
    </el-tabs>

    <div class="footer-actions">
      <el-button @click="saveSettings" type="primary">保存设置</el-button>
      <el-button @click="resetSettings">重置为默认</el-button>
      <el-button @click="exportData">导出数据</el-button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { useSecurityStore } from '../stores/security'

const securityStore = useSecurityStore()
const activeTab = ref('general')

// 计算属性
const settings = computed(() => securityStore.settings)
const stats = computed(() => securityStore.stats)
const recentThreats = computed(() => securityStore.recentThreats)

// 方法
function getThreatTypeName(type: string) {
  const names: Record<string, string> = {
    malicious_url: '恶意URL',
    xss_attack: 'XSS攻击',
    tracker: '隐私追踪',
    insecure_form: '不安全表单',
    suspicious_script: '可疑脚本',
    phishing: '钓鱼网站'
  }
  return names[type] || type
}

function getThreatColor(type: string) {
  const colors: Record<string, string> = {
    malicious_url: '#f56c6c',
    xss_attack: '#e6a23c',
    tracker: '#909399',
    insecure_form: '#67c23a',
    suspicious_script: '#409eff',
    phishing: '#f56c6c'
  }
  return colors[type] || '#909399'
}

function getThreatTagType(level: string) {
  const types: Record<string, string> = {
    low: 'info',
    medium: 'warning',
    high: 'danger',
    critical: 'danger'
  }
  return types[level] || 'info'
}

function getThreatPercentage(count: number) {
  const total = stats.value.totalThreats
  return total > 0 ? Math.round((count / total) * 100) : 0
}

function formatDateTime(timestamp: number) {
  return new Date(timestamp).toLocaleString('zh-CN')
}

async function saveSettings() {
  try {
    await securityStore.updateSettings(settings.value)
    ElMessage.success('设置已保存')
  } catch (error) {
    ElMessage.error('保存设置失败')
  }
}

async function resetSettings() {
  try {
    await securityStore.updateSettings({
      maliciousUrlProtection: true,
      xssProtection: true,
      trackerBlocking: true,
      formProtection: true,
      phishingProtection: true,
      notifications: true,
      autoUpdate: true,
      strictMode: false
    })
    ElMessage.success('设置已重置为默认值')
  } catch (error) {
    ElMessage.error('重置设置失败')
  }
}

async function clearThreats() {
  try {
    await securityStore.clearAllThreats()
    ElMessage.success('威胁历史已清除')
  } catch (error) {
    ElMessage.error('清除历史失败')
  }
}

function exportData() {
  // 导出数据功能
  ElMessage.info('导出功能开发中...')
}

// 生命周期
onMounted(async () => {
  await securityStore.initialize()
})
</script>

<style scoped>
.options-page {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
  background: #f5f5f5;
  min-height: 100vh;
}

.header {
  text-align: center;
  margin-bottom: 30px;
  padding: 20px;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.header h1 {
  margin: 0 0 8px 0;
  color: #333;
}

.header p {
  margin: 0;
  color: #666;
}

.settings-tabs {
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
  padding: 20px;
}

.settings-section h3 {
  margin: 0 0 16px 0;
  color: #333;
  border-bottom: 2px solid #667eea;
  padding-bottom: 8px;
}

.setting-group {
  margin-bottom: 24px;
}

.setting-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 0;
  border-bottom: 1px solid #f0f0f0;
}

.setting-item:last-child {
  border-bottom: none;
}

.setting-info h4 {
  margin: 0 0 4px 0;
  color: #333;
  font-size: 14px;
}

.setting-info p {
  margin: 0;
  color: #666;
  font-size: 12px;
}

.stats-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 20px;
}

.stat-card {
  text-align: center;
}

.stat-content {
  padding: 20px;
}

.stat-number {
  font-size: 32px;
  font-weight: bold;
  color: #667eea;
  margin-bottom: 8px;
}

.stat-label {
  color: #666;
  font-size: 14px;
}

.chart-card {
  margin-top: 20px;
}

.chart-card h3 {
  margin: 0 0 16px 0;
  color: #333;
}

.threat-types {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.threat-type-item {
  display: flex;
  align-items: center;
  gap: 12px;
}

.threat-type-name {
  width: 100px;
  font-size: 12px;
  color: #666;
}

.threat-count {
  width: 40px;
  text-align: right;
  font-size: 12px;
  color: #333;
}

.threats-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.threats-header h3 {
  margin: 0;
  color: #333;
}

.about-content {
  text-align: center;
}

.app-info h2 {
  margin: 0 0 8px 0;
  color: #333;
}

.version {
  color: #666;
  margin-bottom: 16px;
}

.description {
  color: #666;
  line-height: 1.6;
  margin-bottom: 24px;
}

.features {
  margin-bottom: 24px;
}

.features h3 {
  margin: 0 0 12px 0;
  color: #333;
}

.features ul {
  list-style: none;
  padding: 0;
  margin: 0;
}

.features li {
  padding: 4px 0;
  color: #666;
}

.tech-stack h3 {
  margin: 0 0 12px 0;
  color: #333;
}

.tech-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: center;
}

.footer-actions {
  margin-top: 20px;
  text-align: center;
  padding: 20px;
  background: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.footer-actions .el-button {
  margin: 0 8px;
}
</style>
