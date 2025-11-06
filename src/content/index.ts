/**
 * Content Script - 内容脚本
 * 在网页上下文中运行，负责实时监控和防护
 */

console.log('🛡️ Content Security Monitor Starting on:', window.location.href)

// 注入页面标识
const marker = document.createElement('meta')
marker.name = 'web-security-guardian'
marker.content = 'active'
document.head?.appendChild(marker)

// 在window对象上添加标识
;(window as any).webSecurityGuardian = {
  version: '1.0.0',
  isActive: true,
  reportThreat: (threat: any) => {
    chrome.runtime.sendMessage({
      type: 'THREAT_DETECTED',
      data: threat
    })
  }
}

// XSS检测模式
const xssPatterns = [
  /<script[^>]*>.*?<\/script>/gi,
  /javascript:/gi,
  /on\w+\s*=\s*["'][^"']*["']/gi
]

// 检测XSS
function detectXSS() {
  const content = document.documentElement.innerHTML
  let xssFound = false

  xssPatterns.forEach(pattern => {
    if (pattern.test(content)) {
      xssFound = true
    }
  })

  if (xssFound) {
    console.warn('⚠️ Potential XSS detected')
    chrome.runtime.sendMessage({
      type: 'SECURITY_ISSUE',
      issueType: 'XSS_DETECTED',
      data: {
        url: window.location.href,
        timestamp: Date.now()
      }
    })
  }
}

// 检查HTTPS
function checkHTTPS() {
  if (window.location.protocol !== 'https:' && 
      window.location.hostname !== 'localhost' &&
      !window.location.hostname.startsWith('127.0.0.1')) {
    
    console.warn('⚠️ Insecure connection (HTTP)')
    showSecurityWarning('此网站未使用HTTPS加密连接')
  }
}

// 监控表单
function monitorForms() {
  const forms = document.querySelectorAll('form')
  
  forms.forEach(form => {
    form.addEventListener('submit', (e) => {
      const action = form.action || window.location.href
      const hasPassword = form.querySelector('input[type="password"]')
      
      if (hasPassword && !action.startsWith('https://')) {
        console.warn('⚠️ Password submitted over insecure connection')
        showSecurityWarning('密码将通过不安全的连接传输！')
      }
    })
  })
}

// 显示安全警告
function showSecurityWarning(message: string) {
  const warning = document.createElement('div')
  warning.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: linear-gradient(135deg, #ff6b6b, #ee5a24);
    color: white;
    padding: 15px 20px;
    border-radius: 8px;
    z-index: 10000;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 14px;
    font-weight: 500;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    max-width: 300px;
    animation: slideIn 0.3s ease-out;
  `
  
  warning.innerHTML = `
    <div style="display: flex; align-items: center; gap: 10px;">
      <span style="font-size: 18px;">🛡️</span>
      <span>${message}</span>
      <button onclick="this.parentElement.parentElement.remove()" 
              style="background: none; border: none; color: white; font-size: 18px; cursor: pointer; margin-left: auto;">×</button>
    </div>
  `
  
  // 添加动画样式
  if (!document.getElementById('wsg-style')) {
    const style = document.createElement('style')
    style.id = 'wsg-style'
    style.textContent = `
      @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
    `
    document.head?.appendChild(style)
  }
  
  document.body.appendChild(warning)
  
  // 5秒后自动移除
  setTimeout(() => {
    if (warning.parentNode) {
      warning.style.animation = 'slideIn 0.3s ease-out reverse'
      setTimeout(() => warning.remove(), 300)
    }
  }, 5000)
}

// 初始化
function initialize() {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      performChecks()
    })
  } else {
    performChecks()
  }
}

function performChecks() {
  // 执行各种安全检查
  detectXSS()
  checkHTTPS()
  monitorForms()
  
  console.log('✅ Content Security Monitor Started')
}

// 启动
initialize()