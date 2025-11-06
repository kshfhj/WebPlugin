/**
 * Background Script - 后台服务脚本
 * 负责处理网络请求拦截、恶意URL检测、数据管理等核心功能
 */

console.log('🛡️ Web Security Guardian Background Service Starting...')

// 简化的安全管理器
class SimpleSecurityManager {
  private maliciousUrls = new Set([
    'malware-example.com',
    'phishing-test.net',
    'suspicious-site.org',
    'fake-bank.com',
    'scam-lottery.net'
  ])

  private trackerDomains = new Set([
    'google-analytics.com',
    'googletagmanager.com',
    'facebook.com',
    'doubleclick.net',
    'googlesyndication.com',
    'amazon-adsystem.com'
  ])

  isMalicious(url: string): boolean {
    try {
      const hostname = new URL(url).hostname.toLowerCase()
      return Array.from(this.maliciousUrls).some(malicious => 
        hostname === malicious || hostname.endsWith('.' + malicious)
      )
    } catch {
      return false
    }
  }

  isTracker(url: string): boolean {
    try {
      const hostname = new URL(url).hostname.toLowerCase()
      return Array.from(this.trackerDomains).some(tracker => 
        hostname === tracker || hostname.endsWith('.' + tracker)
      )
    } catch {
      return false
    }
  }
}

const securityManager = new SimpleSecurityManager()

// 监听插件安装
chrome.runtime.onInstalled.addListener((details) => {
  console.log('✅ Extension installed:', details.reason)
  
  if (details.reason === 'install') {
    // 初始化存储
    chrome.storage.local.set({
      protectionSettings: {
        maliciousUrlProtection: true,
        xssProtection: true,
        trackerBlocking: true,
        formProtection: true,
        phishingProtection: true,
        notifications: true,
        autoUpdate: true,
        strictMode: false
      },
      securityStats: {
        totalThreats: 0,
        blockedThreats: 0,
        allowedThreats: 0,
        threatsByType: {
          malicious_url: 0,
          xss_attack: 0,
          tracker: 0,
          insecure_form: 0,
          suspicious_script: 0,
          phishing: 0
        },
        threatsByLevel: {
          low: 0,
          medium: 0,
          high: 0,
          critical: 0
        },
        lastScanTime: 0
      }
    })
    
    // 打开欢迎页面
    chrome.tabs.create({
      url: chrome.runtime.getURL('src/options/index.html')
    })
  }
})

// 监听网络请求（基本版本）
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    // 检查恶意URL
    if (securityManager.isMalicious(details.url)) {
      console.log('🚫 Malicious URL detected (blocked by declarativeNetRequest):', details.url)
      
      // 更新统计
      chrome.storage.local.get(['securityStats'], (result) => {
        if (result.securityStats) {
          const stats = result.securityStats
          stats.totalThreats++
          stats.blockedThreats++
          stats.threatsByType.malicious_url++
          stats.threatsByLevel.high++
          chrome.storage.local.set({ securityStats: stats })
        }
      })
    }

    // 检查追踪器
    if (securityManager.isTracker(details.url)) {
      console.log('👁️ Tracker request detected (blocked by declarativeNetRequest):', details.url)
      
      // 更新统计
      chrome.storage.local.get(['securityStats'], (result) => {
        if (result.securityStats) {
          const stats = result.securityStats
          stats.totalThreats++
          stats.blockedThreats++
          stats.threatsByType.tracker++
          stats.threatsByLevel.medium++
          chrome.storage.local.set({ securityStats: stats })
        }
      })
    }
  },
  { urls: ['<all_urls>'] }
)

// 监听消息
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('📨 Received message:', request.type)
  
  try {
    switch (request.type) {
      case 'GET_SECURITY_STATUS':
        chrome.storage.local.get(['securityStats'], (result) => {
          sendResponse({
            maliciousUrlsCount: result.securityStats?.blockedThreats || 0,
            trackersBlocked: result.securityStats?.threatsByType?.tracker || 0
          })
        })
        return true
        
      case 'GET_STATS':
        chrome.storage.local.get(['securityStats'], (result) => {
          sendResponse(result.securityStats || {
            totalThreats: 0,
            blockedThreats: 0,
            allowedThreats: 0,
            threatsByType: {},
            threatsByLevel: {},
            lastScanTime: Date.now()
          })
        })
        return true
        
      case 'UPDATE_SETTINGS':
        chrome.storage.local.set({ protectionSettings: request.data }, () => {
          sendResponse({ success: true })
        })
        return true
        
      case 'SETTINGS_UPDATED':
        console.log('⚙️ Settings updated:', request.data)
        sendResponse({ success: true })
        break
        
      case 'TOGGLE_PROTECTION':
        console.log('🔄 Protection toggled:', request.data)
        sendResponse({ success: true })
        break
        
      case 'SCAN_PAGE':
        console.log('🔍 Scanning page:', request.data?.tabId)
        sendResponse({ success: true })
        break
        
      case 'THREAT_DETECTED':
        console.log('🚨 Threat detected:', request.data)
        
        // 保存威胁记录
        chrome.storage.local.get(['recentThreats'], (result) => {
          const threats = result.recentThreats || []
          threats.unshift(request.data)
          
          // 只保留最近100条
          if (threats.length > 100) {
            threats.splice(100)
          }
          
          chrome.storage.local.set({ recentThreats: threats })
        })
        
        sendResponse({ success: true })
        break
        
      case 'SECURITY_ISSUE':
        console.log('⚠️ Security issue:', request.issueType, request.data)
        sendResponse({ success: true })
        break
        
      default:
        sendResponse({ success: true })
    }
  } catch (error) {
    console.error('❌ Error handling message:', error)
    sendResponse({ error: String(error) })
  }
  
  return true
})

// 监听标签页更新
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    console.log('📄 Page loaded:', tab.url)
    
    // 分析页面URL
    if (securityManager.isMalicious(tab.url)) {
      console.log('⚠️ Warning: Potentially malicious page')
    }
  }
})

// 添加安全响应头
// Manifest V3: 响应头修改应通过 declarativeNetRequest 实现，此处仅记录日志
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    console.log('🔐 Headers received from:', details.url)
  },
  { urls: ['<all_urls>'] }
)

console.log('✅ Web Security Guardian Background Service Started Successfully')

// 保持Service Worker活跃
let heartbeatCount = 0
setInterval(() => {
  heartbeatCount++
  console.log(`💓 Service Worker heartbeat #${heartbeatCount}`)
}, 30000) // 每30秒一次