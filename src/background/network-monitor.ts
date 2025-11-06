/**
 * 网络监控器 - 负责监控网络请求和响应
 */

import browser from 'webextension-polyfill'
import type { ProtectionSettings } from '../types'

export class NetworkMonitor {
  private settings: ProtectionSettings | null = null
  private requestStats: Map<string, number> = new Map()
  private blockedRequests: Set<string> = new Set()

  async initialize(settings: ProtectionSettings) {
    this.settings = settings
    this.setupNetworkListeners()
    console.log('🌐 Network Monitor initialized')
  }

  async updateSettings(settings: ProtectionSettings) {
    this.settings = settings
  }

  private setupNetworkListeners() {
    // Manifest V3: 完全非阻塞模式
    // 实际的阻止功能由 declarativeNetRequest 规则处理
    // webRequest 只用于统计和日志（不访问请求/响应内容）
    
    try {
      // 监听请求开始（仅基本信息，无额外参数）
      browser.webRequest.onBeforeRequest.addListener(
        this.handleBeforeRequest.bind(this),
        { urls: ['<all_urls>'] }
        // 不使用任何 extraInfoSpec 参数
      )

      // 监听请求完成（统计用）
      browser.webRequest.onCompleted.addListener(
        this.handleCompleted.bind(this),
        { urls: ['<all_urls>'] }
      )

      // 监听请求错误（统计用）
      browser.webRequest.onErrorOccurred.addListener(
        this.handleError.bind(this),
        { urls: ['<all_urls>'] }
      )
      
      console.log('📡 Network listeners initialized (observation mode)')
      console.log('🛡️ Request blocking handled by declarativeNetRequest rules')
    } catch (error) {
      console.error('Failed to setup network listeners:', error)
    }
  }

  private handleBeforeRequest(
    details: browser.WebRequest.OnBeforeRequestDetailsType
  ): void {
    // 记录请求统计（非阻塞模式）
    const hostname = this.getHostname(details.url)
    if (hostname) {
      this.requestStats.set(hostname, (this.requestStats.get(hostname) || 0) + 1)
    }

    // 检查是否应该被阻止（仅用于统计和日志）
    // 实际阻止由 declarativeNetRequest 规则处理
    if (this.shouldBlockRequest(details)) {
      this.blockedRequests.add(details.url)
      console.log('🚫 Request should be blocked (handled by declarativeNetRequest):', details.url)
    }
  }

  // Manifest V3: 这些方法已移除
  // 头部检查和修改现在由 declarativeNetRequest 规则处理
  // 如需要检查头部，可以在 onCompleted 中通过其他方式获取

  private handleCompleted(details: browser.WebRequest.OnCompletedDetailsType) {
    // 记录成功的请求（减少日志噪音）
    const hostname = this.getHostname(details.url)
    if (hostname && this.settings?.trackerBlocking && this.isTracker(hostname)) {
      console.log('🚫 Tracker request completed (should be blocked by rules):', hostname)
    }
  }

  private handleError(details: browser.WebRequest.OnErrorOccurredDetailsType) {
    // 记录失败的请求
    console.log('❌ Request failed:', details.url, details.error)
  }

  private shouldBlockRequest(details: browser.WebRequest.OnBeforeRequestDetailsType): boolean {
    const url = details.url
    const hostname = this.getHostname(url)

    if (!hostname) return false

    // 检查追踪器
    if (this.settings?.trackerBlocking && this.isTracker(hostname)) {
      return true
    }

    // 检查恶意域名
    if (this.settings?.maliciousUrlProtection && this.isMalicious(hostname)) {
      return true
    }

    // 检查广告
    if (this.isAd(url)) {
      return true
    }

    return false
  }

  // Manifest V3: 头部分析功能已移除
  // 因为在非阻塞模式下无法访问头部信息
  // 安全头部检查可以通过其他方式实现（如 fetch API）

  private getHostname(url: string): string | null {
    try {
      return new URL(url).hostname
    } catch {
      return null
    }
  }

  private isTracker(hostname: string): boolean {
    // 完整的追踪器域名列表
    const trackerDomains = [
      // Google追踪
      'google-analytics.com',
      'googletagmanager.com',
      'googleadservices.com',
      'googlesyndication.com',
      'doubleclick.net',
      'googletagservices.com',
      
      // Facebook追踪
      'facebook.com',
      'facebook.net',
      'connect.facebook.net',
      
      // 广告网络
      'adnxs.com',
      'adsrvr.org',
      'advertising.com',
      'adsystem.com',
      'adtech.de',
      'criteo.com',
      'criteo.net',
      'pubmatic.com',
      'rubiconproject.com',
      'amazon-adsystem.com',
      'a-msedge.net',
      
      // 分析追踪
      'scorecardresearch.com',
      'quantserve.com',
      'quantcount.com',
      'mixpanel.com',
      'segment.io',
      'segment.com',
      'amplitude.com',
      'fullstory.com',
      'hotjar.com',
      'crazyegg.com',
      'mouseflow.com',
      
      // 内容推荐
      'outbrain.com',
      'taboola.com',
      'revcontent.com',
      'mgid.com',
      
      // 其他追踪器
      'newrelic.com',
      'nr-data.net',
      'clarity.ms',
      'bat.bing.com'
    ]

    return trackerDomains.some(tracker => 
      hostname === tracker || 
      hostname.endsWith('.' + tracker) ||
      hostname.includes(tracker)
    )
  }

  private isMalicious(hostname: string): boolean {
    // 完整的恶意域名列表
    const maliciousDomains = [
      // 测试用恶意域名
      'malware-example.com',
      'phishing-test.net',
      'suspicious-site.org',
      'fake-bank.com',
      'scam-lottery.net',
      'virus-download.com',
      'trojan-site.net',
      
      // 常见钓鱼模式
      'paypal-secure-verify.com',
      'amazon-account-verify.com',
      'google-security-check.com',
      'microsoft-account-alert.com',
      'apple-id-verify.com',
      'netflix-billing-update.com',
      
      // 欺诈网站
      'free-iphone-giveaway.com',
      'win-prize-now.net',
      'claim-your-reward.org',
      'urgent-account-verification.com',
      
      // 恶意软件分发
      'free-software-download.xyz',
      'crack-keygen-free.top',
      'movie-download-free.tk',
      
      // 加密货币诈骗
      'bitcoin-doubler.com',
      'crypto-giveaway.net',
      'eth-airdrop.org'
    ]

    // 完全匹配或子域名匹配
    if (maliciousDomains.some(malicious => 
      hostname === malicious || hostname.endsWith('.' + malicious)
    )) {
      return true
    }
    
    // 检查可疑模式
    const suspiciousPatterns = [
      /paypal.*secure/i,
      /amazon.*login/i,
      /google.*verify/i,
      /microsoft.*security/i,
      /apple.*id/i,
      /bank.*secure/i,
      /.*-paypal\./i,
      /.*-amazon\./i,
      /.*-google\./i,
      /win.*prize/i,
      /free.*iphone/i,
      /claim.*reward/i,
      /bitcoin.*double/i,
      /crypto.*giveaway/i
    ]
    
    return suspiciousPatterns.some(pattern => pattern.test(hostname))
  }

  private isAd(url: string): boolean {
    const adPatterns = [
      /\/ads?\//,
      /\/advertisement/,
      /\/banner/,
      /\/popup/,
      /googleads/,
      /googlesyndication/,
      /doubleclick/
    ]

    return adPatterns.some(pattern => pattern.test(url))
  }

  // 获取网络统计
  getNetworkStats() {
    return {
      requestStats: Object.fromEntries(this.requestStats),
      blockedRequests: Array.from(this.blockedRequests),
      totalRequests: Array.from(this.requestStats.values()).reduce((a, b) => a + b, 0),
      totalBlocked: this.blockedRequests.size
    }
  }

  // 清除统计数据
  clearStats() {
    this.requestStats.clear()
    this.blockedRequests.clear()
  }

  // 检查域名是否可信
  isDomainTrusted(hostname: string): boolean {
    const trustedDomains = [
      'google.com',
      'microsoft.com',
      'apple.com',
      'mozilla.org',
      'github.com',
      'stackoverflow.com'
    ]

    return trustedDomains.some(trusted => 
      hostname === trusted || hostname.endsWith('.' + trusted)
    )
  }
}
