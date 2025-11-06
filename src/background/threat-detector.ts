/**
 * 威胁检测器 - 负责各种安全威胁的检测
 */

import type { ProtectionSettings, PageSecurityAnalysis, ThreatDetection, ThreatType, ThreatLevel } from '../types'
import { XSS_PATTERNS, TRACKER_DOMAINS, detectXSS, isTracker, isMaliciousUrl } from '../utils/security'

export class ThreatDetector {
  private settings: ProtectionSettings | null = null
  private maliciousUrls: Set<string> = new Set()

  async initialize(settings: ProtectionSettings) {
    this.settings = settings
    await this.loadThreatData()
    console.log('🔍 Threat Detector initialized')
  }

  async updateSettings(settings: ProtectionSettings) {
    this.settings = settings
  }

  private async loadThreatData() {
    // 加载恶意URL数据（真实威胁域名示例）
    this.maliciousUrls = new Set([
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
      'eth-airdrop.org',
      
      // 仿冒域名（同形异义字示例）
      'аpple.com', // 西里尔字母а替代拉丁字母a
      'paypaI.com', // 大写I替代小写l
      'g00gle.com', // 数字0替代字母o
      
      // 可疑TLD
      'random-site.tk',
      'suspicious.ml',
      'phishing.ga',
      'malware.cf',
      'scam.gq'
    ])
    
    console.log(`📋 Loaded ${this.maliciousUrls.size} malicious URLs`)
  }

  async checkMaliciousUrl(url: string): Promise<boolean> {
    if (!this.settings?.maliciousUrlProtection) {
      return false
    }

    try {
      const hostname = new URL(url).hostname.toLowerCase()
      const fullUrl = url.toLowerCase()
      
      // 1. 检查已知恶意域名
      for (const malicious of this.maliciousUrls) {
        if (hostname === malicious || hostname.endsWith('.' + malicious)) {
          return true
        }
      }

      // 2. 检查可疑模式
      const suspiciousPatterns = [
        /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP地址
        /[0-9]{10,}/, // 长数字串
        /[a-z]{30,}/, // 超长随机字符串
      ]

      if (suspiciousPatterns.some(pattern => pattern.test(hostname))) {
        return true
      }

      // 3. 检查恶意URL特征
      const maliciousFeatures = [
        // 可疑关键词
        /malware|virus|trojan|ransomware|exploit/i,
        // 钓鱼特征
        /paypal-?(secure|verify|account)/i,
        /amazon-?(login|secure)/i,
        /google-?(verify|account)/i,
        /microsoft-?(security|verify)/i,
        // 下载陷阱
        /free-?(download|crack|keygen)/i,
        /get-?(free|prize|gift)/i,
        // 欺诈特征
        /win.*prize|you.*won|claim.*reward/i,
        /urgent.*action|account.*suspended|verify.*identity/i
      ]

      if (maliciousFeatures.some(pattern => pattern.test(fullUrl))) {
        return true
      }

      // 4. 检查短链接（可疑）
      const shortLinkDomains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
      if (shortLinkDomains.some(domain => hostname.includes(domain))) {
        // 短链接需要进一步检查
        return false // 暂时不直接阻止短链接
      }

      // 5. 检查同形异义字攻击
      const { detectHomographAttack } = await import('../utils/security')
      if (detectHomographAttack(hostname)) {
        return true
      }

      return false
    } catch {
      return false
    }
  }

  async checkTracker(url: string): Promise<boolean> {
    if (!this.settings?.trackerBlocking) {
      return false
    }

    return isTracker(url)
  }

  async checkXSS(content: string): Promise<{ detected: boolean; patterns: any[] }> {
    if (!this.settings?.xssProtection) {
      return { detected: false, patterns: [] }
    }

    return detectXSS(content)
  }

  async analyzePage(url: string): Promise<PageSecurityAnalysis> {
    const threats: ThreatDetection[] = []
    let score = 100

    try {
      // 检查URL安全性
      if (await this.checkMaliciousUrl(url)) {
        threats.push({
          id: `malicious_${Date.now()}`,
          type: 'malicious_url' as ThreatType,
          level: 'high' as ThreatLevel,
          url,
          description: '检测到恶意URL',
          timestamp: Date.now(),
          blocked: false
        })
        score -= 30
      }

      // 检查HTTPS
      if (!url.startsWith('https://') && !url.startsWith('file://')) {
        threats.push({
          id: `insecure_${Date.now()}`,
          type: 'insecure_form' as ThreatType,
          level: 'medium' as ThreatLevel,
          url,
          description: '网站未使用HTTPS加密',
          timestamp: Date.now(),
          blocked: false
        })
        score -= 15
      }

      // 检查域名可信度
      const domainTrust = this.analyzeDomainTrust(url)
      if (domainTrust < 0.7) {
        threats.push({
          id: `suspicious_domain_${Date.now()}`,
          type: 'phishing' as ThreatType,
          level: 'medium' as ThreatLevel,
          url,
          description: '域名可信度较低',
          timestamp: Date.now(),
          blocked: false
        })
        score -= 10
      }

      const recommendations = this.generateRecommendations(threats)

      return {
        url,
        score: Math.max(0, score),
        threats,
        recommendations,
        scanTime: Date.now(),
        isSecure: threats.length === 0
      }
    } catch (error) {
      console.error('Error analyzing page:', error)
      return {
        url,
        score: 50,
        threats: [],
        recommendations: ['页面分析失败，请手动检查安全性'],
        scanTime: Date.now(),
        isSecure: false
      }
    }
  }

  private analyzeDomainTrust(url: string): number {
    try {
      const hostname = new URL(url).hostname.toLowerCase()
      
      // 知名网站列表
      const trustedDomains = [
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
        'facebook.com', 'twitter.com', 'github.com', 'stackoverflow.com',
        'wikipedia.org', 'mozilla.org', 'w3.org'
      ]

      // 检查是否为知名网站
      for (const trusted of trustedDomains) {
        if (hostname === trusted || hostname.endsWith('.' + trusted)) {
          return 1.0
        }
      }

      // 检查域名特征
      let trust = 0.8

      // 域名长度
      if (hostname.length > 30) trust -= 0.1
      if (hostname.length > 50) trust -= 0.2

      // 数字比例
      const digitRatio = (hostname.match(/\d/g) || []).length / hostname.length
      if (digitRatio > 0.3) trust -= 0.2

      // 连字符数量
      const hyphenCount = (hostname.match(/-/g) || []).length
      if (hyphenCount > 3) trust -= 0.1

      // 子域名数量
      const subdomainCount = hostname.split('.').length - 2
      if (subdomainCount > 2) trust -= 0.1

      return Math.max(0, trust)
    } catch {
      return 0.5
    }
  }

  private generateRecommendations(threats: ThreatDetection[]): string[] {
    const recommendations: string[] = []

    if (threats.some(t => t.type === 'malicious_url')) {
      recommendations.push('立即离开此网站，避免输入任何个人信息')
    }

    if (threats.some(t => t.type === 'insecure_form')) {
      recommendations.push('避免在非HTTPS网站上提交敏感信息')
    }

    if (threats.some(t => t.type === 'phishing')) {
      recommendations.push('仔细检查网站域名，确认是否为官方网站')
    }

    if (threats.some(t => t.type === 'xss_attack')) {
      recommendations.push('更新浏览器到最新版本，启用安全防护功能')
    }

    if (recommendations.length === 0) {
      recommendations.push('网站看起来是安全的，但仍需保持警惕')
    }

    return recommendations
  }

  // 检测钓鱼网站（增强版）
  async checkPhishing(url: string): Promise<{ detected: boolean; reasons: string[]; score: number }> {
    if (!this.settings?.phishingProtection) {
      return { detected: false, reasons: [], score: 0 }
    }

    try {
      // 使用utils中的完整钓鱼检测功能
      const { detectPhishing } = await import('../utils/security')
      return detectPhishing(url)
    } catch (error) {
      console.error('Phishing detection error:', error)
      return { detected: false, reasons: [], score: 0 }
    }
  }

  // 检测可疑脚本
  async checkSuspiciousScript(scriptContent: string): Promise<boolean> {
    if (!this.settings?.xssProtection) {
      return false
    }

    const suspiciousPatterns = [
      /eval\s*\(/,
      /document\.write\s*\(/,
      /innerHTML\s*=.*<script/,
      /location\.href\s*=/,
      /window\.open\s*\(/,
      /document\.cookie/,
      /localStorage\./,
      /sessionStorage\./
    ]

    return suspiciousPatterns.some(pattern => pattern.test(scriptContent))
  }

  // 生成威胁报告
  generateThreatReport(threat: ThreatDetection): string {
    const timestamp = new Date(threat.timestamp).toLocaleString('zh-CN')
    
    return `
威胁报告
========
类型: ${this.getThreatTypeName(threat.type)}
级别: ${this.getThreatLevelName(threat.level)}
URL: ${threat.url}
描述: ${threat.description}
时间: ${timestamp}
状态: ${threat.blocked ? '已阻止' : '已检测'}
    `.trim()
  }

  private getThreatTypeName(type: ThreatType): string {
    const names = {
      malicious_url: '恶意URL',
      xss_attack: 'XSS攻击',
      tracker: '隐私追踪',
      insecure_form: '不安全表单',
      suspicious_script: '可疑脚本',
      phishing: '钓鱼网站'
    }
    return names[type] || type
  }

  private getThreatLevelName(level: ThreatLevel): string {
    const names = {
      low: '低',
      medium: '中',
      high: '高',
      critical: '严重'
    }
    return names[level] || level
  }
}
