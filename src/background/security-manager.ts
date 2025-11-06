/**
 * 安全管理器 - 负责核心安全功能管理
 */

import browser from 'webextension-polyfill'
import type { ProtectionSettings, SecurityStats, ThreatDetection, MaliciousUrl } from '../types'
import { getStats, saveStats, getThreats, addThreat, clearThreats, getWhitelist, addToWhitelist } from '../utils/storage'

export class SecurityManager {
  private settings: ProtectionSettings | null = null
  private maliciousUrls: Set<string> = new Set()
  private blocklist: Set<string> = new Set()

  async initialize(settings: ProtectionSettings) {
    this.settings = settings
    await this.loadMaliciousUrls()
    console.log('🔒 Security Manager initialized')
  }

  async updateSettings(settings: ProtectionSettings) {
    this.settings = settings
    console.log('⚙️ Security settings updated')
  }

  private async loadMaliciousUrls() {
    try {
      // 从本地存储加载恶意URL列表
      const stored = await browser.storage.local.get(['maliciousUrls'])
      if (stored.maliciousUrls) {
        this.maliciousUrls = new Set(stored.maliciousUrls)
      }

      // 默认恶意URL列表（用于演示）
      const defaultMalicious = [
        'malware-example.com',
        'phishing-test.net',
        'suspicious-site.org',
        'fake-bank.com',
        'scam-lottery.net'
      ]

      defaultMalicious.forEach(url => this.maliciousUrls.add(url))
      
      console.log(`📋 Loaded ${this.maliciousUrls.size} malicious URLs`)
    } catch (error) {
      console.error('Failed to load malicious URLs:', error)
    }
  }

  async getStats(): Promise<SecurityStats> {
    return await getStats()
  }

  async updateStats(threat: ThreatDetection) {
    try {
      const stats = await getStats()
      
      stats.totalThreats++
      if (threat.blocked) {
        stats.blockedThreats++
      } else {
        stats.allowedThreats++
      }
      
      stats.threatsByType[threat.type]++
      stats.threatsByLevel[threat.level]++
      stats.lastScanTime = Date.now()
      
      await saveStats(stats)
    } catch (error) {
      console.error('Failed to update stats:', error)
    }
  }

  async getThreats(): Promise<ThreatDetection[]> {
    return await getThreats()
  }

  async clearThreats(): Promise<void> {
    await clearThreats()
  }

  async addToWhitelist(url: string): Promise<void> {
    await addToWhitelist(url)
  }

  async addToBlocklist(url: string): Promise<void> {
    try {
      this.blocklist.add(url)
      
      // 保存到存储
      const blocklistArray = Array.from(this.blocklist)
      await browser.storage.local.set({ blocklist: blocklistArray })
      
      console.log(`🚫 Added to blocklist: ${url}`)
    } catch (error) {
      console.error('Failed to add to blocklist:', error)
    }
  }

  isBlocked(url: string): boolean {
    try {
      const hostname = new URL(url).hostname
      return this.blocklist.has(hostname) || this.blocklist.has(url)
    } catch {
      return false
    }
  }

  isMalicious(url: string): boolean {
    try {
      const hostname = new URL(url).hostname
      return this.maliciousUrls.has(hostname) || 
             Array.from(this.maliciousUrls).some(malicious => 
               hostname.includes(malicious)
             )
    } catch {
      return false
    }
  }

  async updateMaliciousUrls(urls: MaliciousUrl[]) {
    try {
      this.maliciousUrls.clear()
      urls.forEach(urlData => {
        this.maliciousUrls.add(new URL(urlData.url).hostname)
      })
      
      // 保存到存储
      await browser.storage.local.set({ 
        maliciousUrls: Array.from(this.maliciousUrls),
        lastMaliciousUrlsUpdate: Date.now()
      })
      
      console.log(`📋 Updated malicious URLs: ${this.maliciousUrls.size} entries`)
    } catch (error) {
      console.error('Failed to update malicious URLs:', error)
    }
  }

  // 获取安全建议
  getSecurityRecommendations(threats: ThreatDetection[]): string[] {
    const recommendations: string[] = []
    
    const threatTypes = new Set(threats.map(t => t.type))
    
    if (threatTypes.has('malicious_url')) {
      recommendations.push('避免访问可疑网站，注意URL拼写和域名')
    }
    
    if (threatTypes.has('xss_attack')) {
      recommendations.push('保持浏览器更新，启用XSS防护功能')
    }
    
    if (threatTypes.has('tracker')) {
      recommendations.push('考虑使用隐私模式浏览，定期清理Cookie')
    }
    
    if (threatTypes.has('insecure_form')) {
      recommendations.push('只在HTTPS网站上提交敏感信息')
    }
    
    if (recommendations.length === 0) {
      recommendations.push('继续保持良好的网络安全习惯')
    }
    
    return recommendations
  }

  // 生成安全报告
  async generateSecurityReport(): Promise<any> {
    try {
      const stats = await getStats()
      const threats = await getThreats()
      const recentThreats = threats.slice(0, 50) // 最近50个威胁
      
      return {
        summary: {
          totalThreats: stats.totalThreats,
          blockedThreats: stats.blockedThreats,
          securityScore: this.calculateSecurityScore(threats),
          lastScanTime: stats.lastScanTime
        },
        threatBreakdown: stats.threatsByType,
        severityBreakdown: stats.threatsByLevel,
        recentThreats,
        recommendations: this.getSecurityRecommendations(recentThreats),
        generatedAt: Date.now()
      }
    } catch (error) {
      console.error('Failed to generate security report:', error)
      throw error
    }
  }

  private calculateSecurityScore(threats: ThreatDetection[]): number {
    if (threats.length === 0) return 100
    
    let score = 100
    const recentThreats = threats.filter(t => 
      Date.now() - t.timestamp < 24 * 60 * 60 * 1000 // 最近24小时
    )
    
    recentThreats.forEach(threat => {
      switch (threat.level) {
        case 'critical':
          score -= 25
          break
        case 'high':
          score -= 15
          break
        case 'medium':
          score -= 8
          break
        case 'low':
          score -= 3
          break
      }
    })
    
    return Math.max(0, Math.min(100, score))
  }
}
