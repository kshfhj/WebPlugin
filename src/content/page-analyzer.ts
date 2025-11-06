/**
 * 页面分析器 - 负责分析页面内容的安全性
 */

import type { ThreatDetection, PageSecurityAnalysis } from '../types'
import { detectXSS, calculateSecurityScore } from '../utils/security'

export class PageAnalyzer {
  private threats: ThreatDetection[] = []

  initialize() {
    console.log('📊 Page Analyzer initialized')
  }

  async scanPage(): Promise<ThreatDetection[]> {
    this.threats = []
    
    // 扫描页面内容
    await this.scanContent()
    
    // 扫描外部资源
    await this.scanExternalResources()
    
    // 扫描URL
    await this.scanUrl()
    
    return this.threats
  }

  async analyzePage(): Promise<PageSecurityAnalysis> {
    const threats = await this.scanPage()
    const score = calculateSecurityScore(threats)
    
    return {
      url: window.location.href,
      score,
      threats,
      recommendations: this.generateRecommendations(threats),
      scanTime: Date.now(),
      isSecure: threats.length === 0
    }
  }

  private async scanContent() {
    const content = document.documentElement.innerHTML
    const xssResult = detectXSS(content)
    
    if (xssResult.detected) {
      xssResult.patterns.forEach(pattern => {
        this.threats.push({
          id: `xss_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          type: 'xss_attack',
          level: pattern.severity,
          url: window.location.href,
          description: `检测到XSS模式: ${pattern.description}`,
          timestamp: Date.now(),
          blocked: false,
          details: { pattern: pattern.id }
        })
      })
    }
  }

  private async scanExternalResources() {
    // 扫描外部脚本
    const scripts = document.querySelectorAll('script[src]')
    scripts.forEach(script => {
      const src = (script as HTMLScriptElement).src
      if (src && !this.isTrustedDomain(src)) {
        this.threats.push({
          id: `external_script_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          type: 'suspicious_script',
          level: 'medium',
          url: window.location.href,
          description: `检测到外部脚本: ${new URL(src).hostname}`,
          timestamp: Date.now(),
          blocked: false,
          details: { src }
        })
      }
    })

    // 扫描外部iframe
    const iframes = document.querySelectorAll('iframe[src]')
    iframes.forEach(iframe => {
      const src = (iframe as HTMLIFrameElement).src
      if (src && !this.isTrustedDomain(src)) {
        this.threats.push({
          id: `external_iframe_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          type: 'suspicious_script',
          level: 'medium',
          url: window.location.href,
          description: `检测到外部iframe: ${new URL(src).hostname}`,
          timestamp: Date.now(),
          blocked: false,
          details: { src }
        })
      }
    })
  }

  private async scanUrl() {
    const url = window.location.href
    
    // 检查HTTPS
    if (!url.startsWith('https://') && !url.startsWith('file://')) {
      this.threats.push({
        id: `insecure_protocol_${Date.now()}`,
        type: 'insecure_form',
        level: 'medium',
        url,
        description: '网站未使用HTTPS加密连接',
        timestamp: Date.now(),
        blocked: false
      })
    }
  }

  private isTrustedDomain(url: string): boolean {
    try {
      const hostname = new URL(url).hostname
      const trustedDomains = [
        window.location.hostname,
        'cdnjs.cloudflare.com',
        'ajax.googleapis.com',
        'code.jquery.com',
        'unpkg.com',
        'jsdelivr.net'
      ]
      
      return trustedDomains.some(trusted => 
        hostname === trusted || hostname.endsWith('.' + trusted)
      )
    } catch {
      return false
    }
  }

  private generateRecommendations(threats: ThreatDetection[]): string[] {
    const recommendations: string[] = []
    const threatTypes = new Set(threats.map(t => t.type))
    
    if (threatTypes.has('xss_attack')) {
      recommendations.push('检测到XSS风险，建议更新浏览器并启用安全防护')
    }
    
    if (threatTypes.has('suspicious_script')) {
      recommendations.push('发现可疑外部资源，请确认网站可信度')
    }
    
    if (threatTypes.has('insecure_form')) {
      recommendations.push('网站未使用HTTPS，避免输入敏感信息')
    }
    
    if (recommendations.length === 0) {
      recommendations.push('页面安全检查通过，但仍需保持警惕')
    }
    
    return recommendations
  }
}
