/**
 * DOM观察器 - 负责监控DOM变化
 */

import type { ThreatDetection } from '../types'
import { detectXSS } from '../utils/security'

export class DOMObserver {
  private observer: MutationObserver | null = null
  private threatCallback?: (threat: ThreatDetection) => void

  initialize() {
    this.setupDOMObserver()
    console.log('👁️ DOM Observer initialized')
  }

  setThreatCallback(callback: (threat: ThreatDetection) => void) {
    this.threatCallback = callback
  }

  private setupDOMObserver() {
    this.observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        this.handleMutation(mutation)
      })
    })

    // 开始观察
    this.observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['src', 'href', 'onclick', 'onload', 'onerror'],
      characterData: true
    })
  }

  private handleMutation(mutation: MutationRecord) {
    switch (mutation.type) {
      case 'childList':
        this.handleChildListMutation(mutation)
        break
      case 'attributes':
        this.handleAttributeMutation(mutation)
        break
      case 'characterData':
        this.handleCharacterDataMutation(mutation)
        break
    }
  }

  private handleChildListMutation(mutation: MutationRecord) {
    mutation.addedNodes.forEach((node) => {
      if (node.nodeType === Node.ELEMENT_NODE) {
        this.analyzeAddedElement(node as Element)
      }
    })
  }

  private handleAttributeMutation(mutation: MutationRecord) {
    const target = mutation.target as Element
    const attributeName = mutation.attributeName
    
    if (!attributeName) return
    
    const newValue = target.getAttribute(attributeName)
    if (!newValue) return
    
    // 检查危险属性
    if (this.isDangerousAttribute(attributeName, newValue)) {
      this.reportThreat({
        id: `dangerous_attribute_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        type: 'xss_attack',
        level: 'medium',
        url: window.location.href,
        description: `检测到危险属性: ${attributeName}="${newValue.substring(0, 50)}"`,
        timestamp: Date.now(),
        blocked: false,
        details: {
          element: target.tagName,
          attribute: attributeName,
          value: newValue.substring(0, 200)
        }
      })
    }
  }

  private handleCharacterDataMutation(mutation: MutationRecord) {
    const target = mutation.target
    const content = target.textContent || ''
    
    // 检查文本内容中的XSS
    const xssResult = detectXSS(content)
    if (xssResult.detected) {
      this.reportThreat({
        id: `text_xss_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        type: 'xss_attack',
        level: 'medium',
        url: window.location.href,
        description: '检测到文本内容中的XSS模式',
        timestamp: Date.now(),
        blocked: false,
        details: {
          content: content.substring(0, 200),
          patterns: xssResult.patterns.map(p => p.id)
        }
      })
    }
  }

  private analyzeAddedElement(element: Element) {
    // 检查脚本标签
    if (element.tagName === 'SCRIPT') {
      this.analyzeScriptElement(element as HTMLScriptElement)
    }
    
    // 检查iframe标签
    if (element.tagName === 'IFRAME') {
      this.analyzeIframeElement(element as HTMLIFrameElement)
    }
    
    // 检查表单标签
    if (element.tagName === 'FORM') {
      this.analyzeFormElement(element as HTMLFormElement)
    }
    
    // 检查元素内容
    const content = element.innerHTML
    if (content) {
      const xssResult = detectXSS(content)
      if (xssResult.detected) {
        this.reportThreat({
          id: `dynamic_xss_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          type: 'xss_attack',
          level: 'high',
          url: window.location.href,
          description: '检测到动态添加的XSS内容',
          timestamp: Date.now(),
          blocked: false,
          details: {
            element: element.tagName,
            content: content.substring(0, 200),
            patterns: xssResult.patterns.map(p => p.id)
          }
        })
      }
    }
    
    // 递归检查子元素
    element.querySelectorAll('*').forEach(child => {
      this.analyzeAddedElement(child)
    })
  }

  private analyzeScriptElement(script: HTMLScriptElement) {
    const src = script.src
    const content = script.textContent || script.innerHTML
    
    if (src) {
      // 外部脚本
      if (!this.isTrustedDomain(src)) {
        this.reportThreat({
          id: `dynamic_external_script_${Date.now()}`,
          type: 'suspicious_script',
          level: 'high',
          url: window.location.href,
          description: `动态加载外部脚本: ${new URL(src).hostname}`,
          timestamp: Date.now(),
          blocked: false,
          details: { src }
        })
      }
    } else if (content) {
      // 内联脚本
      this.reportThreat({
        id: `dynamic_inline_script_${Date.now()}`,
        type: 'suspicious_script',
        level: 'high',
        url: window.location.href,
        description: '动态添加内联脚本',
        timestamp: Date.now(),
        blocked: false,
        details: {
          content: content.substring(0, 200)
        }
      })
    }
  }

  private analyzeIframeElement(iframe: HTMLIFrameElement) {
    const src = iframe.src
    
    if (src && !this.isTrustedDomain(src)) {
      this.reportThreat({
        id: `dynamic_iframe_${Date.now()}`,
        type: 'suspicious_script',
        level: 'medium',
        url: window.location.href,
        description: `动态添加外部iframe: ${new URL(src).hostname}`,
        timestamp: Date.now(),
        blocked: false,
        details: { src }
      })
    }
  }

  private analyzeFormElement(form: HTMLFormElement) {
    const action = form.action
    
    if (action && action !== window.location.href) {
      try {
        const actionUrl = new URL(action)
        const currentUrl = new URL(window.location.href)
        
        if (actionUrl.hostname !== currentUrl.hostname) {
          this.reportThreat({
            id: `dynamic_cross_domain_form_${Date.now()}`,
            type: 'suspicious_script',
            level: 'medium',
            url: window.location.href,
            description: `动态添加跨域表单: ${actionUrl.hostname}`,
            timestamp: Date.now(),
            blocked: false,
            details: { action }
          })
        }
      } catch (error) {
        // 无效URL
      }
    }
  }

  private isDangerousAttribute(name: string, value: string): boolean {
    // 事件处理器属性
    if (name.startsWith('on')) {
      return true
    }
    
    // 危险的src/href值
    if ((name === 'src' || name === 'href') && value.startsWith('javascript:')) {
      return true
    }
    
    // 检查属性值中的脚本
    const xssResult = detectXSS(value)
    return xssResult.detected
  }

  private isTrustedDomain(url: string): boolean {
    try {
      const hostname = new URL(url).hostname
      const trustedDomains = [
        window.location.hostname,
        // 常见 CDN
        'cdnjs.cloudflare.com',
        'ajax.googleapis.com',
        'code.jquery.com',
        'cdn.jsdelivr.net',
        'unpkg.com',
        'jsdelivr.net',
        // 大型网站的资源域名
        'twimg.com',
        'abs.twimg.com',
        'pbs.twimg.com',
        'ton.twimg.com',
        'facebook.net',
        'fbcdn.net',
        'gstatic.com',
        'googleusercontent.com',
        'cloudflare.com',
        'cloudflareinsights.com',
        'cloudfront.net'
      ]
      
      return trustedDomains.some(trusted => 
        hostname === trusted || hostname.endsWith('.' + trusted)
      )
    } catch {
      return false
    }
  }

  private reportThreat(threat: ThreatDetection) {
    if (this.threatCallback) {
      this.threatCallback(threat)
    }
    // 日志已在 handleThreat 中统一输出，这里不再重复
  }

  destroy() {
    if (this.observer) {
      this.observer.disconnect()
      this.observer = null
    }
  }
}

