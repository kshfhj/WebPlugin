/**
 * 表单监控器 - 负责监控表单安全（增强版）
 */

import type { ThreatDetection } from '../types'
import { isSecureForm, detectSQLInjection, detectXSS, detectSensitiveData } from '../utils/security'

export class FormMonitor {
  private formListeners: Map<HTMLFormElement, () => void> = new Map()
  
  initialize() {
    console.log('📝 Form Monitor initialized')
    this.setupFormMonitoring()
  }
  
  // 设置表单实时监控
  private setupFormMonitoring() {
    // 监听所有表单提交
    document.addEventListener('submit', (e) => {
      if (e.target instanceof HTMLFormElement) {
        this.onFormSubmit(e)
      }
    }, true)
    
    // 监听动态添加的表单
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node instanceof HTMLFormElement) {
            this.monitorForm(node)
          } else if (node instanceof HTMLElement) {
            const forms = node.querySelectorAll('form')
            forms.forEach(form => this.monitorForm(form))
          }
        })
      })
    })
    
    observer.observe(document.body, {
      childList: true,
      subtree: true
    })
  }
  
  // 监控单个表单
  private monitorForm(form: HTMLFormElement) {
    if (this.formListeners.has(form)) return
    
    const submitHandler = (e: Event) => {
      this.onFormSubmit(e as SubmitEvent)
    }
    
    form.addEventListener('submit', submitHandler, true)
    this.formListeners.set(form, submitHandler)
  }
  
  // 表单提交事件处理
  private onFormSubmit(e: SubmitEvent) {
    const form = e.target as HTMLFormElement
    const threats = this.analyzeFormSubmit(form)
    
    if (threats.length > 0) {
      // 检查是否有高危威胁
      const hasCriticalThreat = threats.some(t => t.level === 'critical' || t.level === 'high')
      
      if (hasCriticalThreat) {
        // 阻止表单提交并警告用户
        e.preventDefault()
        this.showWarning(threats)
        
        // 发送威胁报告到background
        this.reportThreats(threats)
      }
    }
  }
  
  // 显示警告
  private showWarning(threats: ThreatDetection[]) {
    const message = threats.map(t => `• ${t.description}`).join('\n')
    alert(`⚠️ 检测到安全威胁：\n\n${message}\n\n为了您的安全，表单提交已被阻止。`)
  }
  
  // 报告威胁
  private reportThreats(threats: ThreatDetection[]) {
    // 发送到background script
    if (typeof chrome !== 'undefined' && chrome.runtime) {
      chrome.runtime.sendMessage({
        type: 'THREAT_DETECTED',
        threats
      }).catch(err => console.error('Failed to report threats:', err))
    }
  }

  async scanForms(): Promise<ThreatDetection[]> {
    const threats: ThreatDetection[] = []
    const forms = document.querySelectorAll('form')
    
    forms.forEach((form, index) => {
      const formThreats = this.analyzeForm(form, index)
      threats.push(...formThreats)
    })
    
    return threats
  }

  async checkFormSecurity(form: HTMLFormElement): Promise<boolean> {
    return isSecureForm(form)
  }
  
  // 分析表单提交内容
  private analyzeFormSubmit(form: HTMLFormElement): ThreatDetection[] {
    const threats: ThreatDetection[] = []
    const formData = new FormData(form)
    
    // 检查每个字段的值
    for (const [name, value] of formData.entries()) {
      if (typeof value === 'string') {
        // SQL注入检测
        const sqlResult = detectSQLInjection(value)
        if (sqlResult.detected) {
          sqlResult.patterns.forEach(pattern => {
            threats.push({
              id: `sql_injection_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
              type: 'sql_injection',
              level: pattern.severity,
              url: window.location.href,
              description: `表单字段 "${name}" 包含SQL注入攻击: ${pattern.description}`,
              timestamp: Date.now(),
              blocked: true,
              details: { field: name, value: value.substring(0, 100), pattern: pattern.id }
            })
          })
        }
        
        // XSS检测
        const xssResult = detectXSS(value)
        if (xssResult.detected) {
          xssResult.patterns.forEach(pattern => {
            threats.push({
              id: `xss_form_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
              type: 'xss_attack',
              level: pattern.severity,
              url: window.location.href,
              description: `表单字段 "${name}" 包含XSS攻击: ${pattern.description}`,
              timestamp: Date.now(),
              blocked: true,
              details: { field: name, value: value.substring(0, 100), pattern: pattern.id }
            })
          })
        }
        
        // 敏感信息检测
        const sensitiveResult = detectSensitiveData(value)
        if (sensitiveResult.detected && !form.action.startsWith('https://')) {
          threats.push({
            id: `sensitive_data_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            type: 'insecure_form',
            level: 'high',
            url: window.location.href,
            description: `表单在非HTTPS连接下传输敏感信息: ${sensitiveResult.types.join(', ')}`,
            timestamp: Date.now(),
            blocked: true,
            details: { field: name, types: sensitiveResult.types }
          })
        }
      }
    }
    
    return threats
  }

  private analyzeForm(form: HTMLFormElement, index: number): ThreatDetection[] {
    const threats: ThreatDetection[] = []
    const action = form.action || window.location.href
    const method = form.method.toLowerCase()
    
    // 检查表单是否通过HTTPS提交
    if (method === 'post' && !action.startsWith('https://')) {
      const hasPasswordField = form.querySelector('input[type="password"]')
      const hasSensitiveFields = this.hasSensitiveFields(form)
      
      if (hasPasswordField || hasSensitiveFields) {
        threats.push({
          id: `insecure_form_${Date.now()}_${index}`,
          type: 'insecure_form',
          level: 'high',
          url: window.location.href,
          description: '表单包含敏感信息但未使用HTTPS提交',
          timestamp: Date.now(),
          blocked: false,
          details: {
            action,
            method,
            hasPassword: !!hasPasswordField,
            hasSensitiveFields
          }
        })
      }
    }
    
    // 检查表单目标域名
    if (action && action !== window.location.href) {
      try {
        const actionUrl = new URL(action)
        const currentUrl = new URL(window.location.href)
        
        if (actionUrl.hostname !== currentUrl.hostname) {
          threats.push({
            id: `cross_domain_form_${Date.now()}_${index}`,
            type: 'suspicious_script',
            level: 'medium',
            url: window.location.href,
            description: `表单提交到外部域名: ${actionUrl.hostname}`,
            timestamp: Date.now(),
            blocked: false,
            details: { action, targetDomain: actionUrl.hostname }
          })
        }
      } catch (error) {
        // 无效的URL
        threats.push({
          id: `invalid_form_action_${Date.now()}_${index}`,
          type: 'suspicious_script',
          level: 'medium',
          url: window.location.href,
          description: '表单action包含无效URL',
          timestamp: Date.now(),
          blocked: false,
          details: { action }
        })
      }
    }
    
    return threats
  }

  private hasSensitiveFields(form: HTMLFormElement): boolean {
    const inputs = form.querySelectorAll('input, textarea')
    const sensitivePatterns = [
      /password/i,
      /credit.*card/i,
      /social.*security/i,
      /ssn/i,
      /银行卡/i,
      /密码/i,
      /身份证/i,
      /phone/i,
      /email/i,
      /address/i
    ]
    
    for (const input of inputs) {
      const element = input as HTMLInputElement | HTMLTextAreaElement
      const fieldText = `${element.name} ${element.placeholder} ${element.id}`.toLowerCase()
      
      if (sensitivePatterns.some(pattern => pattern.test(fieldText))) {
        return true
      }
      
      // 检查input类型
      if (element instanceof HTMLInputElement) {
        const sensitiveTypes = ['password', 'email', 'tel']
        if (sensitiveTypes.includes(element.type)) {
          return true
        }
      }
    }
    
    return false
  }

  private getFieldLabel(input: HTMLInputElement | HTMLTextAreaElement): string {
    const id = input.id
    if (id) {
      const label = document.querySelector(`label[for="${id}"]`)
      if (label) return label.textContent || ''
    }
    
    const parentLabel = input.closest('label')
    if (parentLabel) return parentLabel.textContent || ''
    
    return ''
  }
}
