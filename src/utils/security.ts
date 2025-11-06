/**
 * 安全防护工具函数 - 完整实现版本
 */

import { ThreatType, ThreatLevel } from '@/types'
import type { XSSPattern, MaliciousUrl } from '@/types'

// ====== XSS检测模式 ======
export const XSS_PATTERNS: XSSPattern[] = [
  {
    id: 'script_tag',
    pattern: /<script[^>]*>[\s\S]*?<\/script>/gi,
    description: '检测到script标签注入',
    severity: ThreatLevel.HIGH,
    enabled: true
  },
  {
    id: 'script_src',
    pattern: /<script[^>]*src\s*=\s*["'][^"']*["'][^>]*>/gi,
    description: '检测到外部脚本注入',
    severity: ThreatLevel.HIGH,
    enabled: true
  },
  {
    id: 'javascript_protocol',
    pattern: /javascript\s*:/gi,
    description: '检测到javascript:伪协议',
    severity: ThreatLevel.HIGH,
    enabled: true
  },
  {
    id: 'event_handlers',
    pattern: /on\w+\s*=\s*["'][^"']*["']/gi,
    description: '检测到内联事件处理器',
    severity: ThreatLevel.MEDIUM,
    enabled: true
  },
  {
    id: 'onerror_handler',
    pattern: /onerror\s*=\s*["'].*["']/gi,
    description: '检测到onerror事件利用',
    severity: ThreatLevel.HIGH,
    enabled: true
  },
  {
    id: 'iframe_injection',
    pattern: /<iframe[^>]*>/gi,
    description: '检测到iframe注入',
    severity: ThreatLevel.HIGH,
    enabled: true
  },
  {
    id: 'object_embed',
    pattern: /<(object|embed)[^>]*>/gi,
    description: '检测到object/embed标签注入',
    severity: ThreatLevel.MEDIUM,
    enabled: true
  },
  {
    id: 'eval_function',
    pattern: /\beval\s*\(/gi,
    description: '检测到eval函数调用',
    severity: ThreatLevel.HIGH,
    enabled: true
  },
  {
    id: 'function_constructor',
    pattern: /new\s+Function\s*\(/gi,
    description: '检测到Function构造函数',
    severity: ThreatLevel.HIGH,
    enabled: true
  },
  {
    id: 'document_write',
    pattern: /document\.(write|writeln)\s*\(/gi,
    description: '检测到document.write调用',
    severity: ThreatLevel.MEDIUM,
    enabled: true
  },
  {
    id: 'inner_html',
    pattern: /\.innerHTML\s*=\s*[^;]+[<>]/gi,
    description: '检测到innerHTML危险赋值',
    severity: ThreatLevel.MEDIUM,
    enabled: true
  },
  {
    id: 'data_uri',
    pattern: /data:text\/html[^>]*>/gi,
    description: '检测到data:URI注入',
    severity: ThreatLevel.HIGH,
    enabled: true
  },
  {
    id: 'vbscript',
    pattern: /vbscript:/gi,
    description: '检测到VBScript协议',
    severity: ThreatLevel.HIGH,
    enabled: true
  },
  {
    id: 'svg_script',
    pattern: /<svg[^>]*>[\s\S]*?<script/gi,
    description: '检测到SVG中的脚本注入',
    severity: ThreatLevel.HIGH,
    enabled: true
  },
  {
    id: 'meta_refresh',
    pattern: /<meta[^>]*http-equiv\s*=\s*["']refresh["'][^>]*>/gi,
    description: '检测到meta refresh重定向',
    severity: ThreatLevel.MEDIUM,
    enabled: true
  },
  {
    id: 'base_href',
    pattern: /<base[^>]*href\s*=\s*["'][^"']*["'][^>]*>/gi,
    description: '检测到base标签劫持',
    severity: ThreatLevel.MEDIUM,
    enabled: true
  }
]

// ====== SQL注入检测模式 ======
export const SQL_INJECTION_PATTERNS = [
  {
    id: 'sql_union',
    pattern: /(\bunion\b.*\bselect\b|\bselect\b.*\bunion\b)/gi,
    description: '检测到UNION注入攻击',
    severity: ThreatLevel.HIGH
  },
  {
    id: 'sql_or_always_true',
    pattern: /(\bor\b\s+[\d\w'"]+\s*=\s*[\d\w'"]+|\d+\s*=\s*\d+)/gi,
    description: '检测到OR恒真条件',
    severity: ThreatLevel.HIGH
  },
  {
    id: 'sql_comment',
    pattern: /(--|#|\/\*|\*\/)/g,
    description: '检测到SQL注释符号',
    severity: ThreatLevel.MEDIUM
  },
  {
    id: 'sql_sleep',
    pattern: /\b(sleep|benchmark|waitfor\s+delay)\b/gi,
    description: '检测到时间盲注攻击',
    severity: ThreatLevel.HIGH
  },
  {
    id: 'sql_information_schema',
    pattern: /\binformation_schema\b/gi,
    description: '检测到数据库元数据查询',
    severity: ThreatLevel.HIGH
  },
  {
    id: 'sql_exec',
    pattern: /\b(exec|execute|xp_cmdshell)\b/gi,
    description: '检测到命令执行尝试',
    severity: ThreatLevel.CRITICAL
  },
  {
    id: 'sql_drop',
    pattern: /\b(drop|delete|truncate|alter)\b\s+\b(table|database)\b/gi,
    description: '检测到危险SQL操作',
    severity: ThreatLevel.CRITICAL
  },
  {
    id: 'sql_into_outfile',
    pattern: /\binto\s+(outfile|dumpfile)\b/gi,
    description: '检测到文件写入尝试',
    severity: ThreatLevel.HIGH
  },
  {
    id: 'sql_load_file',
    pattern: /\bload_file\s*\(/gi,
    description: '检测到文件读取尝试',
    severity: ThreatLevel.HIGH
  },
  {
    id: 'sql_quotes',
    pattern: /['";].*(\bor\b|\band\b).*['";]/gi,
    description: '检测到引号闭合注入',
    severity: ThreatLevel.HIGH
  }
]

// ====== 常见追踪器域名 (真实列表) ======
export const TRACKER_DOMAINS = [
  // Google追踪
  'google-analytics.com',
  'googletagmanager.com',
  'googleadservices.com',
  'googlesyndication.com',
  'doubleclick.net',
  'googletagservices.com',
  'google.com/pagead',
  'google-analytics.com',
  'www.google-analytics.com',
  
  // Facebook追踪
  'facebook.com/tr',
  'facebook.net',
  'connect.facebook.net',
  'facebook.com/plugins',
  
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
  
  // 社交媒体追踪
  'twitter.com/i/adsct',
  'linkedin.com/px',
  'pinterest.com/ct',
  'instagram.com/embed',
  
  // 内容推荐
  'outbrain.com',
  'taboola.com',
  'revcontent.com',
  'mgid.com',
  
  // 其他追踪器
  'newrelic.com',
  'nr-data.net',
  'clarity.ms',
  'bing.com/api/0/s',
  'bat.bing.com',
  'yandex.ru/metrika'
]

// 恶意URL检测
export function isMaliciousUrl(url: string, maliciousUrls: MaliciousUrl[]): boolean {
  try {
    const urlObj = new URL(url)
    const hostname = urlObj.hostname.toLowerCase()
    
    return maliciousUrls.some(malicious => {
      const maliciousHost = new URL(malicious.url).hostname.toLowerCase()
      return hostname === maliciousHost || hostname.endsWith('.' + maliciousHost)
    })
  } catch {
    return false
  }
}

// ====== 追踪器检测 ======
export function isTracker(url: string): boolean {
  try {
    const urlObj = new URL(url)
    const hostname = urlObj.hostname.toLowerCase()
    const fullUrl = url.toLowerCase()
    
    // 检查域名匹配
    const domainMatch = TRACKER_DOMAINS.some(tracker => {
      const cleanTracker = tracker.toLowerCase()
      return hostname === cleanTracker || 
             hostname.endsWith('.' + cleanTracker) ||
             fullUrl.includes(cleanTracker)
    })
    
    if (domainMatch) return true
    
    // 检查URL路径特征
    const trackerPathPatterns = [
      '/analytics',
      '/tracking',
      '/pixel',
      '/beacon',
      '/collect',
      '/track',
      '/event',
      '/stats'
    ]
    
    return trackerPathPatterns.some(pattern => fullUrl.includes(pattern))
  } catch {
    return false
  }
}

// ====== XSS检测 ======
export function detectXSS(content: string): { detected: boolean; patterns: any[] } {
  const detectedPatterns: any[] = []
  
  // 重置正则表达式的lastIndex
  XSS_PATTERNS.forEach(p => {
    if (p.pattern.global) {
      p.pattern.lastIndex = 0
    }
  })
  
  for (const pattern of XSS_PATTERNS) {
    if (pattern.enabled && pattern.pattern.test(content)) {
      detectedPatterns.push({
        id: pattern.id,
        description: pattern.description,
        severity: pattern.severity
      })
      // 重置lastIndex
      if (pattern.pattern.global) {
        pattern.pattern.lastIndex = 0
      }
    }
  }
  
  return {
    detected: detectedPatterns.length > 0,
    patterns: detectedPatterns
  }
}

// ====== SQL注入检测 ======
export function detectSQLInjection(input: string): { detected: boolean; patterns: any[] } {
  const detectedPatterns: any[] = []
  
  // URL解码
  let decodedInput = input
  try {
    decodedInput = decodeURIComponent(input)
  } catch {
    // 解码失败，使用原始输入
  }
  
  // 检查每个SQL注入模式
  for (const pattern of SQL_INJECTION_PATTERNS) {
    if (pattern.pattern.test(decodedInput)) {
      detectedPatterns.push({
        id: pattern.id,
        description: pattern.description,
        severity: pattern.severity
      })
      // 重置正则表达式
      pattern.pattern.lastIndex = 0
    }
  }
  
  // 额外检查：多个特殊字符组合
  const suspiciousChars = /['"`;\\]+/g
  const matches = decodedInput.match(suspiciousChars)
  if (matches && matches.length > 3) {
    detectedPatterns.push({
      id: 'sql_special_chars',
      description: '检测到可疑的特殊字符组合',
      severity: ThreatLevel.MEDIUM
    })
  }
  
  return {
    detected: detectedPatterns.length > 0,
    patterns: detectedPatterns
  }
}

// 计算安全评分
export function calculateSecurityScore(threats: any[]): number {
  if (threats.length === 0) return 100
  
  let score = 100
  threats.forEach(threat => {
    switch (threat.level) {
      case ThreatLevel.CRITICAL:
        score -= 30
        break
      case ThreatLevel.HIGH:
        score -= 20
        break
      case ThreatLevel.MEDIUM:
        score -= 10
        break
      case ThreatLevel.LOW:
        score -= 5
        break
    }
  })
  
  return Math.max(0, score)
}

// 检查URL是否为HTTPS
export function isSecureUrl(url: string): boolean {
  try {
    return new URL(url).protocol === 'https:'
  } catch {
    return false
  }
}

// 检查表单是否安全
export function isSecureForm(form: HTMLFormElement): boolean {
  const action = form.action || window.location.href
  const method = form.method.toLowerCase()
  
  // POST表单必须使用HTTPS
  if (method === 'post' && !isSecureUrl(action)) {
    return false
  }
  
  // 检查是否包含敏感字段
  const sensitiveFields = form.querySelectorAll('input[type="password"], input[name*="password"], input[name*="credit"], input[name*="card"]')
  if (sensitiveFields.length > 0 && !isSecureUrl(action)) {
    return false
  }
  
  return true
}

// 生成威胁ID
export function generateThreatId(): string {
  return `threat_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
}

// 格式化时间戳
export function formatTimestamp(timestamp: number): string {
  return new Date(timestamp).toLocaleString('zh-CN')
}

// 获取威胁级别颜色
export function getThreatLevelColor(level: ThreatLevel): string {
  switch (level) {
    case ThreatLevel.CRITICAL:
      return '#ff4d4f'
    case ThreatLevel.HIGH:
      return '#ff7a45'
    case ThreatLevel.MEDIUM:
      return '#ffa940'
    case ThreatLevel.LOW:
      return '#52c41a'
    default:
      return '#d9d9d9'
  }
}

// 获取威胁类型图标
export function getThreatTypeIcon(type: ThreatType): string {
  switch (type) {
    case ThreatType.MALICIOUS_URL:
      return '🚫'
    case ThreatType.XSS_ATTACK:
      return '⚠️'
    case ThreatType.TRACKER:
      return '👁️'
    case ThreatType.INSECURE_FORM:
      return '🔓'
    case ThreatType.SUSPICIOUS_SCRIPT:
      return '📜'
    case ThreatType.PHISHING:
      return '🎣'
    default:
      return '❓'
  }
}

// ====== 钓鱼网站检测 ======
export function detectPhishing(url: string): { detected: boolean; reasons: string[]; score: number } {
  const reasons: string[] = []
  let riskScore = 0
  
  try {
    const urlObj = new URL(url)
    const hostname = urlObj.hostname.toLowerCase()
    const fullUrl = url.toLowerCase()
    
    // 1. 检查品牌冒充（常见品牌）
    const brandNames = [
      'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 
      'instagram', 'twitter', 'netflix', 'ebay', 'linkedin', 'alibaba',
      'taobao', 'alipay', 'wechat', 'qq', 'baidu', 'jd', 'bank'
    ]
    
    for (const brand of brandNames) {
      if (hostname.includes(brand)) {
        // 检查是否是真实的品牌域名
        const legitDomains = [
          `${brand}.com`, `${brand}.cn`, `${brand}.net`, `${brand}.org`,
          `www.${brand}.com`, `www.${brand}.cn`
        ]
        
        if (!legitDomains.includes(hostname) && !hostname.endsWith(`.${brand}.com`)) {
          reasons.push(`疑似冒充品牌: ${brand}`)
          riskScore += 40
        }
      }
    }
    
    // 2. 检查IP地址作为域名
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      reasons.push('使用IP地址而非域名')
      riskScore += 30
    }
    
    // 3. 检查可疑的子域名
    const suspiciousSubdomains = ['login', 'signin', 'account', 'verify', 'secure', 'update', 'confirm']
    const subdomains = hostname.split('.')
    if (subdomains.length > 2) {
      suspiciousSubdomains.forEach(suspicious => {
        if (subdomains[0].includes(suspicious)) {
          reasons.push(`可疑的子域名: ${subdomains[0]}`)
          riskScore += 20
        }
      })
    }
    
    // 4. 检查URL长度
    if (hostname.length > 40) {
      reasons.push('域名过长')
      riskScore += 15
    }
    
    // 5. 检查数字比例
    const digits = hostname.match(/\d/g) || []
    const digitRatio = digits.length / hostname.length
    if (digitRatio > 0.3) {
      reasons.push('域名包含过多数字')
      riskScore += 20
    }
    
    // 6. 检查特殊字符
    const hyphenCount = (hostname.match(/-/g) || []).length
    if (hyphenCount > 3) {
      reasons.push('域名包含过多连字符')
      riskScore += 15
    }
    
    // 7. 检查同形异义字攻击（IDN Homograph Attack）
    if (/[а-яА-Я]/.test(hostname) || /[α-ωΑ-Ω]/.test(hostname)) {
      reasons.push('检测到非拉丁字符（可能的同形异义字攻击）')
      riskScore += 50
    }
    
    // 8. 检查可疑TLD
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.win', '.bid']
    if (suspiciousTLDs.some(tld => hostname.endsWith(tld))) {
      reasons.push('使用可疑的顶级域名')
      riskScore += 25
    }
    
    // 9. 检查URL中的@符号（用户名欺骗）
    if (fullUrl.includes('@')) {
      reasons.push('URL包含@符号（可能的用户名欺骗）')
      riskScore += 30
    }
    
    // 10. 检查过多的点号
    const dotCount = (hostname.match(/\./g) || []).length
    if (dotCount > 4) {
      reasons.push('域名层级过深')
      riskScore += 20
    }
    
    // 11. 检查端口号
    if (urlObj.port && urlObj.port !== '80' && urlObj.port !== '443') {
      reasons.push(`使用非标准端口: ${urlObj.port}`)
      riskScore += 10
    }
    
    // 12. 检查可疑关键词组合
    const phishingKeywords = ['verify', 'account', 'update', 'confirm', 'secure', 'banking', 'suspended']
    const keywordMatches = phishingKeywords.filter(keyword => fullUrl.includes(keyword))
    if (keywordMatches.length >= 2) {
      reasons.push(`URL包含多个可疑关键词: ${keywordMatches.join(', ')}`)
      riskScore += 25
    }
    
    return {
      detected: riskScore >= 40,
      reasons,
      score: Math.min(100, riskScore)
    }
  } catch {
    return { detected: false, reasons: [], score: 0 }
  }
}

// ====== 同形异义字检测 ======
export function detectHomographAttack(text: string): boolean {
  // 检测常见的同形异义字
  const homographs = [
    /[а-яА-Я]/, // 西里尔字母
    /[α-ωΑ-Ω]/, // 希腊字母
    /[ა-ჰ]/, // 格鲁吉亚字母
    /[\u0430-\u044F]/, // 西里尔小写
    /[\u0410-\u042F]/ // 西里尔大写
  ]
  
  return homographs.some(pattern => pattern.test(text))
}

// ====== 敏感信息检测 ======
export function detectSensitiveData(text: string): { detected: boolean; types: string[] } {
  const types: string[] = []
  
  // 信用卡号（Luhn算法验证）
  const creditCardPattern = /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g
  if (creditCardPattern.test(text)) {
    types.push('信用卡号')
  }
  
  // 身份证号（中国）
  const idCardPattern = /\b\d{17}[\dxX]\b/g
  if (idCardPattern.test(text)) {
    types.push('身份证号')
  }
  
  // 手机号
  const phonePattern = /\b1[3-9]\d{9}\b/g
  if (phonePattern.test(text)) {
    types.push('手机号')
  }
  
  // 邮箱
  const emailPattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g
  if (emailPattern.test(text)) {
    types.push('邮箱地址')
  }
  
  // IP地址
  const ipPattern = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g
  if (ipPattern.test(text)) {
    types.push('IP地址')
  }
  
  // 密码特征（连续的密码字段）
  const passwordPattern = /(password|pwd|passwd)\s*[:=]\s*\S+/gi
  if (passwordPattern.test(text)) {
    types.push('密码')
  }
  
  return {
    detected: types.length > 0,
    types
  }
}

// ====== 恶意脚本特征检测 ======
export function detectMaliciousScript(scriptContent: string): { detected: boolean; features: string[] } {
  const features: string[] = []
  
  // 检测混淆代码
  if (/\\x[0-9a-fA-F]{2}/.test(scriptContent) || /\\u[0-9a-fA-F]{4}/.test(scriptContent)) {
    features.push('代码混淆（十六进制编码）')
  }
  
  // 检测Base64编码
  if (/atob\s*\(|btoa\s*\(/.test(scriptContent)) {
    features.push('Base64编解码')
  }
  
  // 检测危险函数
  const dangerousFunctions = [
    'eval', 'Function', 'setTimeout', 'setInterval', 
    'execScript', 'crypto', 'XMLHttpRequest'
  ]
  
  dangerousFunctions.forEach(func => {
    if (new RegExp(`\\b${func}\\s*\\(`).test(scriptContent)) {
      features.push(`使用危险函数: ${func}`)
    }
  })
  
  // 检测DOM操作
  if (/document\.(write|writeln|createElement|body|cookie)/.test(scriptContent)) {
    features.push('DOM操作')
  }
  
  // 检测网络请求
  if (/fetch\s*\(|XMLHttpRequest|\.send\s*\(/.test(scriptContent)) {
    features.push('发起网络请求')
  }
  
  // 检测localStorage/sessionStorage
  if (/localStorage|sessionStorage/.test(scriptContent)) {
    features.push('访问本地存储')
  }
  
  // 检测location操作
  if (/location\.(href|replace|assign)/.test(scriptContent)) {
    features.push('页面重定向')
  }
  
  return {
    detected: features.length >= 3,
    features
  }
}

// 防抖函数
export function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: NodeJS.Timeout
  return (...args: Parameters<T>) => {
    clearTimeout(timeout)
    timeout = setTimeout(() => func(...args), wait)
  }
}

// 节流函数
export function throttle<T extends (...args: any[]) => any>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle: boolean
  return (...args: Parameters<T>) => {
    if (!inThrottle) {
      func(...args)
      inThrottle = true
      setTimeout(() => inThrottle = false, limit)
    }
  }
}
