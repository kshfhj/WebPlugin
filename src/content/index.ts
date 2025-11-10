import { DOMObserver } from './dom-observer'
import { FormMonitor } from './form-monitor'
import { ScriptMonitor } from './script-monitor'
import { PageAnalyzer } from './page-analyzer'
import { detectPhishing, generateThreatId } from '../utils/security'
import { ThreatLevel, ThreatType, type ThreatDetection } from '../types'

declare const chrome: any

/**
 * Content Script - 在网页上下文中运行的实时安全监控器
 */

console.log('🛡️ Web Security Guardian 内容脚本启动:', window.location.href)

const domObserver = new DOMObserver()
const formMonitor = new FormMonitor()
const scriptMonitor = new ScriptMonitor()
const pageAnalyzer = new PageAnalyzer()

const displayedThreatIds = new Set<string>()
const reportedThreatIds = new Set<string>()
const threatFingerprints = new Set<string>()
const pendingToasts: ThreatDetection[] = []

// ===== 基础工具 =====

function hasChromeRuntime(): boolean {
  return typeof chrome !== 'undefined' && !!chrome.runtime?.sendMessage
}

function notifyBackground(threat: ThreatDetection) {
  if (!hasChromeRuntime()) return
  if (reportedThreatIds.has(threat.id)) return
  reportedThreatIds.add(threat.id)
  chrome.runtime
    .sendMessage({
      type: 'THREAT_DETECTED',
      threat
    })
    .catch((error: unknown) => console.error('Failed to notify background:', error))
}

function getThreatTypeLabel(type: ThreatType): string {
  switch (type) {
    case ThreatType.MALICIOUS_URL:
      return '恶意网址'
    case ThreatType.XSS_ATTACK:
      return 'XSS攻击'
    case ThreatType.SQL_INJECTION:
      return 'SQL注入'
    case ThreatType.TRACKER:
      return '追踪器'
    case ThreatType.INSECURE_FORM:
      return '不安全传输'
    case ThreatType.SUSPICIOUS_SCRIPT:
      return '可疑脚本'
    case ThreatType.PHISHING:
      return '钓鱼风险'
    case ThreatType.DATA_LEAK:
      return '敏感信息泄露'
    default:
      return '安全警告'
  }
}

function getThreatGradient(level: ThreatLevel): string {
  switch (level) {
    case ThreatLevel.CRITICAL:
      return 'linear-gradient(135deg, #ff1744, #b71c1c)'
    case ThreatLevel.HIGH:
      return 'linear-gradient(135deg, #ff6b6b, #d32f2f)'
    case ThreatLevel.MEDIUM:
      return 'linear-gradient(135deg, #ffb74d, #f57c00)'
    case ThreatLevel.LOW:
      return 'linear-gradient(135deg, #66bb6a, #2e7d32)'
    default:
      return 'linear-gradient(135deg, #607d8b, #455a64)'
  }
}

function showThreatToast(threat: ThreatDetection) {
  if (!document.body) {
    pendingToasts.push(threat)
    return
  }

  let hostname = threat.url
  try {
    hostname = new URL(threat.url).hostname
  } catch {
    // ignore
  }

  const containerId = 'wsg-threat-container'
  let container = document.getElementById(containerId)
  if (!container) {
    container = document.createElement('div')
    container.id = containerId
    container.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      display: flex;
      flex-direction: column;
      gap: 12px;
      z-index: 100000;
      max-width: 340px;
      pointer-events: none;
    `
    document.body.appendChild(container)
  }

  const toast = document.createElement('div')
  toast.style.cssText = `
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 14px 16px;
    border-radius: 14px;
    color: #fff;
    box-shadow: 0 14px 28px rgba(0,0,0,0.25);
    background: ${getThreatGradient(threat.level)};
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 13px;
    line-height: 1.5;
    pointer-events: auto;
    position: relative;
    overflow: hidden;
  `

  toast.innerHTML = `
    <div style="font-size: 20px; line-height: 1;">🛡️</div>
    <div style="flex: 1; min-width: 0;">
      <div style="font-weight: 600; font-size: 13px; margin-bottom: 4px;">
        ${getThreatTypeLabel(threat.type)} · ${threat.level.toUpperCase()}
      </div>
      <div style="font-size: 13px; word-break: break-word;">${threat.description}</div>
      <div style="margin-top: 6px; font-size: 12px; opacity: 0.85;">
        来源：${hostname}
      </div>
    </div>
    <button type="button" aria-label="关闭警告"
      style="background: transparent; border: none; color: #fff; font-size: 18px; cursor: pointer; line-height: 1;">×</button>
  `

  const closeButton = toast.querySelector('button')
  closeButton?.addEventListener('click', (event) => {
    event.stopPropagation()
    toast.remove()
  })

  container.appendChild(toast)

  setTimeout(() => {
    toast.style.opacity = '0'
    toast.style.transform = 'translateX(20px)'
    setTimeout(() => toast.remove(), 300)
  }, 6000)
}

function flushPendingToasts() {
  if (!pendingToasts.length) return
  const queue = [...pendingToasts]
  pendingToasts.length = 0
  queue.forEach(showThreatToast)
}

function handleThreat(threat: ThreatDetection, options: { notifyBackground?: boolean } = {}) {
  console.warn('🚨 Web Security Guardian Threat Detected:', threat)

  const fingerprint = createThreatFingerprint(threat)

  if (!displayedThreatIds.has(threat.id)) {
    displayedThreatIds.add(threat.id)
  }

  if (!threatFingerprints.has(fingerprint)) {
    threatFingerprints.add(fingerprint)
    showThreatToast(threat)
  }

  if (options.notifyBackground) {
    notifyBackground(threat)
  }
}

function createThreatFingerprint(threat: ThreatDetection): string {
  let hostname = threat.url
  try {
    hostname = new URL(threat.url).hostname
  } catch {
    // ignore
  }

  const detailKeys = ['pattern', 'field', 'src', 'function', 'args'] as const
  const detailValues = detailKeys
    .map((key) => (typeof threat.details?.[key] === 'string' ? threat.details?.[key] : ''))
    .filter(Boolean)

  return [threat.type, hostname, threat.description, ...detailValues]
    .join('|')
    .toLowerCase()
}

// ===== 基础标识 =====

const marker = document.createElement('meta')
marker.name = 'web-security-guardian'
marker.content = 'active'
document.head?.appendChild(marker)

;(window as any).webSecurityGuardian = {
  version: '1.0.0',
  isActive: true,
  reportThreat: (rawThreat: Partial<ThreatDetection>) => {
    const normalized: ThreatDetection = {
      id: rawThreat.id || generateThreatId(),
      type: rawThreat.type || ThreatType.DATA_LEAK,
      level: rawThreat.level || ThreatLevel.MEDIUM,
      url: rawThreat.url || window.location.href,
      description: rawThreat.description || '检测到未知安全威胁',
      timestamp: rawThreat.timestamp || Date.now(),
      blocked: rawThreat.blocked ?? false,
      details: rawThreat.details
    }
    handleThreat(normalized, { notifyBackground: true })
  }
}

// ===== 辅助检测 =====

function runBaselineChecks() {
  if (
    window.location.protocol !== 'https:' &&
    window.location.hostname !== 'localhost' &&
    !window.location.hostname.startsWith('127.0.0.')
  ) {
    const threat: ThreatDetection = {
      id: generateThreatId(),
      type: ThreatType.INSECURE_FORM,
      level: ThreatLevel.MEDIUM,
      url: window.location.href,
      description: '当前页面未使用HTTPS加密连接，谨慎输入敏感信息',
      timestamp: Date.now(),
      blocked: false
    }
    handleThreat(threat, { notifyBackground: true })
  }
}

function evaluateUrlRisk(url: string, source: string): boolean {
  try {
    // 规范化 URL
    const normalizedUrl = new URL(url, window.location.href).href
    const phishingResult = detectPhishing(normalizedUrl)
    if (phishingResult.detected) {
      const threat: ThreatDetection = {
        id: generateThreatId(),
        type: ThreatType.PHISHING,
        level: phishingResult.score >= 80 ? ThreatLevel.CRITICAL : ThreatLevel.HIGH,
        url: normalizedUrl,
        description: `检测到疑似钓鱼链接（来源：${source}）`,
        timestamp: Date.now(),
        blocked: true,
        details: {
          reasons: phishingResult.reasons,
          score: phishingResult.score,
          source
        }
      }
      handleThreat(threat, { notifyBackground: true })
      console.warn('🎣 钓鱼风险详情:', phishingResult.reasons)
      return true
    }
  } catch (error: unknown) {
    console.warn('无法解析URL进行安全检查:', url, error)
  }
  return false
}

function watchForSuspiciousLinks() {
  document.addEventListener(
    'click',
    (event) => {
      if (!(event.target instanceof Element)) return
      const anchor = event.target.closest('a[href]') as HTMLAnchorElement | null
      if (!anchor) return
      const url = anchor.href
      if (evaluateUrlRisk(url, 'anchor_click')) {
        event.preventDefault()
        event.stopImmediatePropagation()
      }
    },
    true
  )
}

function interceptWindowOpen() {
  const originalOpen = window.open
  window.open = function (...args: Parameters<typeof window.open>): ReturnType<typeof window.open> {
    const urlArg = args[0]
    const url = typeof urlArg === 'string' ? urlArg : urlArg?.toString?.()
    if (typeof url === 'string' && evaluateUrlRisk(url, 'window.open')) {
      return null
    }
    return originalOpen.apply(window, args)
  }
}

// ===== 启动监控 =====

function startAfterDomReady() {
  flushPendingToasts()

  domObserver.setThreatCallback((threat) => handleThreat(threat, { notifyBackground: true }))
  domObserver.initialize()

  formMonitor.setThreatCallback((threat) => handleThreat(threat))
  formMonitor.initialize()

  pageAnalyzer.initialize()
  pageAnalyzer.analyzePage().then((analysis) => {
    if (analysis.threats.length > 0) {
      analysis.threats.forEach((threat) => handleThreat(threat, { notifyBackground: true }))
    }
    if (hasChromeRuntime()) {
      chrome.runtime
        .sendMessage({
          type: 'PAGE_ANALYZED',
          analysis
        })
        .catch((error: unknown) => console.error('Failed to send PAGE_ANALYZED message:', error))
    }
  })

  runBaselineChecks()

  scriptMonitor.scanScripts().then((threats) => {
    threats.forEach((threat) => handleThreat(threat, { notifyBackground: true }))
  })

  formMonitor.scanForms().then((threats) => {
    threats.forEach((threat) => handleThreat(threat, { notifyBackground: true }))
  })

  watchForSuspiciousLinks()

  console.log('✅ Web Security Guardian 内容脚本已激活')
}

// ===== 脚本入口 =====

scriptMonitor.setThreatCallback((threat) => handleThreat(threat))
scriptMonitor.initialize()
interceptWindowOpen()

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', startAfterDomReady)
} else {
  startAfterDomReady()
}