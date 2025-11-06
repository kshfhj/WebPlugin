/**
 * 类型定义入口文件
 */

export * from './security'

// 全局类型扩展
declare global {
  interface Window {
    webSecurityGuardian?: {
      version: string
      isActive: boolean
    }
  }
}

// Chrome扩展API类型扩展
declare module 'webextension-polyfill' {
  namespace Runtime {
    interface Port {
      name: string
      sender?: any
    }
  }
}
