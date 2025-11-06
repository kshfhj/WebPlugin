# Web Security Guardian - 安全防护功能详解

## 📋 功能概述

Web Security Guardian 是一款功能完整的浏览器安全防护插件，提供多层次的应用层安全防护，实时检测和阻止各种网络威胁。

---

## 🛡️ 核心防护功能

### 1. **恶意URL访问防护**

#### 功能特性
- ✅ 实时检测恶意域名和钓鱼网站
- ✅ IP地址域名检测
- ✅ 可疑TLD（顶级域名）识别
- ✅ 域名信任度评估
- ✅ 短链接警告

#### 检测方法
```typescript
// 恶意域名特征检测
- 已知恶意域名数据库匹配
- 域名长度和复杂度分析
- 数字/字符比例异常检测
- 可疑关键词组合识别
- 非标准端口使用检测
```

#### 阻止的威胁类型
- 恶意软件分发站点
- 钓鱼网站
- 诈骗网站
- 加密货币欺诈
- 仿冒品牌域名

**示例**：
- ❌ `paypal-secure-verify.com` （钓鱼）
- ❌ `amazon-account-verify.com` （钓鱼）
- ❌ `free-iphone-giveaway.com` （诈骗）
- ❌ `bitcoin-doubler.com` （加密货币诈骗）

---

### 2. **跨站脚本攻击（XSS）防护**

#### 功能特性
- ✅ 16+种XSS攻击模式检测
- ✅ 内联脚本监控
- ✅ 事件处理器注入检测
- ✅ DOM操作安全检查
- ✅ 危险函数拦截

#### 检测模式
```javascript
// XSS检测模式列表
1. <script> 标签注入
2. 外部脚本 <script src="..."> 注入
3. javascript: 伪协议
4. 内联事件处理器 (onclick, onerror, etc.)
5. onerror 事件利用
6. <iframe> 注入
7. <object>/<embed> 标签注入
8. eval() 函数调用
9. Function() 构造函数
10. document.write() 调用
11. innerHTML 危险赋值
12. data:URI 注入
13. vbscript: 协议
14. SVG中的脚本注入
15. meta refresh 重定向
16. <base> 标签劫持
```

#### 危险函数拦截
```javascript
// 实时拦截以下危险函数
- eval()
- Function()
- setTimeout(string)
- setInterval(string)
- execScript()
```

**测试示例**：
```javascript
// 这些代码会被检测到
<script>alert('XSS')</script>
<img src=x onerror="alert('XSS')">
<a href="javascript:alert('XSS')">Click</a>
eval('malicious code')
new Function('console.log("test")')
```

---

### 3. **SQL注入攻击防护**

#### 功能特性
- ✅ 10+种SQL注入模式检测
- ✅ 表单输入实时监控
- ✅ URL参数检测
- ✅ 特殊字符组合识别

#### 检测模式
```sql
-- SQL注入检测模式
1. UNION注入: UNION SELECT
2. OR恒真条件: OR '1'='1', OR 1=1
3. SQL注释符: --, #, /* */
4. 时间盲注: SLEEP(), BENCHMARK(), WAITFOR DELAY
5. 元数据查询: information_schema
6. 命令执行: exec, execute, xp_cmdshell
7. 危险操作: DROP TABLE, DELETE, TRUNCATE, ALTER
8. 文件操作: INTO OUTFILE, LOAD_FILE
9. 引号闭合: '; OR '1'='1
10. 特殊字符组合检测
```

**测试示例**：
```sql
-- 这些输入会被检测到
admin' OR '1'='1
'; DROP TABLE users--
1' UNION SELECT * FROM users--
' AND SLEEP(5)--
admin'--
1' OR 1=1--
```

#### 防护措施
- 表单提交前检测
- 高危输入阻止提交
- 用户警告提示
- 威胁日志记录

---

### 4. **第三方追踪器阻止**

#### 功能特性
- ✅ 60+个追踪器域名库
- ✅ 网络请求拦截
- ✅ Cookie阻止
- ✅ 隐私保护

#### 阻止的追踪器类别

**1. Google追踪服务**
```
- google-analytics.com
- googletagmanager.com
- googleadservices.com
- googlesyndication.com
- doubleclick.net
- googletagservices.com
```

**2. Facebook追踪**
```
- facebook.com/tr
- connect.facebook.net
- facebook.com/plugins
```

**3. 广告网络**
```
- criteo.com
- pubmatic.com
- rubiconproject.com
- amazon-adsystem.com
- adnxs.com
```

**4. 分析追踪**
```
- mixpanel.com
- segment.io
- amplitude.com
- hotjar.com
- fullstory.com
- crazyegg.com
```

**5. 内容推荐**
```
- outbrain.com
- taboola.com
- revcontent.com
- mgid.com
```

**效果**：
- 🚫 阻止追踪脚本加载
- 🚫 阻止数据收集请求
- 🚫 阻止广告和推荐内容
- ✅ 保护用户隐私

---

### 5. **钓鱼网站检测**

#### 功能特性
- ✅ 品牌冒充检测
- ✅ 同形异义字攻击识别
- ✅ 域名可信度评分
- ✅ URL特征分析

#### 检测算法
```javascript
// 钓鱼检测评分系统
风险因素：
1. 品牌名称冒充 (+40分)
2. IP地址作为域名 (+30分)
3. 可疑子域名 (+20分)
4. 域名过长 (+15分)
5. 过多数字 (+20分)
6. 过多连字符 (+15分)
7. 同形异义字 (+50分)
8. 可疑TLD (.tk, .ml, .ga等) (+25分)
9. URL中的@符号 (+30分)
10. 域名层级过深 (+20分)
11. 非标准端口 (+10分)
12. 可疑关键词组合 (+25分)

风险阈值：>= 40分判定为钓鱼网站
```

#### 同形异义字检测
```javascript
// 检测不同字母表的相似字符
аpple.com  // 西里尔字母 а 替代拉丁字母 a
paypaI.com // 大写 I 替代小写 l
g00gle.com // 数字 0 替代字母 o
```

**常见钓鱼特征**：
- `paypal-secure.com`
- `amazon-login-verify.com`
- `google-security-check.com`
- `microsoft-account-alert.com`
- `apple-id-verify.com`

---

### 6. **表单安全检查**

#### 功能特性
- ✅ HTTPS传输检测
- ✅ 敏感信息识别
- ✅ 跨域提交警告
- ✅ 实时输入监控

#### 敏感信息类型
```javascript
// 自动检测的敏感信息
1. 信用卡号 (Luhn算法验证)
2. 身份证号 (中国)
3. 手机号码
4. 邮箱地址
5. IP地址
6. 密码字段
```

#### 安全检查规则
```javascript
// 表单安全规则
✓ POST表单必须使用HTTPS
✓ 敏感信息必须加密传输
✗ HTTP表单传输密码 → 阻止
✗ HTTP表单传输信用卡 → 阻止
⚠️ 表单提交到外部域名 → 警告
```

**防护示例**：
```html
<!-- 不安全 - 会被阻止 -->
<form action="http://example.com/login" method="post">
  <input type="password" name="pwd">
  <input type="text" name="card" value="4111-1111-1111-1111">
</form>

<!-- 安全 -->
<form action="https://example.com/login" method="post">
  <input type="password" name="pwd">
</form>
```

---

### 7. **恶意脚本监控**

#### 功能特性
- ✅ 动态脚本注入监控
- ✅ 外部脚本来源检查
- ✅ 代码混淆检测
- ✅ 危险操作拦截

#### 监控内容
```javascript
// 监控的危险操作
1. 动态添加<script>标签
2. eval()调用
3. Function()构造函数
4. document.write()
5. innerHTML赋值
6. location.href修改
7. document.cookie访问
8. localStorage/sessionStorage访问
```

#### 混淆代码检测
```javascript
// 混淆特征识别
- 十六进制编码: \x41\x42
- Unicode编码: \u0041\u0042
- Base64编解码: atob(), btoa()
- 代码压缩（单行超长）
- 过多的特殊字符
```

---

## 🎯 使用方法

### 安装和启动

1. **构建插件**
```bash
npm install
npm run build:extension
```

2. **加载到浏览器**
   - 打开 `chrome://extensions/`
   - 开启"开发者模式"
   - 点击"加载已解压的扩展程序"
   - 选择 `dist-extension` 文件夹

3. **开始防护**
   - 插件自动启动
   - 实时监控网页安全
   - 点击图标查看防护状态

### 测试功能

使用提供的 `test-security.html` 测试页面：
```bash
# 在浏览器中打开
file:///path/to/test-security.html
```

测试内容包括：
- ✅ XSS攻击检测
- ✅ SQL注入检测
- ✅ 敏感信息泄露
- ✅ 恶意脚本检测
- ✅ 追踪器阻止
- ✅ 钓鱼网站识别

---

## 📊 威胁统计

### 威胁级别
```
CRITICAL (严重) - 立即阻止
HIGH     (高)   - 阻止并警告
MEDIUM   (中)   - 警告
LOW      (低)   - 记录
```

### 查看统计
- 点击插件图标查看实时统计
- 查看威胁历史记录
- 导出安全报告
- 查看安全评分

---

## 🔧 配置选项

### 防护开关
```javascript
{
  maliciousUrlProtection: true,  // 恶意URL防护
  xssProtection: true,           // XSS防护
  sqlInjectionProtection: true,  // SQL注入防护
  trackerBlocking: true,         // 追踪器阻止
  formProtection: true,          // 表单安全
  phishingProtection: true,      // 钓鱼检测
  notifications: true,           // 通知提醒
  strictMode: false              // 严格模式
}
```

### 白名单管理
- 添加可信网站到白名单
- 临时允许被阻止的请求
- 自定义安全规则

---

## 🎓 技术实现

### 架构组件

**1. Background Script (后台服务)**
- `security-manager.ts` - 安全管理
- `threat-detector.ts` - 威胁检测
- `network-monitor.ts` - 网络监控

**2. Content Script (内容脚本)**
- `page-analyzer.ts` - 页面分析
- `form-monitor.ts` - 表单监控
- `script-monitor.ts` - 脚本监控

**3. Security Utils (安全工具)**
- `utils/security.ts` - 检测算法
- XSS模式匹配
- SQL注入检测
- 钓鱼网站分析

**4. Rules (规则库)**
- `public/rules/malicious-urls.json` - 恶意URL规则
- `public/rules/tracker-blocking.json` - 追踪器规则

---

## 🚀 性能优化

- ✅ 异步检测，不阻塞页面加载
- ✅ 正则表达式优化
- ✅ 缓存机制
- ✅ 事件节流
- ✅ 增量更新

---

## 📝 开发者说明

### 添加新的威胁检测

1. **在 `utils/security.ts` 中添加检测函数**
```typescript
export function detectNewThreat(input: string) {
  // 检测逻辑
  return { detected: boolean, patterns: [] }
}
```

2. **在相应的监控器中集成**
```typescript
// 例如在 form-monitor.ts 中
const result = detectNewThreat(formData)
if (result.detected) {
  // 处理威胁
}
```

3. **更新类型定义**
```typescript
// types/security.ts
export enum ThreatType {
  NEW_THREAT = 'new_threat'
}
```

---

## ⚠️ 注意事项

1. **误报处理**
   - 部分合法网站可能被误判
   - 使用白名单功能排除
   - 及时反馈误报

2. **性能影响**
   - 启用所有防护会略微影响性能
   - 可根据需求关闭部分功能
   - 严格模式会更严格但更慢

3. **兼容性**
   - Chrome/Edge/Brave等Chromium内核浏览器
   - Manifest V3标准
   - 需要Chrome 88+

---

## 📈 效果展示

### 防护效果统计
```
✅ 阻止恶意URL: 20+ 种模式
✅ 检测XSS攻击: 16+ 种模式
✅ 检测SQL注入: 10+ 种模式
✅ 阻止追踪器: 60+ 个域名
✅ 识别钓鱼网站: 12+ 种特征
✅ 保护表单提交: 实时监控
```

---

## 🔗 相关资源

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [XSS防护指南](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [SQL注入防护](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Chrome Extension文档](https://developer.chrome.com/docs/extensions/)

---

## 📄 许可证

MIT License

---

**开发团队**: Web Security Guardian Team
**版本**: v1.0.0
**更新日期**: 2024

🛡️ **保护您的网络安全，从安装开始！**

