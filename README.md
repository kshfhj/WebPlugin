# 🛡️ Web Security Guardian

一个基于 Vue 3 + TypeScript 开发的现代化浏览器安全防护插件，为用户提供全面的 Web 应用层安全防护。

## ✨ 主要功能

- 🚫 **恶意 URL 检测与阻止** - 实时识别并拦截已知恶意网站，支持动态规则管理
- ⚠️ **XSS 攻击防护** - 检测并阻止跨站脚本攻击
- 👁️ **隐私追踪器阻止** - 拦截第三方追踪脚本，保护用户隐私
- 🔒 **表单安全检查** - 检测 SQL 注入、敏感数据泄露风险
- 🎣 **钓鱼网站识别** - 智能识别仿冒网站
- 🤖 **AI 智能分析** - 集成免费 AI 模型进行智能网址分析和页面安全扫描
- 📊 **可视化统计分析** - 多维度图表展示安全数据
- ⚙️ **灵活开关控制** - 总开关 + 独立功能开关，精细化管理防护功能
- 📋 **黑白名单管理** - 支持 CSV 导入和手动管理，灵活配置信任和阻止列表
- 🏢 **官方网站识别** - 自动识别全球公认的官方网站，直接给出安全评级

## 🛠️ 技术栈

### 前端框架
- **Vue 3** - 渐进式 JavaScript 框架（Composition API）
- **TypeScript** - 类型安全的 JavaScript 超集
- **Vite** - 下一代前端构建工具

### UI 组件库
- **Element Plus** - 基于 Vue 3 的组件库
- **ECharts** - 专业的数据可视化图表库

### 状态管理
- **Pinia** - Vue 3 官方推荐的状态管理库

### 浏览器扩展
- **Chrome Extensions API (Manifest V3)** - 最新版扩展 API
- **Content Scripts** - 页面内容脚本注入
- **Background Service Worker** - 后台服务工作线程
- **DeclarativeNetRequest** - 声明式网络请求拦截

### AI 集成
- **OpenRouter API** - 免费 AI 模型接口
- **DeepSeek R1T2 Chimera** - 智能网站安全分析

## 📦 项目结构

```
web_sec/
├── src/
│   ├── background/              # 后台脚本
│   │   ├── index.ts            # Service Worker 主文件
│   │   ├── network-monitor.ts  # 网络监控
│   │   ├── security-manager.ts # 安全管理器
│   │   └── threat-detector.ts  # 威胁检测器
│   ├── content/                # 内容脚本
│   │   ├── index.ts            # 内容脚本入口
│   │   ├── dom-observer.ts     # DOM 监控
│   │   ├── form-monitor.ts     # 表单监控
│   │   ├── script-monitor.ts   # 脚本监控
│   │   └── page-analyzer.ts    # 页面分析
│   ├── popup/                  # 插件弹窗
│   │   ├── App.vue             # 弹窗主组件（AI分析、页面扫描）
│   │   ├── index.html
│   │   └── main.ts
│   ├── options/                # 设置页面
│   │   ├── App.vue             # 设置主组件（开关管理、统计图表）
│   │   ├── index.html
│   │   └── main.ts
│   ├── views/                  # 测试页面
│   │   ├── HomeView.vue        # 危险行为测试页
│   │   └── AboutView.vue
│   ├── stores/                 # 状态管理
│   │   ├── counter.ts
│   │   └── security/
│   │       └── index.ts        # 安全状态管理
│   ├── types/                  # 类型定义
│   │   ├── index.ts            # 通用类型
│   │   └── security.ts         # 安全相关类型
│   └── utils/                  # 工具函数
│       ├── security.ts         # 安全工具函数
│       └── storage.ts          # 存储工具
├── public/                     # 静态资源
│   ├── icons/                  # 图标资源
│   └── rules/                  # 规则配置
│       ├── malicious-urls.json # 恶意URL规则
│       └── tracker-blocking.json # 追踪器阻止规则
├── dist-extension/             # 插件构建输出
├── scripts/                    # 构建脚本
├── package.json
└── README.md
```

## 🚀 从零运行项目

### 环境要求

- **Node.js**: `^20.19.0` 或 `>=22.12.0`
- **npm**: 最新版本

### 1. 克隆项目

```bash
git clone <your-repository-url>
cd web_sec
```

### 2. 安装依赖

```bash
npm install
```

### 3. 运行开发服务器（测试页面）

```bash
npm run dev
```

访问 `http://localhost:5173/` 查看危险行为测试页面。

### 4. 构建浏览器插件

```bash
npm run build:extension
```

构建完成后，插件文件将输出到 `dist-extension/` 目录。

## 🔌 安装插件到浏览器

### Chrome 浏览器

1. 打开浏览器，进入扩展程序管理页面：
   - Chrome: `chrome://extensions/`

2. 开启右上角的 **"开发者模式"**

3. 点击 **"加载已解压的扩展程序"**

4. 选择项目中的 `dist-extension/` 文件夹

5. 插件安装成功！图标将出现在浏览器工具栏

### 使用插件

- **查看安全状态**: 点击工具栏插件图标，查看当前页面安全评分和威胁统计
- **AI 页面扫描**: 在弹窗中点击"扫描当前页面"按钮，获取 AI 深度分析报告
- **AI 钓鱼检测**: 在弹窗中点击"AI检测"按钮，输入 URL 进行钓鱼网站检测
- **查看统计图表**: 右键插件图标 → 选项 → 统计信息
- **配置防护规则**: 右键插件图标 → 选项 → 基本设置

## ⚙️ 功能开关系统

### 总开关

- **启用插件** - 控制整个安全防护插件的启动状态
- 关闭总开关后，所有安全防护功能将被禁用

### 防护功能开关

每个功能都可以独立开启/关闭：

1. **恶意URL防护** - 检测并阻止访问已知的恶意网站
2. **XSS攻击防护** - 检测并阻止跨站脚本攻击
3. **隐私追踪阻止** - 阻止第三方追踪器收集数据
4. **表单安全检查** - 检查表单提交的安全性
5. **钓鱼网站防护** - 识别并警告钓鱼网站

### 通知设置

- **安全通知** - 当检测到威胁时显示通知
- **严格模式** - 启用更严格的安全检查

### 开关同步机制

- ✅ 实时保存：每次切换开关都会自动保存
- ✅ 前后端同步：设置变化实时同步到所有页面（background、content、popup）
- ✅ 动态规则管理：关闭恶意URL防护时，自动禁用 declarativeNetRequest 规则

## 🛡️ 核心安全检测

### 1. 恶意 URL 检测与阻止

#### 检测机制
- **内置恶意URL库**：30+ 个测试恶意URL，涵盖恶意软件、钓鱼、诈骗等类型
- **模式匹配检测**：使用正则表达式检测可疑域名模式
- **可疑路径检测**：检测包含恶意关键词的URL路径
- **可疑文件类型**：检测危险文件扩展名（.exe, .scr, .bat 等）
- **动态规则管理**：基于开关状态动态启用/禁用 declarativeNetRequest 规则

#### 官方网站识别
自动识别全球公认的官方网站（Google、百度、GitHub、Amazon、PayPal 等 50+ 个），直接给出 100 分安全评级，无需 AI 分析。

### 2. XSS 攻击检测

- **Script 标签注入检测**
- **事件处理器注入检测** (`onerror`, `onload` 等)
- **JavaScript 伪协议检测** (`javascript:`)
- **危险函数拦截** (`eval()`, `Function()`, `setTimeout(string)`)
- **DOM XSS 监控** - 实时监控 DOM 变化
- **动态脚本注入检测** - 检测运行时添加的脚本

### 3. SQL 注入检测

- 表单输入内容分析
- 常见 SQL 注入模式识别：
  - `' OR '1'='1` - OR 恒真条件
  - `'; DROP TABLE users--` - 删除表
  - `1' UNION SELECT * FROM users--` - UNION 注入
  - `' AND SLEEP(5)--` - 时间盲注
- 实时输入验证

### 4. 隐私追踪器阻止

支持阻止以下追踪器：
- Google Analytics
- Google Tag Manager
- Facebook Pixel
- DoubleClick
- Mixpanel
- Amazon AdSystem
- 更多常见追踪器

### 5. 表单安全检查

- **HTTP 表单敏感数据提交警告**
- **敏感信息检测**：
  - 邮箱地址
  - 手机号码
  - 身份证号
  - 信用卡号
- **表单提交拦截机制**

### 6. 钓鱼网站检测

- **域名相似度分析**
- **可疑关键词检测**（20+ 个模式）
- **AI 智能分析**（集成 OpenRouter API）
- **同形异义字攻击检测**

## 🤖 AI 智能分析功能

### AI 页面扫描

点击弹窗中的"扫描当前页面"按钮，AI 会：

1. **收集页面信息**
   - 页面标题、URL、协议（HTTPS/HTTP）
   - 元素统计（表单、链接、脚本、iframe、输入框数量）
   - 可疑元素检测（隐藏iframe、外部脚本、弹窗脚本）
   - 页面描述信息
   - 已检测到的威胁记录

2. **AI 综合分析**
   - URL 和域名安全性
   - 协议安全性
   - 页面元素风险评估
   - 检测到的安全威胁分析
   - 可疑行为识别
   - **综合安全评分（0-100分）**
   - 具体安全建议

3. **评分判断标准**
   - **65分及以上**：✅ 安全（绿色）
   - **65分以下**：⚠️ 需注意（红色）

### AI 钓鱼网站检测

输入 URL 后，AI 会从以下方面分析：
- 域名特征（是否仿冒知名网站）
- URL 结构（是否有异常字符或编码）
- 顶级域名可信度
- 是否包含可疑关键词
- 综合安全评估

### API 配置

AI 功能使用统一的 API Key 配置（位于 `src/popup/App.vue`）：

```typescript
const OPENROUTER_API_KEY = 'your-api-key-here'
```

获取免费 API Key：https://openrouter.ai/

## 📋 黑白名单管理

### 白名单功能

- **作用**：白名单内的网站将被信任，不会进行任何安全检测
- **管理方式**：
  - CSV 文件导入（一行一个网址）
  - 手动添加/删除
  - 批量清空

### 黑名单功能

- **作用**：黑名单内的网站会被标记并显示警告弹窗
- **管理方式**：
  - CSV 文件导入（一行一个网址）
  - 手动添加/删除
  - 批量清空

### 列表格式

CSV 文件格式：每行一个域名或完整 URL

```
example.com
subdomain.example.com
https://malicious-site.com
```

## 📊 数据可视化

### 统计图表（选项页面）

1. **饼图** - 威胁类型分布
2. **柱状图** - 威胁类型统计
3. **环形图** - 威胁等级分布
4. **雷达图** - 安全防护能力评估
5. **进度条** - 威胁类型详情展示

### 威胁等级

- **低危 (Low)** - 绿色
- **中危 (Medium)** - 黄色
- **高危 (High)** - 橙色
- **严重 (Critical)** - 红色

### 威胁类型

- 恶意URL (malicious_url)
- XSS攻击 (xss_attack)
- 隐私追踪 (tracker)
- 不安全表单 (insecure_form)
- 可疑脚本 (suspicious_script)
- 钓鱼网站 (phishing)

## 🎯 高级特性

### 用户交互式监控

- **零初始负载**：页面加载时不执行检测
- **按需启动**：仅在用户点击、提交、按键时激活
- **性能优化**：避免误报和性能影响
- **智能超时**：5 秒无操作自动暂停监控

### 威胁去重与管理

- 每个威胁独立上报
- 实时 Toast 通知
- 页面切换自动清理历史威胁
- 按页面维度统计评分
- 最多保留最近 100 条威胁记录

### 白名单机制

为避免误报，插件内置了可信域名白名单：
- 常见 CDN（cdnjs, jsdelivr, unpkg, cloudflare）
- 大型网站资源域（twimg.com, gstatic.com, fbcdn.net）
- 当前页面同域资源

## 📊 可用脚本

```bash
# 开发服务器（测试页面）
npm run dev

# 构建测试页面
npm run build

# 构建浏览器插件
npm run build:extension

# 类型检查
npm run type-check

# 代码检查
npm run lint

# 代码格式化
npm run format

# 打包插件为 zip
npm run zip
```

## 🧪 测试页面功能

访问 `http://localhost:5173/` 可测试以下场景：

1. **恶意 URL 访问测试**
   - 内置恶意URL测试（5个测试URL）
   - iframe加载恶意URL测试
   
2. **XSS 攻击检测测试**
   - Script 标签注入
   - 事件处理器注入
   - JavaScript 伪协议
   
3. **SQL 注入检测测试**
   - 表单 SQL 注入（4种常见模式）
   
4. **敏感信息泄露检测**
   - 非 HTTPS 提交敏感数据
   
5. **恶意脚本注入检测**
   - 动态脚本注入
   - 外部脚本加载
   
6. **第三方追踪器阻止测试**
   - Google Analytics
   - Facebook Pixel
   - Mixpanel
   
7. **钓鱼网站检测测试**
   - 可疑链接集合

## ⚙️ 配置说明

### AI API 配置

编辑 `src/popup/App.vue` 第 223 行，替换为你的 OpenRouter API Key：

```typescript
const OPENROUTER_API_KEY = 'your-openrouter-api-key'
```

**注意**：该 API Key 统一管理，所有 AI 功能（页面扫描、钓鱼检测）都使用同一个 Key。

获取免费 API Key：https://openrouter.ai/

### 规则库配置

- **恶意 URL 规则**: `public/rules/malicious-urls.json`
- **追踪器规则**: `public/rules/tracker-blocking.json`

规则使用 `declarativeNetRequest` 格式，可在 Manifest V3 中动态启用/禁用。

### 官方网站列表配置

编辑 `src/popup/App.vue` 中的 `trustedOfficialDomains` 数组，添加更多可信域名。

## 🔒 安全说明

- 本插件仅用于学习和研究目的
- 测试页面包含模拟的危险行为，请勿在生产环境部署
- 所有本地检测均在浏览器内进行，不会上传用户数据
- AI 检测功能需要网络连接到 OpenRouter API，会发送 URL 信息到第三方服务
- API Key 存储在代码中，建议使用环境变量或配置加密（生产环境）

## 📝 开发说明

### 添加新的威胁检测规则

1. 在 `src/types/security.ts` 中定义新的威胁类型
2. 在对应的监控模块中实现检测逻辑
3. 通过 `handleThreat()` 上报威胁
4. 在 `src/background/index.ts` 中处理威胁统计
5. 在 `src/content/index.ts` 中添加对应的开关检查

### 添加新的防护开关

1. 在 `src/types/security.ts` 的 `ProtectionSettings` 接口中添加新字段
2. 在 `src/stores/security/index.ts` 中添加默认值
3. 在 `src/options/App.vue` 中添加开关 UI
4. 在检测逻辑中添加开关检查
5. 在 `src/background/index.ts` 中添加对应的处理逻辑

### 自定义 Toast 样式

编辑 `src/content/index.ts` 中的 `showThreatToast()` 函数。

### 动态规则管理

编辑 `src/background/index.ts` 中的 `updateDeclarativeNetRequestRules()` 函数，添加新的规则集管理逻辑。

## 🐛 故障排除

### 插件无法加载

1. 确保已开启"开发者模式"
2. 检查 `dist-extension/` 目录是否存在
3. 查看浏览器控制台的错误信息

### AI 功能无法使用

1. 检查 API Key 是否正确配置
2. 检查网络连接是否正常
3. 查看浏览器控制台的错误信息
4. 确认 OpenRouter API 服务是否可用

### 开关无法保存

1. 检查浏览器扩展权限是否完整
2. 查看浏览器控制台的错误信息
3. 尝试重新安装插件

### 威胁检测不工作

1. 检查总开关是否已开启
2. 检查对应的功能开关是否已开启
3. 检查是否在白名单中
4. 查看浏览器控制台的日志信息

## 📄 许可证

本项目仅供学习和研究使用。

---

**⚠️ 免责声明**: 本项目仅供学习和研究使用，请勿用于非法用途。使用本插件产生的任何后果由使用者自行承担。