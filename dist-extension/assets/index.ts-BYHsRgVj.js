import{T as r,a as c,i as b,d as y,b as u,c as S}from"./security-CuDUei-K.js";class v{suspiciousPatterns=[/eval\s*\(/gi,/document\.write\s*\(/gi,/innerHTML\s*=.*<script/gi,/location\.href\s*=/gi,/window\.open\s*\(/gi,/document\.cookie/gi,/localStorage\./gi,/sessionStorage\./gi];initialize(){console.log("📜 Script Monitor initialized"),this.setupRealTimeMonitoring(),this.interceptDangerousFunctions()}setupRealTimeMonitoring(){new MutationObserver(t=>{t.forEach(n=>{n.addedNodes.forEach(o=>{o.nodeName==="SCRIPT"&&this.handleDynamicScript(o)})})}).observe(document.documentElement,{childList:!0,subtree:!0})}handleDynamicScript(e){console.warn("⚠️ 检测到动态添加的脚本"),e.src?this.analyzeExternalScript(e,0).forEach(t=>{this.reportThreat(t)}):e.textContent&&this.analyzeInlineScript(e,0).forEach(t=>{this.reportThreat(t)})}interceptDangerousFunctions(){const e=document.createElement("script");e.textContent=`
      (function() {
        // 保存原始函数
        const originalEval = window.eval;
        const originalFunction = window.Function;
        const originalSetTimeout = window.setTimeout;
        const originalSetInterval = window.setInterval;
        
        // 显示阻止警告
        function showBlockedWarning(functionName, code) {
          const warning = document.createElement('div');
          warning.style.cssText = \`
            position: fixed;
            top: 20px;
            right: 20px;
            background: linear-gradient(135deg, #ff4d4f, #ff7875);
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            z-index: 999999;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            font-size: 14px;
            font-weight: 500;
            box-shadow: 0 8px 24px rgba(255, 77, 79, 0.4);
            max-width: 350px;
            animation: slideIn 0.3s ease-out;
          \`;
          
          warning.innerHTML = \`
            <div style="display: flex; align-items: start; gap: 10px;">
              <span style="font-size: 20px;">🛡️</span>
              <div style="flex: 1;">
                <div style="font-weight: bold; margin-bottom: 5px;">危险操作已阻止</div>
                <div style="font-size: 12px; opacity: 0.9;">检测到 \${functionName}() 调用已被拦截</div>
                <div style="font-size: 11px; opacity: 0.7; margin-top: 5px; font-family: monospace; background: rgba(0,0,0,0.2); padding: 5px; border-radius: 3px; max-height: 60px; overflow: auto;">\${code.substring(0, 100)}...</div>
              </div>
              <button onclick="this.closest('div[style*=fixed]').remove()" 
                      style="background: none; border: none; color: white; font-size: 20px; cursor: pointer; padding: 0; line-height: 1;">×</button>
            </div>
          \`;
          
          if (!document.getElementById('wsg-animation-style')) {
            const style = document.createElement('style');
            style.id = 'wsg-animation-style';
            style.textContent = \`
              @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
              }
            \`;
            document.head.appendChild(style);
          }
          
          document.body.appendChild(warning);
          
          setTimeout(() => {
            if (warning.parentNode) {
              warning.style.animation = 'slideIn 0.3s ease-out reverse';
              setTimeout(() => warning.remove(), 300);
            }
          }, 5000);
        }
        
        // 拦截并阻止eval
        window.eval = function(...args) {
          const code = args[0]?.toString() || '';
          console.error('🚫 eval() 调用已被阻止:', code.substring(0, 100));
          showBlockedWarning('eval', code);
          window.postMessage({
            type: 'WEB_SEC_GUARDIAN_ALERT',
            function: 'eval',
            args: code.substring(0, 200),
            stack: new Error().stack,
            blocked: true
          }, '*');
          
          // 抛出错误，阻止执行
          throw new Error('🛡️ Web Security Guardian: eval() 调用已被安全策略阻止');
        };
        
        // 拦截并阻止Function构造函数
        window.Function = new Proxy(originalFunction, {
          construct(target, args) {
            const code = args.join('; ');
            console.error('🚫 Function() 调用已被阻止:', code.substring(0, 100));
            showBlockedWarning('Function', code);
            window.postMessage({
              type: 'WEB_SEC_GUARDIAN_ALERT',
              function: 'Function',
              args: code.substring(0, 200),
              stack: new Error().stack,
              blocked: true
            }, '*');
            
            // 抛出错误，阻止执行
            throw new Error('🛡️ Web Security Guardian: Function() 构造函数已被安全策略阻止');
          }
        });
        
        // 拦截并阻止setTimeout中的字符串
        window.setTimeout = function(handler, ...args) {
          if (typeof handler === 'string') {
            console.error('🚫 setTimeout(string) 调用已被阻止:', handler.substring(0, 100));
            showBlockedWarning('setTimeout', handler);
            window.postMessage({
              type: 'WEB_SEC_GUARDIAN_ALERT',
              function: 'setTimeout',
              args: handler.substring(0, 200),
              blocked: true
            }, '*');
            
            // 阻止字符串形式的setTimeout，但允许函数形式
            throw new Error('🛡️ Web Security Guardian: setTimeout(string) 已被安全策略阻止');
          }
          return originalSetTimeout.call(this, handler, ...args);
        };
        
        // 拦截并阻止setInterval中的字符串
        window.setInterval = function(handler, ...args) {
          if (typeof handler === 'string') {
            console.error('🚫 setInterval(string) 调用已被阻止:', handler.substring(0, 100));
            showBlockedWarning('setInterval', handler);
            window.postMessage({
              type: 'WEB_SEC_GUARDIAN_ALERT',
              function: 'setInterval',
              args: handler.substring(0, 200),
              blocked: true
            }, '*');
            
            // 阻止字符串形式的setInterval
            throw new Error('🛡️ Web Security Guardian: setInterval(string) 已被安全策略阻止');
          }
          return originalSetInterval.call(this, handler, ...args);
        };
        
        console.log('%c🛡️ Web Security Guardian%c - 危险函数拦截已激活', 'background: #667eea; color: white; padding: 4px 8px; border-radius: 3px; font-weight: bold;', 'color: #667eea; font-weight: bold;');
        console.log('%c所有 eval()、Function()、setTimeout(string)、setInterval(string) 调用将被阻止', 'color: #ff4d4f; font-weight: bold;');
      })();
    `,(document.head||document.documentElement).insertBefore(e,(document.head||document.documentElement).firstChild),e.remove(),window.addEventListener("message",t=>{if(t.source===window&&t.data.type==="WEB_SEC_GUARDIAN_ALERT"){const n={id:`dangerous_function_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:c.XSS_ATTACK,level:r.HIGH,url:window.location.href,description:`检测到危险函数调用: ${t.data.function}()`,timestamp:Date.now(),blocked:t.data.blocked||!1,details:{function:t.data.function,args:t.data.args,stack:t.data.stack}};this.reportThreat(n)}})}reportThreat(e){typeof chrome<"u"&&chrome.runtime&&chrome.runtime.sendMessage({type:"THREAT_DETECTED",threat:e}).catch(t=>console.error("Failed to report threat:",t))}async scanScripts(){const e=[];return document.querySelectorAll("script:not([src])").forEach((o,i)=>{const s=this.analyzeInlineScript(o,i);e.push(...s)}),document.querySelectorAll("script[src]").forEach((o,i)=>{const s=this.analyzeExternalScript(o,i);e.push(...s)}),e}analyzeInlineScript(e,t){const n=[],o=e.textContent||e.innerHTML||"";return o.trim()&&(this.suspiciousPatterns.forEach((i,s)=>{const a=o.match(i);a&&n.push({id:`suspicious_inline_script_${Date.now()}_${t}_${s}`,type:c.SUSPICIOUS_SCRIPT,level:this.getPatternSeverity(i),url:window.location.href,description:`内联脚本包含可疑代码: ${this.getPatternDescription(i)}`,timestamp:Date.now(),blocked:!1,details:{pattern:i.toString(),matches:a.slice(0,3),scriptContent:o.substring(0,200)}})}),o.length>1e4&&this.isObfuscated(o)&&n.push({id:`obfuscated_script_${Date.now()}_${t}`,type:c.SUSPICIOUS_SCRIPT,level:r.MEDIUM,url:window.location.href,description:"检测到可能的混淆脚本代码",timestamp:Date.now(),blocked:!1,details:{scriptLength:o.length,scriptPreview:o.substring(0,100)}})),n}analyzeExternalScript(e,t){const n=[],o=e.src;if(!o)return n;try{const i=new URL(o);this.isTrustedDomain(i.hostname)||n.push({id:`untrusted_external_script_${Date.now()}_${t}`,type:c.SUSPICIOUS_SCRIPT,level:r.MEDIUM,url:window.location.href,description:`加载来自不可信域名的脚本: ${i.hostname}`,timestamp:Date.now(),blocked:!1,details:{src:o,domain:i.hostname}}),i.protocol==="http:"&&window.location.protocol==="https:"&&n.push({id:`mixed_content_script_${Date.now()}_${t}`,type:c.INSECURE_FORM,level:r.MEDIUM,url:window.location.href,description:"HTTPS页面加载HTTP脚本（混合内容）",timestamp:Date.now(),blocked:!1,details:{src:o}})}catch{n.push({id:`invalid_script_src_${Date.now()}_${t}`,type:c.SUSPICIOUS_SCRIPT,level:r.HIGH,url:window.location.href,description:"脚本src包含无效URL",timestamp:Date.now(),blocked:!1,details:{src:o}})}return n}getPatternSeverity(e){const t=e.toString();return t.includes("eval")?r.HIGH:t.includes("document.write")?r.MEDIUM:t.includes("innerHTML.*<script")?r.HIGH:t.includes("location.href")?r.MEDIUM:t.includes("document.cookie")?r.MEDIUM:r.LOW}getPatternDescription(e){const t=e.toString();return t.includes("eval")?"eval()函数调用":t.includes("document.write")?"document.write()调用":t.includes("innerHTML.*<script")?"innerHTML注入脚本":t.includes("location.href")?"页面重定向":t.includes("document.cookie")?"Cookie访问":t.includes("localStorage")?"localStorage访问":t.includes("sessionStorage")?"sessionStorage访问":"可疑代码模式"}isObfuscated(e){return[/[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*['"]\w+['"]/.test(e),e.split(`
`).length<10&&e.length>5e3,/\\x[0-9a-fA-F]{2}/.test(e),/\\u[0-9a-fA-F]{4}/.test(e),(e.match(/[{}]/g)||[]).length>e.length*.1].filter(Boolean).length>=2}isTrustedDomain(e){return[window.location.hostname,"cdnjs.cloudflare.com","ajax.googleapis.com","code.jquery.com","unpkg.com","jsdelivr.net","stackpath.bootstrapcdn.com","maxcdn.bootstrapcdn.com","fonts.googleapis.com","use.fontawesome.com"].some(n=>e===n||e.endsWith("."+n))}}class x{formListeners=new Map;initialize(){console.log("📝 Form Monitor initialized"),this.setupFormMonitoring()}setupFormMonitoring(){document.addEventListener("submit",t=>{t.target instanceof HTMLFormElement&&this.onFormSubmit(t)},!0),new MutationObserver(t=>{t.forEach(n=>{n.addedNodes.forEach(o=>{o instanceof HTMLFormElement?this.monitorForm(o):o instanceof HTMLElement&&o.querySelectorAll("form").forEach(s=>this.monitorForm(s))})})}).observe(document.body,{childList:!0,subtree:!0})}monitorForm(e){if(this.formListeners.has(e))return;const t=n=>{this.onFormSubmit(n)};e.addEventListener("submit",t,!0),this.formListeners.set(e,t)}onFormSubmit(e){const t=e.target,n=this.analyzeFormSubmit(t);n.length>0&&n.some(i=>i.level==="critical"||i.level==="high")&&(e.preventDefault(),this.showWarning(n),this.reportThreats(n))}showWarning(e){const t=e.map(s=>`• ${s.description}`).join("<br>"),n=document.createElement("div");n.style.cssText=`
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      z-index: 999999;
      display: flex;
      align-items: center;
      justify-content: center;
      animation: fadeIn 0.2s ease-out;
    `;const o=document.createElement("div");o.style.cssText=`
      background: white;
      border-radius: 12px;
      padding: 30px;
      max-width: 500px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      animation: slideDown 0.3s ease-out;
    `,o.innerHTML=`
      <style>
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        @keyframes slideDown {
          from { transform: translateY(-50px); opacity: 0; }
          to { transform: translateY(0); opacity: 1; }
        }
      </style>
      <div style="text-align: center; margin-bottom: 20px;">
        <div style="font-size: 64px; margin-bottom: 10px;">🛡️</div>
        <div style="font-size: 24px; font-weight: bold; color: #ff4d4f; margin-bottom: 10px;">
          表单提交已被阻止
        </div>
        <div style="font-size: 14px; color: #666;">
          检测到以下安全威胁
        </div>
      </div>
      
      <div style="background: #fff2e8; border-left: 4px solid #ff7a45; padding: 15px; margin: 20px 0; border-radius: 4px;">
        <div style="font-size: 13px; color: #333; line-height: 1.8;">
          ${t}
        </div>
      </div>
      
      <div style="text-align: center; margin-top: 20px;">
        <button id="wsg-close-btn" style="
          background: linear-gradient(135deg, #667eea, #764ba2);
          color: white;
          border: none;
          padding: 12px 30px;
          border-radius: 6px;
          font-size: 14px;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.3s;
        ">我知道了</button>
      </div>
    `,n.appendChild(o),document.body.appendChild(n);const i=o.querySelector("#wsg-close-btn");i&&(i.addEventListener("click",()=>{n.remove()}),i.addEventListener("mouseover",s=>{s.target.style.transform="translateY(-2px)",s.target.style.boxShadow="0 6px 20px rgba(102, 126, 234, 0.4)"}),i.addEventListener("mouseout",s=>{s.target.style.transform="translateY(0)",s.target.style.boxShadow="none"})),n.addEventListener("click",s=>{s.target===n&&n.remove()}),setTimeout(()=>{this.showNotification("表单提交已被阻止","high")},100)}showNotification(e,t){const n=document.createElement("div");n.style.cssText=`
      position: fixed;
      top: 140px;
      right: 20px;
      background: linear-gradient(135deg, #ff4d4f, #ff7875);
      color: white;
      padding: 15px 20px;
      border-radius: 8px;
      z-index: 999998;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 14px;
      font-weight: 500;
      box-shadow: 0 8px 24px rgba(255, 77, 79, 0.4);
      max-width: 300px;
      animation: slideIn 0.3s ease-out;
    `,n.innerHTML=`
      <div style="display: flex; align-items: center; gap: 10px;">
        <span style="font-size: 20px;">⚠️</span>
        <span>${e}</span>
      </div>
    `,document.body.appendChild(n),setTimeout(()=>{n.parentNode&&n.remove()},4e3)}reportThreats(e){typeof chrome<"u"&&chrome.runtime&&chrome.runtime.sendMessage({type:"THREAT_DETECTED",threats:e}).catch(t=>console.error("Failed to report threats:",t))}async scanForms(){const e=[];return document.querySelectorAll("form").forEach((n,o)=>{const i=this.analyzeForm(n,o);e.push(...i)}),e}async checkFormSecurity(e){return b(e)}analyzeFormSubmit(e){const t=[],n=new FormData(e);for(const[o,i]of n.entries())if(typeof i=="string"){const s=y(i);s.detected&&s.patterns.forEach(d=>{t.push({id:`sql_injection_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:"sql_injection",level:d.severity,url:window.location.href,description:`表单字段 "${o}" 包含SQL注入攻击: ${d.description}`,timestamp:Date.now(),blocked:!0,details:{field:o,value:i.substring(0,100),pattern:d.id}})});const a=u(i);a.detected&&a.patterns.forEach(d=>{t.push({id:`xss_form_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:"xss_attack",level:d.severity,url:window.location.href,description:`表单字段 "${o}" 包含XSS攻击: ${d.description}`,timestamp:Date.now(),blocked:!0,details:{field:o,value:i.substring(0,100),pattern:d.id}})});const p=S(i);p.detected&&!e.action.startsWith("https://")&&t.push({id:`sensitive_data_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:"insecure_form",level:"high",url:window.location.href,description:`表单在非HTTPS连接下传输敏感信息: ${p.types.join(", ")}`,timestamp:Date.now(),blocked:!0,details:{field:o,types:p.types}})}return t}analyzeForm(e,t){const n=[],o=e.action||window.location.href,i=e.method.toLowerCase();if(i==="post"&&!o.startsWith("https://")){const s=e.querySelector('input[type="password"]'),a=this.hasSensitiveFields(e);(s||a)&&n.push({id:`insecure_form_${Date.now()}_${t}`,type:"insecure_form",level:"high",url:window.location.href,description:"表单包含敏感信息但未使用HTTPS提交",timestamp:Date.now(),blocked:!1,details:{action:o,method:i,hasPassword:!!s,hasSensitiveFields:a}})}if(o&&o!==window.location.href)try{const s=new URL(o),a=new URL(window.location.href);s.hostname!==a.hostname&&n.push({id:`cross_domain_form_${Date.now()}_${t}`,type:"suspicious_script",level:"medium",url:window.location.href,description:`表单提交到外部域名: ${s.hostname}`,timestamp:Date.now(),blocked:!1,details:{action:o,targetDomain:s.hostname}})}catch{n.push({id:`invalid_form_action_${Date.now()}_${t}`,type:"suspicious_script",level:"medium",url:window.location.href,description:"表单action包含无效URL",timestamp:Date.now(),blocked:!1,details:{action:o}})}return n}hasSensitiveFields(e){const t=e.querySelectorAll("input, textarea"),n=[/password/i,/credit.*card/i,/social.*security/i,/ssn/i,/银行卡/i,/密码/i,/身份证/i,/phone/i,/email/i,/address/i];for(const o of t){const i=o,s=`${i.name} ${i.placeholder} ${i.id}`.toLowerCase();if(n.some(a=>a.test(s))||i instanceof HTMLInputElement&&["password","email","tel"].includes(i.type))return!0}return!1}getFieldLabel(e){const t=e.id;if(t){const o=document.querySelector(`label[for="${t}"]`);if(o)return o.textContent||""}const n=e.closest("label");return n&&n.textContent||""}}class T{observer=null;threatCallback;initialize(){this.setupDOMObserver(),console.log("👁️ DOM Observer initialized")}setThreatCallback(e){this.threatCallback=e}setupDOMObserver(){this.observer=new MutationObserver(e=>{e.forEach(t=>{this.handleMutation(t)})}),this.observer.observe(document.body,{childList:!0,subtree:!0,attributes:!0,attributeFilter:["src","href","onclick","onload","onerror"],characterData:!0})}handleMutation(e){switch(e.type){case"childList":this.handleChildListMutation(e);break;case"attributes":this.handleAttributeMutation(e);break;case"characterData":this.handleCharacterDataMutation(e);break}}handleChildListMutation(e){e.addedNodes.forEach(t=>{t.nodeType===Node.ELEMENT_NODE&&this.analyzeAddedElement(t)})}handleAttributeMutation(e){const t=e.target,n=e.attributeName;if(!n)return;const o=t.getAttribute(n);o&&this.isDangerousAttribute(n,o)&&this.reportThreat({id:`dangerous_attribute_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:c.XSS_ATTACK,level:r.MEDIUM,url:window.location.href,description:`检测到危险属性: ${n}="${o.substring(0,50)}"`,timestamp:Date.now(),blocked:!1,details:{element:t.tagName,attribute:n,value:o.substring(0,200)}})}handleCharacterDataMutation(e){const n=e.target.textContent||"",o=u(n);o.detected&&this.reportThreat({id:`text_xss_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:c.XSS_ATTACK,level:r.MEDIUM,url:window.location.href,description:"检测到文本内容中的XSS模式",timestamp:Date.now(),blocked:!1,details:{content:n.substring(0,200),patterns:o.patterns.map(i=>i.id)}})}analyzeAddedElement(e){e.tagName==="SCRIPT"&&this.analyzeScriptElement(e),e.tagName==="IFRAME"&&this.analyzeIframeElement(e),e.tagName==="FORM"&&this.analyzeFormElement(e);const t=e.innerHTML;if(t){const n=u(t);n.detected&&this.reportThreat({id:`dynamic_xss_${Date.now()}_${Math.random().toString(36).substr(2,9)}`,type:c.XSS_ATTACK,level:r.HIGH,url:window.location.href,description:"检测到动态添加的XSS内容",timestamp:Date.now(),blocked:!1,details:{element:e.tagName,content:t.substring(0,200),patterns:n.patterns.map(o=>o.id)}})}e.querySelectorAll("*").forEach(n=>{this.analyzeAddedElement(n)})}analyzeScriptElement(e){const t=e.src,n=e.textContent||e.innerHTML;if(t){if(!this.isTrustedDomain(t)){const o=new URL(t).hostname;console.warn("⚠️ 检测到动态加载外部脚本:",t),this.reportThreat({id:`dynamic_external_script_${Date.now()}`,type:c.SUSPICIOUS_SCRIPT,level:this.isSuspiciousDomain(o)?r.HIGH:r.MEDIUM,url:window.location.href,description:`检测到动态加载外部脚本: ${o}`,timestamp:Date.now(),blocked:!1,details:{src:t}})}}else if(n){console.warn("⚠️ 检测到动态添加内联脚本");const o=this.hasDangerousCode(n);this.reportThreat({id:`dynamic_inline_script_${Date.now()}`,type:c.SUSPICIOUS_SCRIPT,level:o?r.HIGH:r.MEDIUM,url:window.location.href,description:o?"检测到包含危险代码的内联脚本":"检测到动态添加内联脚本",timestamp:Date.now(),blocked:!1,details:{content:n.substring(0,200),dangerous:o}})}}analyzeIframeElement(e){const t=e.src;t&&!this.isTrustedDomain(t)&&this.reportThreat({id:`dynamic_iframe_${Date.now()}`,type:c.SUSPICIOUS_SCRIPT,level:r.MEDIUM,url:window.location.href,description:`动态添加外部iframe: ${new URL(t).hostname}`,timestamp:Date.now(),blocked:!1,details:{src:t}})}analyzeFormElement(e){const t=e.action;if(t&&t!==window.location.href)try{const n=new URL(t),o=new URL(window.location.href);n.hostname!==o.hostname&&this.reportThreat({id:`dynamic_cross_domain_form_${Date.now()}`,type:c.SUSPICIOUS_SCRIPT,level:r.MEDIUM,url:window.location.href,description:`动态添加跨域表单: ${n.hostname}`,timestamp:Date.now(),blocked:!1,details:{action:t}})}catch{}}isDangerousAttribute(e,t){return e.startsWith("on")||(e==="src"||e==="href")&&t.startsWith("javascript:")?!0:u(t).detected}isTrustedDomain(e){try{const t=new URL(e).hostname;return[window.location.hostname,"cdnjs.cloudflare.com","ajax.googleapis.com","code.jquery.com","unpkg.com","jsdelivr.net","stackpath.bootstrapcdn.com"].some(o=>t===o||t.endsWith("."+o))}catch{return!1}}isSuspiciousDomain(e){return[/evil-domain/i,/malware/i,/hack/i,/phish/i,/steal/i,/attack/i,/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/].some(n=>n.test(e))}hasDangerousCode(e){return[/document\.cookie/i,/localStorage\.|sessionStorage\./i,/XMLHttpRequest|fetch\(/i,/eval\s*\(/i,/new\s+Function\s*\(/i,/window\.location\s*=/i].filter(o=>o.test(e)).length>=2}reportThreat(e){this.threatCallback&&this.threatCallback(e),console.warn("🚨 DOM Observer detected threat:",e)}destroy(){this.observer&&(this.observer.disconnect(),this.observer=null)}}console.log("%c🛡️ Web Security Guardian%c - Content Script Loading","background: #667eea; color: white; padding: 4px 8px; border-radius: 3px; font-weight: bold;","color: #667eea; font-weight: bold;");console.log("📍 URL:",window.location.href);const m=document.createElement("meta");m.name="web-security-guardian";m.content="active";document.head?.appendChild(m);window.webSecurityGuardian={version:"1.0.0",isActive:!0,reportThreat:l=>{typeof chrome<"u"&&chrome.runtime&&chrome.runtime.sendMessage({type:"THREAT_DETECTED",data:l}).catch(()=>{})}};let h,f,g;function E(){document.readyState==="loading"?document.addEventListener("DOMContentLoaded",()=>{w()}):w()}function w(){try{h=new v,h.initialize(),f=new x,f.initialize(),g=new T,g.initialize(),console.log("%c✅ 所有安全监控器已激活","color: #52c41a; font-weight: bold;"),console.log("  📜 脚本监控: eval()、Function()、setTimeout()、setInterval() 已被拦截"),console.log("  📝 表单监控: XSS、SQL注入、敏感信息检测已激活"),console.log("  👁️ DOM监控: 动态脚本注入检测已激活")}catch(l){console.error("❌ 监控器初始化失败:",l)}}typeof chrome<"u"&&chrome.runtime&&chrome.runtime.onMessage.addListener(l=>{l?.type==="SHOW_SECURITY_WARNING"&&l.message&&_(l.message)});function _(l){const e=document.createElement("div");if(e.style.cssText=`
    position: fixed;
    top: 20px;
    right: 20px;
    background: linear-gradient(135deg, #ff6b6b, #ee5a24);
    color: white;
    padding: 15px 20px;
    border-radius: 8px;
    z-index: 999999;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 14px;
    font-weight: 500;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    max-width: 300px;
    animation: slideIn 0.3s ease-out;
  `,e.innerHTML=`
    <div style="display: flex; align-items: center; gap: 10px;">
      <span style="font-size: 18px;">🛡️</span>
      <span>${l}</span>
      <button onclick="this.parentElement.parentElement.remove()" 
              style="background: none; border: none; color: white; font-size: 18px; cursor: pointer; margin-left: auto;">×</button>
    </div>
  `,!document.getElementById("wsg-style")){const t=document.createElement("style");t.id="wsg-style",t.textContent=`
      @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
    `,document.head?.appendChild(t)}document.body.appendChild(e),setTimeout(()=>{e.parentNode&&(e.style.animation="slideIn 0.3s ease-out reverse",setTimeout(()=>e.remove(),300))},5e3)}E();
