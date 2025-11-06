(function(){console.log("🛡️ Content Security Monitor Starting on:",window.location.href);const o=document.createElement("meta");o.name="web-security-guardian";o.content="active";document.head?.appendChild(o);window.webSecurityGuardian={version:"1.0.0",isActive:!0,reportThreat:t=>{chrome.runtime.sendMessage({type:"THREAT_DETECTED",data:t})}};const r=[/<script[^>]*>.*?<\/script>/gi,/javascript:/gi,/on\w+\s*=\s*["'][^"']*["']/gi];function c(){const t=document.documentElement.innerHTML;let e=!1;r.forEach(n=>{n.test(t)&&(e=!0)}),e&&(console.warn("⚠️ Potential XSS detected"),chrome.runtime.sendMessage({type:"SECURITY_ISSUE",issueType:"XSS_DETECTED",data:{url:window.location.href,timestamp:Date.now()}}))}function d(){window.location.protocol!=="https:"&&window.location.hostname!=="localhost"&&!window.location.hostname.startsWith("127.0.0.1")&&(console.warn("⚠️ Insecure connection (HTTP)"),s("此网站未使用HTTPS加密连接"))}function l(){document.querySelectorAll("form").forEach(e=>{e.addEventListener("submit",n=>{const a=e.action||window.location.href;e.querySelector('input[type="password"]')&&!a.startsWith("https://")&&(console.warn("⚠️ Password submitted over insecure connection"),s("密码将通过不安全的连接传输！"))})})}function s(t){const e=document.createElement("div");if(e.style.cssText=`
    position: fixed;
    top: 20px;
    right: 20px;
    background: linear-gradient(135deg, #ff6b6b, #ee5a24);
    color: white;
    padding: 15px 20px;
    border-radius: 8px;
    z-index: 10000;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 14px;
    font-weight: 500;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    max-width: 300px;
    animation: slideIn 0.3s ease-out;
  `,e.innerHTML=`
    <div style="display: flex; align-items: center; gap: 10px;">
      <span style="font-size: 18px;">🛡️</span>
      <span>${t}</span>
      <button onclick="this.parentElement.parentElement.remove()" 
              style="background: none; border: none; color: white; font-size: 18px; cursor: pointer; margin-left: auto;">×</button>
    </div>
  `,!document.getElementById("wsg-style")){const n=document.createElement("style");n.id="wsg-style",n.textContent=`
      @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
    `,document.head?.appendChild(n)}document.body.appendChild(e),setTimeout(()=>{e.parentNode&&(e.style.animation="slideIn 0.3s ease-out reverse",setTimeout(()=>e.remove(),300))},5e3)}function m(){document.readyState==="loading"?document.addEventListener("DOMContentLoaded",()=>{i()}):i()}function i(){c(),d(),l(),console.log("✅ Content Security Monitor Started")}m();
})()
