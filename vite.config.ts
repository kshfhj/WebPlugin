import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import vueDevTools from 'vite-plugin-vue-devtools'
import { crx } from '@crxjs/vite-plugin'
import manifest from './src/manifest.json'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const isExtension = mode === 'extension'
  
  return {
    plugins: [
      vue(),
      !isExtension && vueDevTools(),
      isExtension && crx({ manifest })
    ].filter(Boolean),
    resolve: {
      alias: {
        '@': fileURLToPath(new URL('./src', import.meta.url))
      },
    },
    build: isExtension ? {
      outDir: 'dist-extension'
    } : undefined,
    define: {
      __VUE_OPTIONS_API__: true,
      __VUE_PROD_DEVTOOLS__: false,
    }
  }
})
