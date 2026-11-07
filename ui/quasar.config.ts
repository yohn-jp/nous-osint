import { defineConfig } from '#q-app'

export default defineConfig(() => ({
  extras: ['material-icons'],
  css: ['app.scss', 'workstation.scss'],
  framework: {
    config: {
      brand: {
        primary: '#315f9e',
        secondary: '#526777',
        accent: '#a76b35',
        dark: '#151c22',
        positive: '#347353',
        negative: '#a43d37',
        info: '#315f9e',
        warning: '#a76b35',
      },
    },
  },
  build: {
    vueRouterMode: 'history',
    vueOptionsAPI: false,
    typescript: { strict: true },
  },
  devServer: {
    host: '127.0.0.1',
    port: 9000,
    open: false,
    proxy: {
      '/v1': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: false,
      },
    },
  },
}))
