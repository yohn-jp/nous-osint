import { defineConfig } from '#q-app'

export default defineConfig(() => ({
  extras: ['material-icons'],
  css: ['app.scss'],
  framework: {
    config: {
      brand: {
        primary: '#397650',
        secondary: '#5c7464',
        accent: '#9fba92',
        dark: '#15201b',
        positive: '#397650',
        negative: '#b3483b',
        info: '#457c91',
        warning: '#b08035',
      },
    },
  },
  build: {
    vueRouterMode: 'hash',
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
