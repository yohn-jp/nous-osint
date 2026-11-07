import { defineConfig } from '#q-app'

export default defineConfig(() => ({
  extras: ['material-icons'],
  css: ['app.scss'],
  framework: {
    config: {
      brand: {
        primary: '#0b685f',
        secondary: '#486967',
        accent: '#236b83',
        dark: '#142521',
        positive: '#207b56',
        negative: '#b04740',
        info: '#236b83',
        warning: '#96621d',
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
