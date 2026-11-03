import { defineRouter } from '#q-app'
import { createRouter, createWebHashHistory, type Router } from 'vue-router'
import routes from './routes'

export default defineRouter((): Router => createRouter({
  history: createWebHashHistory(),
  routes,
  scrollBehavior(to, from, saved) {
    if (saved) return saved
    if (to.path === from.path) return false
    return { left: 0, top: 0 }
  },
}))
