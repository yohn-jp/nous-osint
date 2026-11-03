import type { RouteRecordRaw } from 'vue-router'

const routes: RouteRecordRaw[] = [{
  path: '/',
  component: () => import('../layouts/MainLayout.vue'),
  children: [
    { path: '', redirect: '/explore' },
    { path: 'explore', name: 'explore', component: () => import('../pages/ExplorePage.vue') },
    { path: 'items/:id', name: 'item', component: () => import('../pages/ItemPage.vue') },
    { path: 'changes', name: 'changes', component: () => import('../pages/ChangesPage.vue') },
    { path: 'sources', name: 'sources', component: () => import('../pages/SourcesPage.vue') },
    { path: 'sources/new', name: 'source-onboarding', component: () => import('../pages/SourceOnboardingPage.vue') },
  ],
}, { path: '/:catchAll(.*)*', redirect: '/explore' }]

export default routes
