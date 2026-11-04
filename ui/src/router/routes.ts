import type { RouteRecordRaw } from 'vue-router'

const routes: RouteRecordRaw[] = [{
  path: '/',
  component: () => import('../layouts/MainLayout.vue'),
  children: [
    { path: '', redirect: '/explore' },
    { path: 'explore', name: 'explore', component: () => import('../pages/ExplorePage.vue') },
    { path: 'items/:id', name: 'item', component: () => import('../pages/ItemPage.vue') },
    { path: 'cves/:id', name: 'cve', component: () => import('../pages/CvePage.vue') },
    { path: 'changes', name: 'changes', component: () => import('../pages/ChangesPage.vue') },
    { path: 'sources', name: 'sources', component: () => import('../pages/SourcesPage.vue') },
    { path: 'sources/new', name: 'source-onboarding', component: () => import('../pages/SourceOnboardingPage.vue') },
    { path: 'admin/sources', name: 'admin-sources', component: () => import('../pages/AdminSourcesPage.vue') },
    { path: 'admin/sources/new', name: 'admin-new', component: () => import('../pages/AdminSourceFormPage.vue') },
    { path: 'admin/sources/:id/edit', name: 'admin-edit', component: () => import('../pages/AdminSourceFormPage.vue') },
  ],
}, { path: '/:catchAll(.*)*', redirect: '/explore' }]

export default routes
