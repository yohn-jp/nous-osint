<script setup lang="ts">
import { computed, nextTick, ref } from 'vue'
import { api } from '../lib/api'
import { useQuasar } from 'quasar'
import { useRoute, useRouter } from 'vue-router'

const $q = useQuasar()
const route = useRoute()
const router = useRouter()
const drawerOpen = ref(false)
const active = computed(() => String(route.name ?? 'live'))
const canAdmin = ref(false)
void api.adminSession().then(session => { canAdmin.value = session.allowed }).catch(() => { canAdmin.value = false })
const researchNav = [
  { to: '/live', name: 'live', icon: 'sensors', title: 'Live Feed' },
  { to: '/explore', name: 'explore', icon: 'manage_search', title: '探索' },
  { to: '/changes', name: 'changes', icon: 'history', title: '変更履歴' },
  { to: '/sources', name: 'sources', icon: 'rss_feed', title: '情報源' },
]
const adminNav = [
  { to: '/admin/sources', name: 'admin-sources', icon: 'tune', title: '情報源管理' },
  { to: '/admin/reports', name: 'admin-reports', icon: 'view_timeline', title: 'レポート生成' },
]
const isActive = (name: string) => {
  if (name === 'admin-sources') return ['admin-sources', 'admin-new', 'admin-edit'].includes(active.value)
  if (name === 'admin-reports') return active.value === 'admin-reports'
  if (name === 'sources') return ['sources', 'source-onboarding'].includes(active.value)
  return active.value === name || (['item', 'cve'].includes(active.value) && name === 'explore')
}
function closeDrawerOnMobile() { if ($q.screen.lt.md) drawerOpen.value = false }
function toggleDark() { $q.dark.set(!$q.dark.isActive) }
async function openSearch() {
  closeDrawerOnMobile()
  if (route.path !== '/explore') await router.push({ name: 'explore' })
  await nextTick()
  document.getElementById('nous-search-input')?.focus()
}
</script>

<template>
  <q-layout view="hHh Lpr fFf" class="nous-shell">
    <a class="nous-skip-link" href="#nous-main">本文へ移動</a>
    <q-header class="nous-header">
      <q-toolbar class="nous-global-bar">
        <q-btn v-if="$q.screen.lt.md" flat round dense icon="menu" aria-label="メニューを開閉" @click="drawerOpen = !drawerOpen" />
        <router-link to="/live" class="brand-link" aria-label="Nous OSINT Live Feedへ移動">
          <span class="nous-mark" aria-hidden="true">N</span>
          <span class="brand-name">nous<span class="brand-soft"> / osint</span></span>
        </router-link>
        <div class="header-workspace-label" aria-hidden="true">INTELLIGENCE WORKSPACE</div>
        <q-space />
        <button class="header-search" type="button" aria-label="収集レコードを検索" @click="openSearch">
          <q-icon name="search" size="18px" aria-hidden="true" />
          <span>収集情報を検索</span><kbd>/</kbd>
        </button>
        <q-btn class="header-theme-toggle" flat round dense
          :icon="$q.dark.isActive ? 'light_mode' : 'dark_mode'"
          :aria-label="$q.dark.isActive ? 'ライトモードに切り替える' : 'ダークモードに切り替える'"
          :aria-pressed="$q.dark.isActive" @click="toggleDark" />
      </q-toolbar>
    </q-header>

    <q-drawer v-model="drawerOpen" show-if-above :breakpoint="1024" :width="186" bordered class="nous-drawer">
      <nav class="sidebar-main" aria-label="主要ナビゲーション">
        <div class="sidebar-caption">RESEARCH</div>
        <q-list class="sidebar-nav">
          <q-item v-for="entry in researchNav" :key="entry.name" clickable :to="entry.to" exact
            class="nav-entry" :active="isActive(entry.name)" active-class="nav-entry-active" @click="closeDrawerOnMobile">
            <q-item-section avatar><q-icon :name="entry.icon" size="18px" /></q-item-section>
            <q-item-section><q-item-label>{{ entry.title }}</q-item-label></q-item-section>
          </q-item>
        </q-list>

        <div class="sidebar-caption sidebar-section-gap">PUBLICATIONS</div>
        <q-list class="sidebar-nav">
          <q-item clickable href="/reports/" class="nav-entry" @click="closeDrawerOnMobile">
            <q-item-section avatar><q-icon name="article" size="18px" /></q-item-section>
            <q-item-section><q-item-label>分析レポート</q-item-label></q-item-section>
          </q-item>
        </q-list>

        <template v-if="canAdmin">
          <div class="sidebar-caption sidebar-section-gap">OPERATIONS</div>
          <q-list class="sidebar-nav">
            <q-item v-for="entry in adminNav" :key="entry.name" clickable :to="entry.to" exact
              class="nav-entry" :active="isActive(entry.name)" active-class="nav-entry-active" @click="closeDrawerOnMobile">
              <q-item-section avatar><q-icon :name="entry.icon" size="18px" /></q-item-section>
              <q-item-section><q-item-label>{{ entry.title }}</q-item-label></q-item-section>
            </q-item>
          </q-list>
        </template>
      </nav>
      <div class="sidebar-footnote">NOUS / RESEARCH INSTRUMENT</div>
    </q-drawer>

    <q-page-container id="nous-main" tabindex="-1"><router-view /></q-page-container>
    <q-footer v-if="$q.screen.lt.md" class="mobile-footer">
      <nav class="mobile-destinations" aria-label="主要画面">
        <router-link v-for="entry in researchNav" :key="entry.name" :to="entry.to"
          :aria-current="isActive(entry.name) ? 'page' : undefined" class="mobile-destination" @click="closeDrawerOnMobile">
          <q-icon :name="entry.icon" size="19px" /><span>{{ entry.title }}</span>
        </router-link>
        <a class="mobile-destination" href="/reports/"><q-icon name="article" size="19px" /><span>レポート</span></a>
      </nav>
    </q-footer>
  </q-layout>
</template>
