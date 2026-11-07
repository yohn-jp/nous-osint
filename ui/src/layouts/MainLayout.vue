<script setup lang="ts">
import { computed, ref } from 'vue'
import { api } from '../lib/api'
import { useQuasar } from 'quasar'
import { useRoute } from 'vue-router'

const $q = useQuasar()
const route = useRoute()
const drawerOpen = ref(false)
const active = computed(() => String(route.name ?? 'explore'))
const isAdminArea = computed(() => route.path.startsWith('/admin/'))
const canAdmin = ref(false)
void api.adminSession().then(session => { canAdmin.value = session.allowed }).catch(() => { canAdmin.value = false })
const nav = [
  { to: '/explore', name: 'explore', icon: 'travel_explore', title: '探索' },
  { to: '/changes', name: 'changes', icon: 'update', title: '変更履歴' },
  { to: '/sources', name: 'sources', icon: 'rss_feed', title: '情報源' },
]
const adminNav = [
  { to: '/admin/sources', name: 'admin-sources', icon: 'tune', title: '情報源管理' },
  { to: '/admin/reports', name: 'admin-reports', icon: 'calendar_month', title: 'レポート生成' },
]
const isActive = (name: string) => {
  if (name === 'admin-sources') return ['admin-sources', 'admin-new', 'admin-edit'].includes(active.value)
  if (name === 'admin-reports') return active.value === 'admin-reports'
  if (name === 'sources') return ['sources', 'source-onboarding'].includes(active.value)
  return active.value === name || (active.value === 'item' && name === 'explore')
}
function toggleDark() { $q.dark.set(!$q.dark.isActive) }
const adminDestination = computed(() => isAdminArea.value ? '/explore' : '/admin/sources')
const adminLabel = computed(() => isAdminArea.value ? 'ライブラリへ戻る' : '管理')
function closeDrawerOnMobile() { if ($q.screen.lt.md) drawerOpen.value = false }
</script>

<template>
  <q-layout view="hHh Lpr fFf" class="nous-shell">
    <a class="nous-skip-link" href="#nous-main">本文に移動</a>
    <q-header class="nous-header">
      <q-toolbar class="q-px-lg" style="min-height: 64px">
        <q-btn v-if="$q.screen.lt.md" flat round dense icon="menu" aria-label="メニュー" @click="drawerOpen = !drawerOpen" />
        <router-link to="/explore" class="brand-link" aria-label="Nous OSINT 探索へ戻る">
          <q-avatar rounded class="nous-mark" size="34px"><q-icon name="radar" size="22px" /></q-avatar>
          <span class="brand-name">nous<span class="brand-soft"> / osint</span></span>
          <span class="brand-context" aria-hidden="true">INTELLIGENCE DESK</span>
        </router-link>
        <q-space />

        <q-btn v-if="$q.screen.gt.sm" flat no-caps class="header-reports-action q-mr-sm" href="/reports/" icon="article" label="分析レポート" />
        <q-btn v-if="canAdmin" flat no-caps class="header-admin-action q-mr-sm" :to="adminDestination"
          :icon="isAdminArea ? 'arrow_back' : 'admin_panel_settings'"
          :label="$q.screen.gt.xs ? adminLabel : undefined" :aria-label="adminLabel" />
        <q-btn flat round dense :icon="$q.dark.isActive ? 'light_mode' : 'dark_mode'" :aria-label="$q.dark.isActive ? 'ライトモード' : 'ダークモード'" :aria-pressed="$q.dark.isActive" @click="toggleDark" />
      </q-toolbar>
    </q-header>

    <q-drawer v-model="drawerOpen" show-if-above :breakpoint="1024" :width="222" bordered class="nous-drawer">
      <div class="q-px-md q-pt-xl q-pb-md sidebar-caption">ライブラリ</div>
      <q-list padding class="q-px-sm">
        <q-item v-for="entry in nav" :key="entry.name" clickable v-ripple :to="entry.to" exact class="nav-entry" :active="isActive(entry.name)" active-class="nav-entry-active" @click="closeDrawerOnMobile">
          <q-item-section avatar><q-icon :name="entry.icon" size="20px" /></q-item-section>
          <q-item-section><q-item-label>{{ entry.title }}</q-item-label></q-item-section>
        </q-item>
      </q-list>
      <div class="q-px-md q-pt-lg q-pb-sm sidebar-caption">レポート</div>
      <q-list padding class="q-px-sm">
        <q-item clickable v-ripple href="/reports/" class="nav-entry report-external-link" @click="closeDrawerOnMobile">
          <q-item-section avatar><q-icon name="article" size="20px" /></q-item-section>
          <q-item-section><q-item-label>分析レポート</q-item-label><q-item-label caption>記事と根拠を確認</q-item-label></q-item-section>
          <q-item-section side><q-icon name="arrow_forward" size="17px" aria-hidden="true" /></q-item-section>
        </q-item>
      </q-list>
      <template v-if="canAdmin && isAdminArea">
        <div class="q-px-md q-pt-lg q-pb-sm sidebar-caption">管理</div>
        <q-list padding class="q-px-sm">
          <q-item v-for="entry in adminNav" :key="entry.name" clickable v-ripple :to="entry.to" exact class="nav-entry" :active="isActive(entry.name)" active-class="nav-entry-active" @click="closeDrawerOnMobile">
            <q-item-section avatar><q-icon :name="entry.icon" size="20px" /></q-item-section>
            <q-item-section><q-item-label>{{ entry.title }}</q-item-label></q-item-section>
          </q-item>
        </q-list>
      </template>
    </q-drawer>

    <q-page-container id="nous-main" tabindex="-1"><router-view /></q-page-container>
    <q-footer v-if="$q.screen.lt.md" class="mobile-footer">
      <q-tabs v-if="isAdminArea && canAdmin" no-caps dense indicator-color="primary" active-color="primary" class="mobile-tabs">
        <q-route-tab to="/admin/sources" :exact="false" icon="tune" label="情報源管理" />
        <q-route-tab to="/admin/reports" exact icon="calendar_month" label="レポート生成" />
        <q-route-tab to="/explore" exact icon="arrow_back" label="探索へ戻る" />
      </q-tabs>
      <q-tabs v-else no-caps dense indicator-color="primary" active-color="primary" class="mobile-tabs">
        <q-route-tab v-for="entry in nav" :key="entry.name" :to="entry.to" exact :icon="entry.icon" :label="entry.title" />
      </q-tabs>
      <a class="mobile-report-link" href="/reports/" aria-label="分析レポート"><q-icon name="article" size="22px" /><span>レポート</span></a>
    </q-footer>
  </q-layout>
</template>
