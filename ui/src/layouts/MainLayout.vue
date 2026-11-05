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
  { to: '/explore', name: 'explore', icon: 'travel_explore', title: '探索', caption: 'Explore' },
  { to: '/changes', name: 'changes', icon: 'update', title: '変更履歴', caption: 'Changes' },
  { to: '/sources', name: 'sources', icon: 'rss_feed', title: '情報源', caption: 'Sources' },
]
const adminNav = [
  { to: '/admin/sources', name: 'admin-sources', icon: 'tune', title: '情報源管理', caption: 'Source administration' },
  { to: '/admin/reports', name: 'admin-reports', icon: 'calendar_month', title: 'レポート生成管理', caption: 'Report generation' },
]
const isActive = (name: string) => {
  if (name === 'admin-sources') return ['admin-sources', 'admin-new', 'admin-edit'].includes(active.value)
  if (name === 'admin-reports') return active.value === 'admin-reports'
  return active.value === name || (active.value === 'item' && name === 'explore')
}
function toggleDark() { $q.dark.set(!$q.dark.isActive) }
const adminDestination = computed(() => isAdminArea.value ? '/explore' : '/admin/sources')
const adminLabel = computed(() => isAdminArea.value ? 'ライブラリへ戻る' : '管理')
function closeDrawerOnMobile() { if ($q.screen.lt.md) drawerOpen.value = false }
</script>

<template>
  <q-layout view="hHh Lpr fFf" class="nous-shell">
    <q-header class="nous-header">
      <q-toolbar class="q-px-lg" style="min-height: 64px">
        <q-btn v-if="$q.screen.lt.md" flat round dense icon="menu" aria-label="メニュー" @click="drawerOpen = !drawerOpen" />
        <q-avatar rounded class="nous-mark" size="34px"><q-icon name="radar" size="22px" /></q-avatar>
        <div class="q-ml-md brand-name">nous<span class="brand-soft"> / osint</span></div>
        <q-space />
        <div class="header-descriptor gt-sm">OPEN SOURCE INTELLIGENCE LIBRARY</div>
        <q-space />
        <q-btn v-if="canAdmin" flat no-caps class="header-admin-action q-mr-sm" :to="adminDestination"
          :icon="isAdminArea ? 'arrow_back' : 'admin_panel_settings'"
          :label="$q.screen.gt.xs ? adminLabel : undefined" :aria-label="adminLabel" />
        <q-btn flat round dense :icon="$q.dark.isActive ? 'light_mode' : 'dark_mode'" :aria-label="$q.dark.isActive ? 'ライトモード' : 'ダークモード'" @click="toggleDark" />
      </q-toolbar>
    </q-header>

    <q-drawer v-model="drawerOpen" show-if-above :breakpoint="1024" :width="222" bordered class="nous-drawer">
      <div class="q-px-md q-pt-xl q-pb-md sidebar-caption">LIBRARY</div>
      <q-list padding class="q-px-sm">
        <q-item v-for="entry in nav" :key="entry.name" clickable v-ripple :to="entry.to" :href="entry.href" exact class="nav-entry" :active="isActive(entry.name)" active-class="nav-entry-active" @click="closeDrawerOnMobile">
          <q-item-section avatar><q-icon :name="entry.icon" size="20px" /></q-item-section>
          <q-item-section><q-item-label>{{ entry.title }}</q-item-label><q-item-label caption>{{ entry.caption }}</q-item-label></q-item-section>
        </q-item>
      </q-list>
      <div class="q-px-md q-pt-lg q-pb-sm sidebar-caption">PUBLICATIONS</div>
      <q-list padding class="q-px-sm">
        <q-item clickable v-ripple href="/reports/" target="_blank" rel="noopener noreferrer" class="nav-entry report-external-link" @click="closeDrawerOnMobile">
          <q-item-section avatar><q-icon name="article" size="20px" /></q-item-section>
          <q-item-section><q-item-label>分析レポート</q-item-label><q-item-label caption>別の閲覧サイトで開く</q-item-label></q-item-section>
          <q-item-section side><q-icon name="open_in_new" size="17px" aria-label="新しいタブで開く" /></q-item-section>
        </q-item>
      </q-list>
      <template v-if="canAdmin && isAdminArea">
        <div class="q-px-md q-pt-lg q-pb-sm sidebar-caption">ADMINISTRATION</div>
        <q-list padding class="q-px-sm">
          <q-item v-for="entry in adminNav" :key="entry.name" clickable v-ripple :to="entry.to" exact class="nav-entry" :active="isActive(entry.name)" active-class="nav-entry-active" @click="closeDrawerOnMobile">
            <q-item-section avatar><q-icon :name="entry.icon" size="20px" /></q-item-section>
            <q-item-section><q-item-label>{{ entry.title }}</q-item-label><q-item-label caption>{{ entry.caption }}</q-item-label></q-item-section>
          </q-item>
        </q-list>
      </template>
      <div class="sidebar-footer">SOURCE FIRST · HISTORY PRESERVED</div>
    </q-drawer>

    <q-page-container><router-view /></q-page-container>
    <q-footer v-if="$q.screen.lt.md" class="mobile-footer">
      <q-tabs no-caps dense indicator-color="primary" active-color="primary" class="text-grey-7">
        <template v-for="entry in nav" :key="entry.name">
          <q-route-tab v-if="entry.to" :to="entry.to" exact :icon="entry.icon" :label="entry.title" />
          <q-tab v-else :name="entry.name" :href="entry.href" :icon="entry.icon" :label="entry.title" />
        </template>
      </q-tabs>
    </q-footer>
  </q-layout>
</template>
