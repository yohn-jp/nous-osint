<script setup lang="ts">
import { computed, ref } from 'vue'
import { api } from '../lib/api'
import { useQuasar } from 'quasar'
import { useRoute } from 'vue-router'

const $q = useQuasar()
const route = useRoute()
const drawerOpen = ref(false)
const active = computed(() => String(route.name ?? 'explore'))
const canAdmin = ref(false)
void api.adminSession().then(() => { canAdmin.value = true }).catch(() => { canAdmin.value = false })
const nav = [
  { to: '/explore', name: 'explore', icon: 'travel_explore', title: '探索', caption: 'Explore' },
  { to: '/changes', name: 'changes', icon: 'update', title: '変更履歴', caption: 'Changes' },
  { to: '/sources', name: 'sources', icon: 'rss_feed', title: '情報源', caption: 'Sources' },
]
const visibleNav = computed(() => canAdmin.value ? [...nav, { to: '/admin/sources', name: 'admin-sources', icon: 'tune', title: '管理', caption: 'Admin' }] : nav)
const isActive = (name: string) => active.value === name || (active.value === 'item' && name === 'explore') || (name === 'admin-sources' && active.value.startsWith('admin-'))
function toggleDark() { $q.dark.set(!$q.dark.isActive) }
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
        <q-btn flat round dense :icon="$q.dark.isActive ? 'light_mode' : 'dark_mode'" :aria-label="$q.dark.isActive ? 'ライトモード' : 'ダークモード'" @click="toggleDark" />
      </q-toolbar>
    </q-header>

    <q-drawer v-model="drawerOpen" show-if-above :breakpoint="1024" :width="222" bordered class="nous-drawer">
      <div class="q-px-md q-pt-xl q-pb-md sidebar-caption">LIBRARY</div>
      <q-list padding class="q-px-sm">
        <q-item v-for="entry in visibleNav" :key="entry.name" clickable v-ripple :to="entry.to" exact class="nav-entry" :active="isActive(entry.name)" active-class="nav-entry-active" @click="closeDrawerOnMobile">
          <q-item-section avatar><q-icon :name="entry.icon" size="20px" /></q-item-section>
          <q-item-section><q-item-label>{{ entry.title }}</q-item-label><q-item-label caption>{{ entry.caption }}</q-item-label></q-item-section>
        </q-item>
      </q-list>
      <div class="sidebar-footer">SOURCE FIRST · HISTORY PRESERVED</div>
    </q-drawer>

    <q-page-container><router-view /></q-page-container>
    <q-footer v-if="$q.screen.lt.md" class="mobile-footer">
      <q-tabs no-caps dense indicator-color="primary" active-color="primary" class="text-grey-7">
        <q-route-tab v-for="entry in visibleNav" :key="entry.name" :to="entry.to" exact :icon="entry.icon" :label="entry.title" />
      </q-tabs>
    </q-footer>
  </q-layout>
</template>
