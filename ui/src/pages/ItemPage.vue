<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import ItemPreview from '../components/ItemPreview.vue'

const route = useRoute()
const id = computed(() => Number(route.params.id))
const backTarget = computed(() => {
  const candidate = route.query.returnTo
  if (typeof candidate !== 'string' || candidate.includes('\\')) return '/explore'
  const allowed = [
    /^\/(?:live|explore|changes)(?:\?[^#]*)?$/,
    /^\/cves\/CVE-[0-9]{4}-[0-9]{4,}(?:\?[^#]*)?$/,
  ]
  return allowed.some(pattern => pattern.test(candidate)) ? candidate : '/explore'
})
const backLabel = computed(() => backTarget.value.startsWith('/live') ? '観測記録へ戻る'
  : backTarget.value.startsWith('/changes') ? '変更履歴へ戻る'
    : backTarget.value.startsWith('/cves/') ? 'CVE情報へ戻る' : '検索結果へ戻る')
</script>

<template>
  <q-page class="nous-page atlas-page item-page">
    <nav class="atlas-context-nav" aria-label="記録の移動">
      <q-btn flat no-caps icon="arrow_back" :to="backTarget" :label="backLabel" />
      <router-link to="/explore">記録索引 <span aria-hidden="true">↗</span></router-link>
    </nav>
    <ItemPreview :item-id="id" />
  </q-page>
</template>
