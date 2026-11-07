<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import ItemPreview from '../components/ItemPreview.vue'

const route = useRoute()
const id = computed(() => Number(route.params.id))
const backTarget = computed(() => {
  const candidate = route.query.returnTo
  if (typeof candidate !== 'string') return '/explore'
  const allowed = [
    /^\/explore(?:\?[^#]*)?$/,
    /^\/changes(?:\?[^#]*)?$/,
    /^\/cves\/CVE-[0-9]{4}-[0-9]{4,}(?:\?[^#]*)?$/,
  ]
  // Explicitly allow only known internal return destinations; never an arbitrary URL.
  return allowed.some(pattern => pattern.test(candidate)) && !candidate.includes('\\') ? candidate : '/explore'
})
const backLabel = computed(() => backTarget.value.startsWith('/changes') ? '変更履歴へ戻る'
  : backTarget.value.startsWith('/cves/') ? 'CVE情報へ戻る' : '検索結果へ戻る')
</script>

<template>
  <q-page class="nous-page">
    <q-btn class="q-mb-md" flat no-caps icon="arrow_back" color="secondary" :to="backTarget" :label="backLabel" />
    <section class="content-panel" style="max-width: 900px">
      <ItemPreview :item-id="id" />
    </section>
  </q-page>
</template>
