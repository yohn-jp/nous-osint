<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import ItemPreview from '../components/ItemPreview.vue'

const route = useRoute()
const id = computed(() => Number(route.params.id))
const backTarget = computed(() => {
  const candidate = route.query.returnTo
  return typeof candidate === 'string' && (candidate === '/explore' || candidate.startsWith('/explore?')) ? candidate : '/explore'
})
</script>

<template>
  <q-page class="nous-page">
    <q-btn class="q-mb-md" flat no-caps icon="arrow_back" color="secondary" :to="backTarget" label="検索結果へ戻る" />
    <section class="content-panel" style="max-width: 900px">
      <ItemPreview :item-id="id" />
    </section>
  </q-page>
</template>
