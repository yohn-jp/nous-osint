<template>
  <q-page class="nous-page">
    <section class="content-panel not-found-panel">
      <div class="not-found-code">404</div>
      <h1 class="page-title">ページが見つかりません</h1>
      <p class="page-subtitle">URLを確認するか、探索画面に戻ってください。</p>
      <q-btn color="primary" unelevated icon="travel_explore" label="探索画面へ戻る" to="/explore" />
    </section>
  </q-page>
</template>

<style scoped>
.not-found-panel {
  max-width: 680px;
  margin: min(12vh, 120px) auto 0;
  padding: clamp(28px, 6vw, 56px);
  text-align: center;
}
.not-found-code {
  color: var(--nous-muted);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 1.8px;
  margin-bottom: 12px;
}
.not-found-panel .page-subtitle { margin-bottom: 24px; }
</style>
