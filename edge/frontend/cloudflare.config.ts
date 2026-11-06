import { bindings, defineConfig } from 'cf/config';

export default defineConfig(({ mode, isPreview }) => {
  if (isPreview) throw new Error('Public previews are disabled; use private CI artifacts.');
  if (mode && !['production', 'passthrough'].includes(mode)) throw new Error('Unknown release mode');
  return {
    worker: {
      name: 'nous-frontend',
      entrypoint: './src/index.ts',
      compatibilityDate: '2026-11-06',
      workersDev: false,
      previewUrls: false,
      assets: { runWorkerFirst: true, htmlHandling: 'none', notFoundHandling: 'none' },
      env: { ASSETS: bindings.assets(), PASSTHROUGH_ONLY: bindings.text(mode === 'passthrough' ? 'true' : 'false') },
      // No routes/domains: Terraform exclusively owns the zone Worker Route.
    },
  };
});
