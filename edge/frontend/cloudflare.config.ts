import { bindings, defineConfig } from 'cf/config';

export default defineConfig(({ mode, isPreview }) => {
  if (isPreview) throw new Error('Public previews are disabled; use private CI artifacts.');
  if (mode && mode !== 'production') throw new Error('Only static UI production releases are allowed');
  return {
    worker: {
      name: 'nous-frontend',
      entrypoint: './src/index.ts',
      compatibilityDate: '2026-11-06',
      workersDev: false,
      previewUrls: false,
      // Existing assets bypass Worker; misses use the explicit SPA route classifier.
      // Never return index.html for a missing JS/CSS file.
      assets: { runWorkerFirst: false, htmlHandling: 'none', notFoundHandling: 'none' },
      env: { ASSETS: bindings.assets() },
      // Never attach a catch-all route. Terraform owns explicit UI-only paths.
    },
  };
});
