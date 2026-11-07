import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { z } from 'astro/zod';

const evidenceId = z.string().regex(/^E[0-9]{3}$/);
const claimId = z.string().regex(/^C[0-9]{3}$/);
const httpsUrl = z.string().url().refine((value) => value.startsWith('https://'));

const claim = z.strictObject({
  claim_id: claimId,
  text: z.string().min(10).max(500),
  classification: z.enum(['observed', 'inference', 'unconfirmed']),
  evidence_ids: z.array(evidenceId).min(1).max(50),
});

const textWithClaims = z.strictObject({
  text: z.string().min(1).max(1600),
  evidence_ids: z.array(evidenceId).min(1).max(50),
  claim_ids: z.array(claimId).min(1).max(20),
});

const source = z.strictObject({
  evidence_id: evidenceId,
  source_key: z.string().min(1).max(100),
  relation: z.enum(['record', 'reference', 'kev', 'title_mention']),
  title: z.string().max(300),
  publisher_url: httpsUrl,
  observed_at: z.string().datetime({ offset: true }),
  published_at: z.string().datetime({ offset: true }).nullable(),
  license_id: z.string().max(100),
});

const block = z.discriminatedUnion('type', [
  z.strictObject({ type: z.literal('paragraph'), ...textWithClaims.shape }),
  z.strictObject({
    type: z.literal('bullet_list'),
    items: z.array(textWithClaims.extend({ text: z.string().min(1).max(500) })).min(1).max(10),
  }),
  z.strictObject({
    type: z.literal('fact_table'),
    headers: z.array(z.string().max(60)).min(2).max(5),
    rows: z.array(z.strictObject({
      cells: z.array(z.string().max(240)).min(2).max(5),
      evidence_ids: z.array(evidenceId).min(1).max(50),
      claim_ids: z.array(claimId).min(1).max(20),
    })).min(1).max(20),
  }),
  z.strictObject({
    type: z.literal('cve_fact'),
    cve_id: z.string().regex(/^CVE-[0-9]{4}-[0-9]{4,}$/),
    evidence_ids: z.array(evidenceId).min(1).max(50),
    claim_ids: z.array(claimId).min(1).max(20),
  }),
  z.strictObject({
    type: z.literal('source_list'),
    evidence_ids: z.array(evidenceId).min(1).max(50),
  }),
  z.strictObject({ type: z.literal('quote'), ...textWithClaims.shape, text: z.string().min(1).max(300) }),
]);

const cve = z.strictObject({
  id: z.string().regex(/^CVE-[0-9]{4}-[0-9]{4,}$/),
  kev_status: z.enum(['listed', 'not_listed', 'unknown']),
  catalog_as_of: z.string().datetime({ offset: true }).nullable(),
  catalog_fresh: z.boolean(),
  canonical_url: httpsUrl,
  catalog_source_url: httpsUrl.nullable(),
  evidence_ids: z.array(evidenceId).min(1).max(200),
});

const reportV1 = z.strictObject({
  slug: z.string().regex(/^[a-z0-9][a-z0-9-]{0,126}$/),
  category: z.enum(['security', 'cve']),
  published_at: z.string().datetime({ offset: true }),
  url: z.string().regex(/^\/reports\/(?:security|cve)\/[a-z0-9][a-z0-9-]{0,126}\/$/),
  schema_version: z.literal(1),
  template_id: z.enum(['security-daily', 'cve-kev-deep-dive']),
  language: z.literal('ja'),
  title: z.string().min(8).max(120),
  dek: z.string().min(10).max(240),
  summary: z.array(z.string().min(12).max(240)).min(1).max(3),
  sections: z.array(z.strictObject({
    heading: z.string().min(2).max(80),
    blocks: z.array(block).min(1).max(12),
  })).min(2).max(8),
  claims: z.array(claim).min(1).max(50),
  sources: z.array(source).max(50),
  cve: cve.optional(),
}).superRefine((value, context) => {
  const sourceIds = new Set<string>();
  for (const [index, item] of value.sources.entries()) {
    if (sourceIds.has(item.evidence_id)) {
      context.addIssue({ code: 'custom', path: ['sources', index, 'evidence_id'], message: 'Duplicate evidence ID' });
    }
    sourceIds.add(item.evidence_id);
  }
  const claimMap = new Map<string, (typeof value.claims)[number]>();
  for (const [index, item] of value.claims.entries()) {
    if (claimMap.has(item.claim_id)) {
      context.addIssue({ code: 'custom', path: ['claims', index, 'claim_id'], message: 'Duplicate claim ID' });
    }
    claimMap.set(item.claim_id, item);
  }
  const displayedClaims = new Set<string>();
  const checkIds = (ids: string[], path: (string | number)[]) => {
    for (const id of ids) {
      if (!sourceIds.has(id)) {
        context.addIssue({ code: 'custom', path, message: `Unknown evidence ID ${id}` });
      }
    }
  };
  const textIsSafe = (text: string) => !/(?:<\/?[a-z!]|https?:\/\/|javascript:|data:|\bon\w+\s*=)/i.test(text);
  const checkText = (text: string, path: (string | number)[]) => {
    if (!textIsSafe(text)) {
      context.addIssue({ code: 'custom', path, message: 'Unsafe generated text' });
    }
  };
  for (const [claimIndex, item] of value.claims.entries()) {
    checkIds(item.evidence_ids, ['claims', claimIndex, 'evidence_ids']);
    checkText(item.text, ['claims', claimIndex, 'text']);
  }
  for (const [sectionIndex, section] of value.sections.entries()) {
    checkText(section.heading, ['sections', sectionIndex, 'heading']);
    for (const [blockIndex, item] of section.blocks.entries()) {
      const blockPath: (string | number)[] = ['sections', sectionIndex, 'blocks', blockIndex];
      if (item.type === 'source_list') {
        checkIds(item.evidence_ids, [...blockPath, 'evidence_ids']);
        continue;
      }
      if (item.type === 'cve_fact') {
        checkIds(item.evidence_ids, [...blockPath, 'evidence_ids']);
        if (value.cve?.id !== item.cve_id) {
          context.addIssue({
            code: 'custom', path: [...blockPath, 'cve_id'],
            message: 'CVE fact ID must match the deterministic CVE metadata',
          });
        }
        for (const [claimIndex, id] of item.claim_ids.entries()) {
          if (!claimMap.has(id)) {
            context.addIssue({
              code: 'custom', path: [...blockPath, 'claim_ids', claimIndex],
              message: `Unknown claim ID ${id}`,
            });
          } else {
            displayedClaims.add(id);
          }
        }
        continue;
      }
      const rows = item.type === 'paragraph' || item.type === 'quote'
        ? [item]
        : item.type === 'bullet_list' ? item.items
          : item.type === 'fact_table' ? item.rows : [];
      for (const [rowIndex, row] of rows.entries()) {
        const claimIds = row.claim_ids;
        const rowPath = item.type === 'paragraph' || item.type === 'quote'
          ? blockPath : [...blockPath, item.type === 'bullet_list' ? 'items' : 'rows', rowIndex];
        const related = claimIds.map((id) => claimMap.get(id));
        if (related.some((claim) => claim === undefined)) {
          context.addIssue({ code: 'custom', path: [...rowPath, 'claim_ids'], message: 'Unknown claim ID' });
          continue;
        }
        const claims = related as (typeof value.claims)[number][];
        const expectedText = claims.map((claim) => claim.text.trim()).join(' ');
        const visibleText = 'cells' in row ? row.cells.join(' | ') : row.text;
        if (visibleText.trim() !== expectedText) {
          context.addIssue({ code: 'custom', path: [...rowPath, 'text'], message: 'Visible text must match verified claims' });
        }
        const expectedEvidence = [...new Set(claims.flatMap((claim) => claim.evidence_ids))].sort();
        if ([...new Set(row.evidence_ids)].sort().join(',') !== expectedEvidence.join(',')) {
          context.addIssue({ code: 'custom', path: [...rowPath, 'evidence_ids'], message: 'Evidence IDs must match claims' });
        }
        checkIds(row.evidence_ids, [...rowPath, 'evidence_ids']);
        claimIds.forEach((id) => displayedClaims.add(id));
        if ('text' in row) checkText(row.text, [...rowPath, 'text']);
        if ('cells' in row) row.cells.forEach((cell, index) => checkText(cell, [...rowPath, 'cells', index]));
      }
      if (item.type === 'fact_table') {
        item.headers.forEach((header, index) => checkText(header, [...blockPath, 'headers', index]));
        for (const [rowIndex, row] of item.rows.entries()) {
          if (row.cells.length !== item.headers.length) {
            context.addIssue({ code: 'custom', path: [...blockPath, 'rows', rowIndex, 'cells'], message: 'Table cell count mismatch' });
          }
        }
      }
    }
  }
  if (displayedClaims.size !== claimMap.size || [...claimMap.keys()].some((id) => !displayedClaims.has(id))) {
    context.addIssue({ code: 'custom', path: ['claims'], message: 'Every verified claim must be shown exactly in an article block' });
  }
  const verifiedText = new Set([...claimMap.values()].map((item) => item.text.trim()));
  if (!verifiedText.has(value.title.trim())) {
    context.addIssue({ code: 'custom', path: ['title'], message: 'Title must exactly match a verified claim' });
  }
  if (!verifiedText.has(value.dek.trim())) {
    context.addIssue({ code: 'custom', path: ['dek'], message: 'Dek must exactly match a verified claim' });
  }
  for (const [index, summary] of value.summary.entries()) {
    if (!verifiedText.has(summary.trim())) {
      context.addIssue({ code: 'custom', path: ['summary', index], message: 'Summary must exactly match a verified claim' });
    }
  }
  if (value.cve) checkIds(value.cve.evidence_ids, ['cve', 'evidence_ids']);
  for (const [index, summary] of value.summary.entries()) checkText(summary, ['summary', index]);
  checkText(value.title, ['title']);
  checkText(value.dek, ['dek']);
  if ((value.category === 'cve') !== (value.cve !== undefined)) {
    context.addIssue({ code: 'custom', message: 'CVE category and CVE panel must agree' });
  }
  if (value.category === 'cve' && value.template_id !== 'cve-kev-deep-dive') {
    context.addIssue({ code: 'custom', message: 'CVE template/category mismatch' });
  }
  if (value.category === 'security' && value.template_id !== 'security-daily') {
    context.addIssue({ code: 'custom', message: 'Security template/category mismatch' });
  }
  if (value.url !== `/reports/${value.category}/${value.slug}/`) {
    context.addIssue({ code: 'custom', path: ['url'], message: 'Published URL does not match its allowlisted slug' });
  }
  if (value.cve?.kev_status === 'not_listed' && !value.cve.catalog_fresh) {
    context.addIssue({ code: 'custom', path: ['cve', 'catalog_fresh'], message: 'not_listed requires a fresh complete catalog snapshot' });
  }
  if (value.cve?.kev_status === 'unknown' && value.cve.catalog_fresh) {
    context.addIssue({ code: 'custom', path: ['cve', 'kev_status'], message: 'fresh complete snapshots resolve unknown to listed or not_listed' });
  }
});

const claimV2 = claim.extend({
  section: z.enum(['primary_observations', 'analysis', 'unknowns']),
  importance: z.enum(['normal', 'high']),
});

const sectionV2 = z.strictObject({
  heading: z.string().min(2).max(80),
  claim_ids: z.array(claimId).max(50),
  evidence_ids: z.array(evidenceId).min(1).max(200),
});

const reportV2 = z.strictObject({
  slug: z.string().regex(/^[a-z0-9][a-z0-9-]{0,126}$/),
  category: z.enum(['security', 'cve']),
  published_at: z.string().datetime({ offset: true }),
  url: z.string().regex(/^\/reports\/(?:security|cve)\/[a-z0-9][a-z0-9-]{0,126}\/$/),
  schema_version: z.literal(2),
  template_id: z.enum(['security-daily', 'cve-kev-deep-dive']),
  language: z.literal('ja'),
  title: z.string().min(8).max(120),
  dek: z.string().min(10).max(240),
  summary: z.array(z.string().min(10).max(240)).min(1).max(3),
  sections: z.array(sectionV2).min(1).max(4),
  claims: z.array(claimV2).min(1).max(50),
  sources: z.array(source).min(1).max(50),
  cve: cve.optional(),
}).superRefine((value, context) => {
  const sourceIds = new Set<string>();
  for (const [index, item] of value.sources.entries()) {
    if (sourceIds.has(item.evidence_id)) {
      context.addIssue({ code: 'custom', path: ['sources', index, 'evidence_id'], message: 'Duplicate evidence ID' });
    }
    sourceIds.add(item.evidence_id);
  }
  const claimMap = new Map<string, (typeof value.claims)[number]>();
  const safeText = (text: string) => !/(?:<\/?[a-z!]|https?:\/\/|javascript:|data:|\bon\w+\s*=)/i.test(text);
  for (const [index, item] of value.claims.entries()) {
    if (claimMap.has(item.claim_id)) {
      context.addIssue({ code: 'custom', path: ['claims', index, 'claim_id'], message: 'Duplicate claim ID' });
    }
    claimMap.set(item.claim_id, item);
    if (!safeText(item.text)) {
      context.addIssue({ code: 'custom', path: ['claims', index, 'text'], message: 'Unsafe claim text' });
    }
    for (const id of item.evidence_ids) {
      if (!sourceIds.has(id)) {
        context.addIssue({ code: 'custom', path: ['claims', index, 'evidence_ids'], message: `Unknown evidence ID ${id}` });
      }
    }
  }
  const displayed = new Set<string>();
  for (const [sectionIndex, section] of value.sections.entries()) {
    const path = ['sections', sectionIndex] as (string | number)[];
    if (!safeText(section.heading)) {
      context.addIssue({ code: 'custom', path: [...path, 'heading'], message: 'Unsafe heading' });
    }
    for (const id of section.evidence_ids) {
      if (!sourceIds.has(id)) {
        context.addIssue({ code: 'custom', path: [...path, 'evidence_ids'], message: `Unknown evidence ID ${id}` });
      }
    }
    const expectedEvidence = new Set<string>();
    for (const [claimIndex, id] of section.claim_ids.entries()) {
      const item = claimMap.get(id);
      if (!item) {
        context.addIssue({ code: 'custom', path: [...path, 'claim_ids', claimIndex], message: `Unknown claim ID ${id}` });
        continue;
      }
      displayed.add(id);
      for (const evidenceIdValue of item.evidence_ids) expectedEvidence.add(evidenceIdValue);
      const expectedHeading = value.template_id === 'cve-kev-deep-dive'
        ? item.section === 'primary_observations' ? 'CVEの確認情報' : '影響と未確認事項'
        : item.section === 'primary_observations' ? '確認された事実'
          : item.section === 'analysis' ? '分析' : '未確認事項';
      if (section.heading !== expectedHeading) {
        context.addIssue({ code: 'custom', path: [...path, 'heading'], message: 'Unreviewed claim grouping' });
      }
    }
    if ([...expectedEvidence].some((id) => !section.evidence_ids.includes(id))) {
      context.addIssue({ code: 'custom', path: [...path, 'evidence_ids'], message: 'Evidence IDs must cover claims' });
    }
  }
  if (displayed.size !== claimMap.size || [...claimMap.keys()].some((id) => !displayed.has(id))) {
    context.addIssue({ code: 'custom', path: ['claims'], message: 'Every approved claim must be displayed' });
  }
  const verifiedText = new Set([...claimMap.values()].map((item) => item.text));
  if (!verifiedText.has(value.dek)) {
    context.addIssue({ code: 'custom', path: ['dek'], message: 'Dek must reference an approved claim' });
  }
  for (const [index, summary] of value.summary.entries()) {
    if (!verifiedText.has(summary)) {
      context.addIssue({ code: 'custom', path: ['summary', index], message: 'Summary must reference an approved claim' });
    }
  }
  if (!safeText(value.title) || !safeText(value.dek) || value.summary.some((line) => !safeText(line))) {
    context.addIssue({ code: 'custom', path: ['title'], message: 'Unsafe article framing' });
  }
  if ((value.category === 'cve') !== (value.cve !== undefined)) {
    context.addIssue({ code: 'custom', message: 'CVE category and CVE panel must agree' });
  }
  if (value.template_id !== (value.category === 'cve' ? 'cve-kev-deep-dive' : 'security-daily')) {
    context.addIssue({ code: 'custom', message: 'Template/category mismatch' });
  }
  if (value.url !== `/reports/${value.category}/${value.slug}/`) {
    context.addIssue({ code: 'custom', path: ['url'], message: 'Published URL does not match its allowlisted slug' });
  }
  if (value.cve?.kev_status === 'not_listed' && !value.cve.catalog_fresh) {
    context.addIssue({ code: 'custom', path: ['cve', 'catalog_fresh'], message: 'not_listed requires a fresh catalog snapshot' });
  }
  if (value.cve?.kev_status === 'unknown' && value.cve.catalog_fresh) {
    context.addIssue({ code: 'custom', path: ['cve', 'kev_status'], message: 'Fresh snapshots resolve unknown status' });
  }
});

const report = z.union([reportV1, reportV2]);

const reports = defineCollection({
  loader: glob({ base: './src/content/reports', pattern: '**/*.json' }),
  schema: report,
});

export const collections = { reports };
