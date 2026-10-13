import { useRef, useState } from 'react';
import { ApiError, downloadBlob, postForm } from '../../api';
import { Card } from '../../components/ui';

type ImportResult = {
  imported: Record<string, number>;
  wiped: Record<string, number>;
  exported_at?: string;
  schema_revision?: string;
};

export function DataTransferPanel() {
  const fileRef = useRef<HTMLInputElement>(null);
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState<'export' | 'import' | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const onExport = async () => {
    setMsg(null);
    setBusy('export');
    try {
      await downloadBlob('/data/export', `portreveal-inventory-${new Date().toISOString().slice(0, 10)}.zip`);
      setMsg({ ok: true, text: 'Export downloaded.' });
    } catch (e: unknown) {
      setMsg({ ok: false, text: e instanceof ApiError ? e.message : 'Export failed.' });
    } finally {
      setBusy(null);
    }
  };

  const onImport = async () => {
    setMsg(null);
    const file = fileRef.current?.files?.[0];
    if (!file) {
      setMsg({ ok: false, text: 'Choose a .zip inventory file first.' });
      return;
    }
    if (!confirm) {
      setMsg({ ok: false, text: 'Check the confirmation box before importing.' });
      return;
    }
    setBusy('import');
    try {
      const fd = new FormData();
      fd.append('file', file);
      fd.append('confirm', 'true');
      const result = await postForm<ImportResult>('/data/import', fd);
      const parts = Object.entries(result.imported || {}).map(([k, v]) => `${v} ${k}`).join(', ');
      setMsg({ ok: true, text: `Import complete: ${parts || 'no rows'}. Web captures were cleared — re-run them if needed.` });
      setConfirm(false);
      if (fileRef.current) fileRef.current.value = '';
    } catch (e: unknown) {
      setMsg({ ok: false, text: e instanceof ApiError ? e.message : 'Import failed.' });
    } finally {
      setBusy(null);
    }
  };

  return (
    <Card title="Inventory export / import">
      <div className="stack">
        <div className="muted small">
          Move scan inventory and history between environments (for example from local development to production)
          without re-running nmap. Users, app settings, and SMTP/LDAP secrets are not included. Web captures and
          screenshots are not exported; import clears existing capture records on the target so you can re-run them.
        </div>
        <div className="row wrap">
          <button className="btn primary" disabled={busy !== null} onClick={onExport}>
            {busy === 'export' ? 'Exporting…' : 'Download inventory ZIP'}
          </button>
        </div>
        <hr />
        <div className="muted small">
          Import <strong>replaces</strong> networks, devices, ports, scans, events, and snapshots on this instance.
          Production admin users and configuration are kept.
        </div>
        <label className="field">Inventory ZIP
          <input ref={fileRef} type="file" accept=".zip,application/zip" disabled={busy !== null} />
        </label>
        <label className="check">
          <input type="checkbox" checked={confirm} disabled={busy !== null}
                 onChange={(e) => setConfirm(e.target.checked)} />
          I understand this will replace the current inventory
        </label>
        <div>
          <button className="btn danger" disabled={busy !== null || !confirm} onClick={onImport}>
            {busy === 'import' ? 'Importing…' : 'Import and replace inventory'}
          </button>
        </div>
        {msg && <div className={`alert ${msg.ok ? 'ok' : 'error'}`}>{msg.text}</div>}
      </div>
    </Card>
  );
}
